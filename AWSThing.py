import asyncio
from copy import deepcopy
import json
import sys
import threading
import time
from typing import Optional, Tuple
from uuid import UUID, uuid4
from awsiot import mqtt_connection_builder, iotshadow
from awsiot.iotshadow import IotShadowClient, ShadowStateWithDelta, ShadowState
from awscrt import mqtt
import logging


# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("Connection interrupted. error: {}".format(error))


# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

    if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
        print("Session did not persist. Resubscribing to existing topics...")
        resubscribe_future, _ = connection.resubscribe_existing_topics()

        # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
        # evaluate result with a callback instead.
        resubscribe_future.add_done_callback(on_resubscribe_complete)


def on_resubscribe_complete(resubscribe_future):
    resubscribe_results = resubscribe_future.result()
    print("Resubscribe results: {}".format(resubscribe_results))

    for topic, qos in resubscribe_results["topics"]:
        if qos is None:
            sys.exit("Server rejected resubscribe to topic: {}".format(topic))


# Callback when the subscribed topic receives a message
def on_message_received(topic, payload, dup, qos, retain, **kwargs):
    print("Received message from topic '{}': {}".format(topic, payload))


# Callback when the connection successfully connects
def on_connection_success(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionSuccessData)
    print(
        "Connection Successful with return code: {} session present: {}".format(
            callback_data.return_code, callback_data.session_present
        )
    )


# Callback when a connection attempt fails
def on_connection_failure(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionFailureData)
    print("Connection failed with error code: {}".format(callback_data.error))


# Callback when a connection has been disconnected or shutdown successfully
def on_connection_closed(connection, callback_data):
    print("Connection closed")


def remove_keys_from_dict_with_null_values(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def filter_dict_for_null_values(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is None}


class AWSIOTThing:
    def __init__(
        self,
        id: UUID,
        name: str,
        endpoint: str,
        cert_filepath: str,
        pri_key_filepath: str,
        root_ca_filepath: str,
        initial_state: Optional[dict] = None,
        override_cloud_state: bool = False,
        clean_session: bool = True,
        keep_alive_secs: int = 30,
        subscribe_qos: mqtt.QoS = mqtt.QoS.AT_LEAST_ONCE,
        publish_qos: mqtt.QoS = mqtt.QoS.AT_LEAST_ONCE,
        verbose: bool = False,
    ) -> None:
        # Validate that the filepaths exist and have the correct extensions
        # TODO: there has to be a better way
        if not cert_filepath.endswith(".cert.pem"):
            raise ValueError(f"cert_filepath must end with .cert.pem")

        if (
            not pri_key_filepath.endswith(".private.key")
            and not pri_key_filepath.endswith(".private.pem")
            and not pri_key_filepath.endswith(".private.key.pem")
        ):
            raise ValueError(f"pri_key_filepath must end with .private.key or .private.pem or .private.key.pem")

        if not root_ca_filepath.endswith(".crt"):
            raise ValueError(f"root_ca_filepath must end with .root.ca.pem")

        # If the caller asks us to override the cloud state, they must provide a state
        if override_cloud_state and not initial_state:
            raise ValueError("override_cloud_state is True but no thing_state was provided!")

        if initial_state is not None and not override_cloud_state:
            print(
                "Warning: initial_state provided but override_cloud_state is False, so initial_state will be ignored."
            )

        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.cert_filepath = cert_filepath
        self.pri_key_filepath = pri_key_filepath
        self.root_ca_filepath = root_ca_filepath
        self.clean_session = clean_session
        self.keep_alive_secs = keep_alive_secs
        self.subscribe_qos = subscribe_qos
        self.publish_qos = publish_qos
        # TODO: what's the nice way to handle this?
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.initial_state = initial_state
        self.override_cloud_state = override_cloud_state

    def connect(
        self,
        on_connection_interrupted=on_connection_interrupted,
        on_connection_resumed=on_connection_resumed,
        on_connection_success=on_connection_success,
        on_connection_failure=on_connection_failure,
        on_connection_closed=on_connection_closed,
        on_resubscribe_complete=on_resubscribe_complete,
    ):
        """
        Connect to the AWS IoT Core endpoint. Uses the default handlers for events, but you can supply your own.

        :param on_connection_interrupted: Callback when connection is accidentally lost.
        :param on_connection_resumed: Callback when an interrupted connection is re-established.
        :param on_connection_success: Callback when the connection successfully connects
        :param on_connection_failure: Callback when a connection attempt fails
        :param on_connection_closed: Callback when a connection has been disconnected or shutdown successfully
        :param on_resubscribe_complete: Callback when the subscribed topic receives a message
        :return: None
        """
        # self.logger.debug(f"{self.name}: Connecting...")
        # Had to use port 443
        # No weird cert manipulation for this?
        # unclear what clean session does
        # TODO: Need to find a way to tie the policy to a device ID programmatically
        mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=self.endpoint,
            cert_filepath=self.cert_filepath,
            pri_key_filepath=self.pri_key_filepath,
            ca_filepath=self.root_ca_filepath,
            client_id=str(self.id),  # had to allow connection to client/* under policy
            clean_session=self.clean_session,
            keep_alive_secs=self.keep_alive_secs,
            on_connection_interrupted=on_connection_interrupted,
            on_connection_resumed=on_connection_resumed,
            on_connection_success=on_connection_success,
            on_connection_failure=on_connection_failure,
            on_connection_closed=on_connection_closed,
            on_resubscribe_complete=on_resubscribe_complete,
        )
        connect_future = mqtt_connection.connect()
        connect_future.result()
        print(f"{self.name}: Base connection established. Connecting to shadow...")
        self.mqtt_connection = mqtt_connection

        if self.initial_state is not None:
            self.smart_shadow = SmartShadow(mqtt_connection, self.name, self.initial_state, self.override_cloud_state)
            self.smart_shadow.connect()

    def publish(self, topic: str, payload: str, qos: Optional[mqtt.QoS] = None, fire_and_forget: bool = False):
        publish_future, _ = self.mqtt_connection.publish(
            topic=topic, payload=payload, qos=self.publish_qos if qos is None else qos
        )
        if not fire_and_forget:
            publish_future.result()
            # self.logger.debug(f"{self.name}: Published to topic {topic} with payload {payload}")

    def subscribe(self, topic: str, callback, qos: Optional[mqtt.QoS] = None):
        subscribe_future, _ = self.mqtt_connection.subscribe(
            topic=topic, qos=self.subscribe_qos if qos is None else qos, callback=callback
        )
        subscribe_future.result()
        print(f"{self.name}: Subscribed to topic {topic} with callback {callback}")

    def unsubscribe(self, topic: str):
        unsubscribe_future, _ = self.mqtt_connection.unsubscribe(topic=topic)
        unsubscribe_future.result()
        print(f"{self.name}: Unsubscribed from topic {topic}")

    def disconnect(self):
        disconnect_future = self.mqtt_connection.disconnect()
        disconnect_future.result()
        print(f"{self.name}: Disconnected!")

    def get_state(self) -> Optional[dict]:
        if self.smart_shadow is None:
            print(f"{self.name}: No shadow connected, cannot get state.")
            return None
        return self.smart_shadow.get_state()

    async def update_shadow_state_async(self, state: dict, timeout: int = 15) -> None:
        if self.smart_shadow is None:
            print(f"{self.name}: No shadow connected, cannot update state.")
            return None

        waited_secs = 0
        self.smart_shadow.update_shadow_state(state)
        while self.smart_shadow.get_state() != state:
            print(f"{self.name}: Waiting for shadow update to complete...")
            await asyncio.sleep(1)
            waited_secs += 1
            if waited_secs > timeout:
                raise TimeoutError(f"{self.name}: Shadow update timed out after {timeout} seconds.")

        print(f"{self.name}: Shadow update complete.")

    def update_shadow_state_synchronous(self, state: dict, timeout: int = 15) -> None:
        if self.smart_shadow is None:
            print(f"{self.name}: No shadow connected, cannot update state.")
            return None

        waited_secs = 0
        self.smart_shadow.update_shadow_state(state)
        while self.smart_shadow.get_state() != state:
            print(f"{self.name}: Waiting for shadow update to complete...")
            time.sleep(1)
            waited_secs += 1
            if waited_secs > timeout:
                raise TimeoutError(f"{self.name}: Shadow update timed out after {timeout} seconds.")

        print(f"{self.name}: Shadow update complete.")


class SmartShadow:
    def __init__(
        self,
        mqtt_connection: mqtt.Connection,
        thing_name: str,
        initial_state: Optional[dict] = None,
        override_cloud_state: bool = False,
    ) -> None:
        self.mqtt_connection = mqtt_connection
        self.thing_name = thing_name
        self.lock = threading.Lock()
        self.shadow_client = IotShadowClient(self.mqtt_connection)
        self.request_tokens = set()
        self.override_cloud_state = override_cloud_state
        # If we know we don't care about the cloud state, we can use the inital state here
        self.state = initial_state if override_cloud_state else None
        self.initial_state_set = True if override_cloud_state else False

    def add_request_token(self, token: str) -> None:
        with self.lock:
            self.request_tokens.add(token)

    def remove_request_token(self, token: str | None) -> None:
        if token is None:
            print("Warning: tried to remove a null request token")
            return
        with self.lock:
            try:
                self.request_tokens.remove(token)
            except KeyError:
                print(f"Warning: tried to remove non-existent request token {token}!")
                # TODO, should we die if this happens?

    def modify_local_state(self, state: ShadowStateWithDelta | ShadowState) -> bool:
        # TODO: most of this, for example, the delta state
        changed = False
        with self.lock:
            # A state of None means that the shadow has been deleted
            if state.desired is None:
                print(f"Received request to clear state for shadow {self.thing_name}!")
            # If we receive a state update, we should update our local state
            elif state.desired != self.state:
                # a value of None means that the key should be deleted
                new_state = remove_keys_from_dict_with_null_values(state.desired)
                # if any keys we have now are missing in the new desired state, we should delete them also
                if self.state is not None:
                    missing_keys = set(self.state.keys()) - set(new_state.keys())
                    print(f"Removed keys {missing_keys} from update for shadow {self.thing_name}.")
                self.state = new_state
                changed = True
            # if our local state is different from the reported state, we should update the cloud, which
            # we can do by publishing an update with the same state for both desired and reported
            elif state.reported != self.state:
                print(f"State for shadow {self.thing_name} out of sync, updating...")
                changed = True
            else:
                changed = False

            if not self.initial_state_set:
                self.initial_state_set = True
                print(f"Initial state for shadow {self.thing_name} set to {self.state}")
            elif not changed:
                print(f"State for shadow {self.thing_name} unchanged at {self.state}")
            else:
                print(f"Updated state for shadow {self.thing_name} to {self.state}")
        return changed

    def receive_explicitly_requested_state(self, response: iotshadow.GetShadowResponse) -> None:
        print(f"Received state for shadow {response.client_token} with payload {response.state}")
        self.remove_request_token(response.client_token)
        state: ShadowStateWithDelta = response.state  # type: ignore
        self.modify_local_state(state)

    def receive_updated_state(self, response: iotshadow.UpdateShadowResponse) -> None:
        print(f"Received update for shadow {response.client_token} with payload {response.state}")
        self.remove_request_token(response.client_token)
        state: ShadowState = response.state  # type: ignore
        changed = self.modify_local_state(state)
        if changed:
            with self.lock:
                canonical_state = self.state
                if state.desired is not None and self.state is not None:
                    canonical_state = self.state | filter_dict_for_null_values(state.desired)

                generic_token = str(uuid4())
                self.shadow_client.publish_update_shadow(
                    request=iotshadow.UpdateShadowRequest(
                        thing_name=self.thing_name,
                        state=iotshadow.ShadowState(desired=self.state, reported=canonical_state),
                        client_token=generic_token,
                    ),
                    qos=mqtt.QoS.AT_LEAST_ONCE,
                )
            self.add_request_token(generic_token)

    def get_state(self) -> Optional[dict]:
        with self.lock:
            return self.state

    def request_initial_state(self) -> None:
        """
        Request the initial state of the shadow. This is a blocking call.

        The way that AWS IoT Core Shadows work is that downloading cloud state
        is request-based. We publish a generic message to the shadow get topic,
        and the cloud responds by publishing the current state of the shadow
        to the /get/accepted topic.
        """

        generic_token = str(uuid4())

        # TODO: do we need the lock here?
        with self.lock:
            print(f"Getting initial state for shadow {self.thing_name}...")
            publish_get_future = self.shadow_client.publish_get_shadow(
                request=iotshadow.GetShadowRequest(thing_name=self.thing_name, client_token=generic_token),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
            print(f"Initial state request for shadow {self.thing_name} sent.")

        self.add_request_token(generic_token)

        publish_get_future.result()

    def override_cloud_initial_state(self) -> None:
        """
        Override the cloud state with the initial state. This is a blocking call.

        First, publish a delete request for the shadow to eliminate that state.
        """

        generic_token = str(uuid4())
        self.shadow_client.publish_delete_shadow(
            request=iotshadow.DeleteShadowRequest(thing_name=self.thing_name, client_token=generic_token),
            qos=mqtt.QoS.AT_LEAST_ONCE,
        )
        self.add_request_token(generic_token)
        print(f"Sent request to delete unnamed shadow for {self.thing_name}.")
        # Now publish an update with our initial state
        generic_token = str(uuid4())
        self.shadow_client.publish_update_shadow(
            request=iotshadow.UpdateShadowRequest(
                thing_name=self.thing_name,
                state=iotshadow.ShadowState(desired=self.state, reported=self.state),
                client_token=generic_token,
            ),
            qos=mqtt.QoS.AT_LEAST_ONCE,
        )
        self.add_request_token(generic_token)
        print(f"Sent request to update shadow for {self.thing_name} with initial state {self.state}.")

    def handle_get_failure(self, response: iotshadow.ErrorResponse) -> None:
        """
        TODO: implement
        """
        self.remove_request_token(response.client_token)
        if response.code == 404:
            print(f"Shadow {self.thing_name} does not exist, creating using initial state {self.state}")
            generic_token = str(uuid4())
            self.shadow_client.publish_update_shadow(
                request=iotshadow.UpdateShadowRequest(
                    thing_name=self.thing_name,
                    state=iotshadow.ShadowState(desired=self.state),
                    client_token=generic_token,
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
            self.add_request_token(generic_token)
        else:
            print(f"Failed to get state for shadow {self.thing_name} with error {response.message}")
            exit(1)

    def handle_update_failure(self, response: iotshadow.ErrorResponse) -> None:
        self.remove_request_token(response.client_token)
        print(f"Failed to update state for shadow {self.thing_name} with error {response.message}")
        exit(1)

    def update_shadow_state(self, state: dict) -> None:
        """
        Update the shadow state. This is a blocking call.

        The way that AWS IoT Core Shadows work is that updating cloud state
        is request-based. We publish a message to the shadow update topic with our current
        state as "reported", and the cloud responds by publishing the current state of
        the shadow to the /update/accepted topic.
        """
        print(f"Updating state for shadow {self.thing_name}...")
        # if the incoming state is missing keys from the current state, we need to
        # set those keys to null in the update
        canonical_state = deepcopy(state)
        with self.lock:
            if self.state is not None:
                missing_keys = set(self.state.keys()) - set(canonical_state.keys())
                for key in missing_keys:
                    canonical_state[key] = None
                print(f"Removed keys {missing_keys} from update for shadow {self.thing_name}.")
        generic_token = str(uuid4())
        with self.lock:
            publish_update_future = self.shadow_client.publish_update_shadow(
                request=iotshadow.UpdateShadowRequest(
                    thing_name=self.thing_name,
                    state=iotshadow.ShadowState(desired=canonical_state, reported=canonical_state),
                    client_token=generic_token,
                ),
                qos=mqtt.QoS.AT_LEAST_ONCE,
            )
        self.add_request_token(generic_token)
        publish_update_future.result()

    def handle_delta_update(self, response: iotshadow.ShadowDeltaUpdatedEvent) -> None:
        # TODO: implement
        pass

    def connect(self) -> None:
        """
        TODO: Allow for connection to a named shadow
        Connect to the default shadow topics for the thing.

        This function resolves my primary confusion with the AWS IoT Core,
        which is the extremely complex machinery required to manage shadow
        state. From the perspective of the devicie developer, I just want to
        define a device state, and then .connect() to the cloud, and let
        the state update as needed in the background. By default, AWS IoT expects that
        you're going to do each piece of that by hand throughout your device code.
        Why they expect that, I don't know.

        """
        print(f"Connecting to shadow {self.thing_name}...")
        # Connect to update events...
        update_accepted_subscribed_future, _ = self.shadow_client.subscribe_to_update_shadow_accepted(
            request=iotshadow.UpdateShadowSubscriptionRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self.receive_updated_state,
        )
        update_rejected_subscribed_future, _ = self.shadow_client.subscribe_to_update_shadow_rejected(
            request=iotshadow.UpdateShadowSubscriptionRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
            # TODO: make the real callback
            callback=self.handle_update_failure,
        )
        # And wait for subscriptions to succeed
        update_accepted_subscribed_future.result()
        update_rejected_subscribed_future.result()

        # Now connect to get events...
        get_accepted_subscribed_future, _ = self.shadow_client.subscribe_to_get_shadow_accepted(
            request=iotshadow.GetShadowSubscriptionRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self.receive_explicitly_requested_state,
        )

        get_rejected_subscribed_future, _ = self.shadow_client.subscribe_to_get_shadow_rejected(
            request=iotshadow.GetShadowSubscriptionRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self.handle_get_failure,
        )

        # again, wait for subscriptions to succeed
        get_accepted_subscribed_future.result()
        get_rejected_subscribed_future.result()

        print(f"Base subscribtion to shadow {self.thing_name} established.")
        # The AWS IOT examples split this out into its own logs,
        # so I call it out as two processes here :shrug:
        print(f"Subscribing to delta events for shadow {self.thing_name}...")
        delta_subscribed_future, _ = self.shadow_client.subscribe_to_shadow_delta_updated_events(
            request=iotshadow.ShadowDeltaUpdatedSubscriptionRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
            # TODO: make the real callback
            callback=self.handle_delta_update,
        )

        # Wait for subscription to succeed
        delta_subscribed_future.result()
        print(f"Subscribed to delta events for shadow {self.thing_name}.")

        if self.override_cloud_state:
            self.override_cloud_initial_state()
        else:
            self.request_initial_state()

        print(f"Shadow connection for {self.thing_name} complete, all systems nominal.")
