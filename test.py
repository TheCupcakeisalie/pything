import json
from uuid import uuid4
from awscrt import mqtt
from time import sleep
from os import getenv
from AWSThing import AWSIOTThing
from dotenv import load_dotenv

load_dotenv(".env.local")

thing_id = getenv("thing_id") or str(uuid4())
thing_name = getenv("thing_name") or "test"
endpoint = getenv("aws_endpoint")
auth_directory = getenv("auth_directory")

if __name__ == "__main__":
    thing = AWSIOTThing(
        id=thing_id,
        name=thing_name,
        endpoint=endpoint,
        cert_filepath=f"{auth_directory}/{thing_name}.cert.pem",
        pri_key_filepath=f"{auth_directory}/{thing_name}.private.key",
        root_ca_filepath=f"{auth_directory}/root-CA.crt",
        initial_state={
            "hello": "world",
        },
        override_cloud_state=False,
        clean_session=False,
        keep_alive_secs=30,
        subscribe_qos=mqtt.QoS.AT_LEAST_ONCE,
        publish_qos=mqtt.QoS.AT_LEAST_ONCE,
        verbose=True,
    )

    thing.connect()
    sleep(5)
    thing.update_shadow_state_synchronous({"foo": "bar"}, timeout=5)
    sleep(1)
    print(json.dumps(thing.get_state(), indent=4))
    thing.disconnect()
