import json
import os

import pika.exceptions
import vyper
from bson.objectid import ObjectId
from vyper.compiler.settings import Settings, OptimizationLevel

from config import Config
from db import get_mongo_client

compiler_name = os.environ.get("SERVICE_NAME")

conf = Config("./config.yml")
compiler_params = conf.get_compiler_params_by_name(compiler_name)

if compiler_params is None:
    # TODO: raise a error here
    pass

connection = pika.BlockingConnection(pika.ConnectionParameters(
    host=compiler_params["queue"]["host"],
    port=int(compiler_params["queue"]["port"])
))
channel = connection.channel()

queue_name = 'queue3.10'

channel.queue_declare(queue_name)

compiler_key = f"{vyper.__version__.replace('.', '_')}_{compiler_name}"

db_ = get_mongo_client(conf.db["host"], conf.db["port"])
queue_collection = db_["compilation_log"]
compilation_results = db_[f"compilation_results_{compiler_key}"]


def callback(ch, method, properties, body):
    data = json.loads(body)
    print(data["_id"])
    gen = {
        "generation_id": data["_id"],
        "ran": False
    }
    try:
        settings = Settings(optimize=OptimizationLevel.from_string(compiler_params["exec_params"]["optimization"]))
        comp = vyper.compile_code(data["generation_result"], output_formats=("bytecode", "abi"), settings=settings)
        gen.update(comp)
        queue_collection.update_one({"_id": ObjectId(data["_id"])},
                                    {"$set": {f"compiled_{compiler_key}": True}})
    except Exception as e:
        gen.update({"error": str(e)})
    compilation_results.insert_one(gen)


while True:
    try:
        channel.basic_consume(queue_name, on_message_callback=callback, auto_ack=True)
        channel.start_consuming()
    except (pika.exceptions.StreamLostError, pika.exceptions.ChannelWrongStateError):
        pass
