import json

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

import vyperProtoNew_pb2
from config import Config
from db import get_mongo_client
from queue_managers import QueueManager, MultiQueueManager
from input_generation import InputGenerator, InputStrategy
from json_encoders import ExtendedEncoder

with atheris.instrument_imports():
    import sys
    import vyper
    from converters.typed_converters import TypedConverter

__version__ = "0.1.1"  # same version as images' one

conf = Config()

db_client = get_mongo_client(conf.db["host"], conf.db["port"])

qm = MultiQueueManager(queue_managers=[
    QueueManager(
        q_params["host"],
        q_params["port"],
        q_params["queue_name"]
    )
    for q_params in conf.compiler_queues])

input_strategy = InputStrategy.DEFAULT
input_generator = InputGenerator(input_strategy)

@atheris.instrument_func
def TestOneProtoInput(msg):
    data = {
        "json_msg": MessageToJson(msg),
        "generation_result": None,
        "compilation_result": None,
        "error_type": None,
        "error_message": None,
        "generator_version": __version__,
    }
    c_log = db_client["compilation_log"]
    f_log = db_client['failure_log']
    try:
        proto = TypedConverter(msg)
        proto.visit()
    except Exception as e:
        f_log.insert_one({
            "error_type": type(e).__name__,
            "error_message": str(e),
            "json_msg": MessageToJson(msg),
        })
        raise e  # Do we actually want to fail here?
    data["generation_result"] = proto.result
    try:
        c_result = vyper.compile_code(proto.result)
        data["compilation_result"] = c_result
    except Exception as e:
        data["error_type"] = type(e).__name__
        data["error_message"] = str(e)
    ins_res = c_log.insert_one(data)

    input_values = dict()
    for name, types in proto.function_inputs.items():
        input_values[name] = input_generator.generate(types)

    input_values = json.dumps(input_values, cls=ExtendedEncoder)

    message = {
        "_id": str(ins_res.inserted_id),
        "generation_result": proto.result,
        "function_input_values": input_values,
        "json_msg": MessageToJson(msg),
        "generator_version": __version__,
    }
    qm.publish(**message)


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
