import pickle
import logging

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

import vyperProtoNew_pb2
from config import Config
from db import get_mongo_client
from queue_managers import QueueManager, MultiQueueManager

with atheris.instrument_imports():
    import sys
    import vyper
    from converters.typed_converters import TypedConverter

__version__ = "0.1.0"  # same version as images' one

conf = Config()
# TODO: get level from config
logger = logging.getLogger("generator")
logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logging.INFO)
logger.info("Starting version %s", __version__)

db_client = get_mongo_client(conf.db["host"], conf.db["port"])

qm = MultiQueueManager(queue_managers=[
    QueueManager(
        q_params["host"],
        q_params["port"],
        q_params["queue_name"],
        logger
    )
    for q_params in conf.compiler_queues])


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

    logger.debug("Converting: %s", MessageToJson(msg))

    c_log = db_client["compilation_log"]
    f_log = db_client['failure_log']
    try:
        proto = TypedConverter(msg)
        proto.visit()
    except Exception as e:
        converter_error = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "json_msg": MessageToJson(msg),
        }
        f_log.insert_one(converter_error)

        logger.critical("Converter has crashed: %s", converter_error)
        raise e  # Do we actually want to fail here?
    data["generation_result"] = proto.result
    try:
        c_result = vyper.compile_code(proto.result)
        data["compilation_result"] = c_result
    except Exception as e:
        data["error_type"] = type(e).__name__
        data["error_message"] = str(e)
    ins_res = c_log.insert_one(data)

    logger.debug("Compilation result: %s", data)

    function_inputs = pickle.dumps(proto.function_inputs).hex()
    logger.debug("Generated inputs: %s", function_inputs)

    message = {
        "_id": str(ins_res.inserted_id),
        "generation_result": proto.result,
        "function_input_types": function_inputs,
        "json_msg": MessageToJson(msg),
        "generator_version": __version__,
    }
    qm.publish(**message)


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
