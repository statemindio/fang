import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

with atheris.instrument_imports():
    import sys

import vyperProtoNew_pb2
from converters.typed_converters import TypedConverter
from tests.integration_runner.db import get_mongo_client


class CountExceeded(Exception):
    pass


db_queue = get_mongo_client()


@atheris.instrument_func
def TestOneProtoInput(msg):
    proto = TypedConverter(msg)
    proto.visit()
    queue = db_queue["test_col"]
    queue.insert_one({
        "result": proto.result,
        "msg_json": MessageToJson(msg),
        "in_queue": False,
        "compiled": False,
    })


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
