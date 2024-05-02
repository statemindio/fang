import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

import vyperProtoNew_pb2
from db import get_mongo_client

with atheris.instrument_imports():
    import sys
    import vyper
    from converters.typed_converters import TypedConverter
    from vyper.exceptions import CompilerPanic, StaticAssertionException

db_client = get_mongo_client()

__version__ = "0.0.8"  # same version as images' one


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
    proto = TypedConverter(msg)
    proto.visit()
    data["generation_result"] = proto.result
    try:
        c_result = vyper.compile_code(proto.result)
        data["compilation_result"] = c_result
    except Exception as e:
        data["error_type"] = type(e).__name__
        data["error_message"] = str(e)

    c_log.insert_one(data)


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
