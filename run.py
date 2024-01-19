import atheris
import atheris_libprotobuf_mutator
import sys
from google.protobuf.json_format import MessageToJson

with atheris.instrument_imports():
    import sys
    from vyper import compile_code
    from vyper.exceptions import CompilerPanic, StaticAssertionException

import vyperProtoNew_pb2
from converters.typed_converters import TypedConverter


@atheris.instrument_func
def TestOneProtoInput(msg):
    proto = TypedConverter(msg)
    proto.visit()
    print(proto.result)
    print('proto:')
    print(MessageToJson(msg))
    print('compiler:')
    try:
        print(compile_code(proto.result))
    except StaticAssertionException:
        print("StaticAssertionException")
    print("-------------")


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        [sys.argv[0]], TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
