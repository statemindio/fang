import atheris
import atheris_libprotobuf_mutator
import sys
from google.protobuf.json_format import MessageToJson

with atheris.instrument_imports():
    import sys
    from vyper import compile_code
    from vyper.exceptions import CompilerPanic

import vyperProto_pb2
from converters import ProtoConverter


@atheris.instrument_func
def TestOneProtoInput(msg):
    proto = ProtoConverter(msg)
    proto.visit()
    print(proto.result)
    print('proto:')
    print(MessageToJson(msg))
    print("-------------")


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        [sys.argv[0]], TestOneProtoInput, proto=vyperProto_pb2.Contract)
    atheris.Fuzz()
