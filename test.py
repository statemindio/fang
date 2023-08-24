import atheris
import sys

import atheris_libprotobuf_mutator
import vyperProto_pb2


@atheris.instrument_func
def TestOneProtoInput(msg):
    print(msg.key)
    
    if msg.key == "0":
        raise RuntimeError('Solved!')


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProto_pb2.Reentrancy)
    atheris.Fuzz()