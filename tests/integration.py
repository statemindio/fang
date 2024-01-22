# import pprint

import atheris
import atheris_libprotobuf_mutator
import sys
from google.protobuf.json_format import MessageToJson

with atheris.instrument_imports():
    import sys
    from vyper import compile_code
    from vyper.exceptions import CompilerPanic

import vyperProtoNew_pb2
from converters.typed_converters import TypedConverter

success = 0
errors = 0
samples_count = 0
max_samples = 100000


class CountExceeded(Exception):
    pass


@atheris.instrument_func
def TestOneProtoInput(msg):
    global success
    global errors
    global samples_count
    global max_samples

    try:
        if samples_count >= max_samples:
            raise CountExceeded("Max samples")
        samples_count += 1

        proto = TypedConverter(msg)
        proto.visit()
        print(proto.result)
        print('proto:')
        print(MessageToJson(msg))
        try:
            comp = compile_code(proto.result)
            print(comp)
            success += 1
        except Exception as e:
            errors += 1
        print("-------------")
    except (KeyboardInterrupt, CountExceeded):
        print(success, errors)
        sys.exit(0)


if __name__ == '__main__':
    # try:
    atheris_libprotobuf_mutator.Setup(
        [sys.argv[0]], TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
    # except Exception as e:
    #     print(e)
    # except (KeyboardInterrupt, CountExceeded):
    #     print(success, errors)
    sys.exit(0)
