import importlib
from config import Config

def import_proto():
    conf = Config()
    proto_file = conf.proto_file
    return importlib.import_module(proto_file)
