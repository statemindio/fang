from config import Config
import vyper

conf = Config()
if vyper.__version__ == '0.3.10':
    from vyperProtoNew_pb2 import *
# 0.3.10 and 0.4.0 w decimals are the same for now
# but will diverge
elif vyper.__version__ == '0.4.0' and 'enable_decimals' in conf.extra_flags:
    from vyperProtoNew_pb2 import *
elif vyper.__version__ == '0.4.0':
    from vyperProtoNewNoDecimal_pb2 import *
