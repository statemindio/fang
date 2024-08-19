from config import Config
import vyper

conf = Config()
if vyper.__version__ == '0.3.10':
    from vyperProtoNew_pb2 import *
# 0.3.10 and 0.4.0 w decimals are the same for now
# but will diverge
elif '--enable-decimals' in conf.extra_flags and vyper.__version__ == '0.4.0':
    from vyperProtoNew_pb2 import *
elif vyper.__version__ == '0.4.0':
    from vyperProtoNewNoDecimal_pb2 import *
