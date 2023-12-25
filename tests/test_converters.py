from google.protobuf.json_format import Parse

from converters import ProtoConverter, TypedConverter
from vyperProto_pb2 import Contract


def test_typed_converter_var_decl_empty():
    json_message = """
{
  "decls": [
    {}
  ]
}
    """
    expected = """x_INT_0 : uint8"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected

# def test_proto_converter():
#     json_message = """
# {
#   "decls": [
#     {}
#   ],
#   "functions": [
#     {
#       "outputParams": [
#         {
#           "d": {}
#         }
#       ],
#       "block": {
#         "statements": [
#           {
#             "selfd": {}
#           }
#         ]
#       }
#     }
#   ]
# }
#     """
#     expected = """x_INT_0 : uint8
#
# @external
# @pure
# def func_0() -> (decimal):
#     selfdestruct(0xe2204Cf6451214Cccc8D953e023eEC388453F57f)"""
#     mes = Parse(json_message, Contract())
#     conv = TypedConverter(mes)
#     conv.visit()
#     print(conv.result)
#     assert False
