from google.protobuf.json_format import Parse

from converters import ProtoConverter, TypedConverter
from vyperProto_pb2 import Contract


def test_var_decl_empty():
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


def test_var_decl_address():
    json_message = """
{
  "decls": [
    {
        "adr": {}
    }
  ]
}
    """
    expected = """x_ADDRESS_0 : address"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_bool():
    json_message = """
{
  "decls": [
    {
        "b": {}
    }
  ]
}
    """
    expected = """x_BOOL_0 : bool"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_decimal():
    json_message = """
{
  "decls": [
    {
        "d": {}
    }
  ]
}
    """
    expected = """x_DECIMAL_0 : decimal"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_bytes_m_empty():
    json_message = """
{
  "decls": [
    {
        "bM": {}
    }
  ]
}
    """
    expected = """x_BYTESM_0 : bytes1"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_bytes_m_32():
    json_message = """
{
  "decls": [
    {
        "bM": {
            "m": 63
        }
    }
  ]
}
    """
    expected = """x_BYTESM_0 : bytes32"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_string_empty():
    json_message = """
{
  "decls": [
    {
        "s": {}
    }
  ]
}
    """
    expected = """x_STRING_0 : String[1]"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_string_382():
    json_message = """
{
  "decls": [
    {
        "s": {
            "max_len": 382
        }
    }
  ]
}
    """
    expected = """x_STRING_0 : String[382]"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_bytes_empty():
    json_message = """
{
  "decls": [
    {
        "barr": {}
    }
  ]
}
    """
    expected = """x_BYTES_0 : Bytes[1]"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    assert conv.result == expected


def test_var_decl_bytes_382():
    json_message = """
{
  "decls": [
    {
        "barr": {
            "max_len": 382
        }
    }
  ]
}
    """
    expected = """x_BYTES_0 : Bytes[382]"""
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
