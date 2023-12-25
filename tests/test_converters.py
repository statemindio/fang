from google.protobuf.json_format import Parse

from converters import ProtoConverter, TypedConverter
from vyperProto_pb2 import Contract


def convert_message(message: str) -> TypedConverter:
    mes = Parse(message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    return conv


def test_var_decl_empty():
    json_message = """
{
  "decls": [
    {}
  ]
}
    """
    expected = """x_INT_0 : uint8
"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_var_decl_int_empty():
    json_message = """
{
  "decls": [
    {
        "i": {}
    }
  ]
}
    """
    expected = """x_INT_0 : uint8
"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_var_decl_uint_256():
    json_message = """
{
  "decls": [
    {
        "i": {
            "n": 511,
            "sign": false
        }
    }
  ]
}
    """
    expected = """x_INT_0 : uint256
"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_var_decl_int_256():
    json_message = """
{
  "decls": [
    {
        "i": {
            "n": 511,
            "sign": true
        }
    }
  ]
}
    """
    expected = """x_INT_0 : int256
"""
    conv = convert_message(json_message)
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
    expected = """x_ADDRESS_0 : address
"""
    conv = convert_message(json_message)
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
    expected = """x_BOOL_0 : bool
"""
    conv = convert_message(json_message)
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
    expected = """x_DECIMAL_0 : decimal
"""
    conv = convert_message(json_message)
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
    expected = """x_BYTESM_0 : bytes1
"""
    conv = convert_message(json_message)
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
    expected = """x_BYTESM_0 : bytes32
"""
    conv = convert_message(json_message)
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
    expected = """x_STRING_0 : String[1]
"""
    conv = convert_message(json_message)
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
    expected = """x_STRING_0 : String[382]
"""
    conv = convert_message(json_message)
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
    expected = """x_BYTES_0 : Bytes[1]
"""
    conv = convert_message(json_message)
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
    expected = """x_BYTES_0 : Bytes[382]
"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_var_decl_multiple_bytes_382():
    json_message = """
{
  "decls": [
    {
        "barr": {
            "max_len": 382
        }
    },
    {
        "barr": {
            "max_len": 382
        }
    },
    {
        "barr": {
            "max_len": 382
        }
    }
  ]
}
    """
    expected = """x_BYTES_0 : Bytes[382]
x_BYTES_1 : Bytes[382]
x_BYTES_2 : Bytes[382]
"""
    conv = convert_message(json_message)
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
