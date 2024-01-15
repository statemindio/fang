import pytest
from google.protobuf.json_format import Parse

from converters.typed_converters import TypedConverter
from types_d import Address, BytesM
from vyperProtoNew_pb2 import Contract, CreateMinimalProxy, Sha256, Func


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


def test_var_decl_multiple_bytes_382_and_ints():
    json_message = """
{
  "decls": [
    {
        "barr": {
            "max_len": 382
        }
    },
    {
        "i": {
            "n": 511,
            "sign": false
        }
    },
    {
        "barr": {
            "max_len": 382
        }
    },
    {
        "i": {
            "n": 127,
            "sign": true
        }
    }
  ]
}
    """
    expected = """x_BYTES_0 : Bytes[382]
x_INT_0 : uint256
x_BYTES_1 : Bytes[382]
x_INT_1 : int128

"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_visit_create_min_proxy():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
{
    "target": {
        "varRef": {}
    }
}"""
    mes = Parse(json_message, CreateMinimalProxy())
    address_type = Address()
    conv.type_stack.append(address_type)
    conv._var_tracker.register_global_variable("var0", address_type)
    expected = "create_minimal_proxy_to(self.var0)"
    res = conv.visit_create_min_proxy(mes)
    assert res == expected


def test_visit_sha256():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "bmVal": {
            "varRef": {}
        }
    }"""
    mes = Parse(json_message, Sha256())
    bytes_m_type = BytesM(32)
    conv.type_stack.append(bytes_m_type)
    conv._var_tracker.register_global_variable("var0", bytes_m_type)
    expected = "sha256(self.var0)"
    res = conv._visit_sha256(mes)
    assert res == expected


def test_function():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "vis": "INTERNAL",
        "mut": "VIEW",
        "input_params": [
            
        ],
        "output_params": [],
        "block": {
            "statements": [
                {
                    "selfd": {
                        "to": {
                            "varRef": {}
                        }
                    }
                },
                {
                    "if_stmt": {
                        "cases": []
                    }
                }
            ]
        }
    }
    """
    mes = Parse(json_message, Func())
    address_type = Address()
    conv.type_stack.append(address_type)
    conv._var_tracker.register_global_variable("var0", address_type)
    expected = """@internal
@nonpayable
def func_0():
    selfdestruct(self.var0)
    if False:
        pass
"""
    res = conv.visit_func(mes)
    assert res == expected


def test_elif_cases():
    json_message = """
        {
          "decls": [
            {}
          ],
          "functions": [
            {
              "outputParams": [
                {
                  "d": {}
                }
              ],
              "block": {
                "statements": [
                  {
                    "selfd": {}
                  },
                  {
                    "if_stmt": {
                      "cases": [
                        {
                            "cond": {
                                "intBoolBinOp": {
                                    "op": "EQ",
                                    "left": {
                                        "lit": {
                                            "intval": 2
                                        }
                                    },
                                    "right": {
                                        "lit": {
                                            "intval": 5
                                        }
                                    }
                                }
                            },
                            "if_body": {
                                "statements": [
                                    {
                                        "selfd": {}
                                    }
                                ]
                            }
                        },
                        {
                            "cond": {
                                "intBoolBinOp": {
                                    "op": "LESSEQ",
                                    "left": {
                                        "lit": {
                                            "intval": 2
                                        }
                                    },
                                    "right": {
                                        "lit": {
                                            "intval": 5
                                        }
                                    }
                                }
                            },
                            "if_body": {
                                "statements": [
                                    {
                                        "selfd": {}
                                    }
                                ]
                            }
                        }
                      ]
                    }
                  } 
                ]
              }
            }
          ]
        }
    """

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()

    expected = """x_INT_0 : uint8

@external
@nonpayable
def func_0():
    selfdestruct(0x0000000000000000000000000000000000000000)
    if 2 == 5:
        selfdestruct(0x0000000000000000000000000000000000000000)

    elif 2 <= 5:
        selfdestruct(0x0000000000000000000000000000000000000000)



"""
    print(conv.result)
    assert conv.result == expected


def test_proto_converter():
    json_message = """
    {
      "decls": [
        {}
      ],
      "functions": [
        {
          "outputParams": [
            {
              "d": {}
            }
          ],
          "block": {
            "statements": [
              {
                "selfd": {}
              }
            ]
          }
        }
      ]
    }
    """
    expected = """x_INT_0 : uint8

@external
@nonpayable
def func_0():
    selfdestruct(0x0000000000000000000000000000000000000000)

"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


def test_assignment():
    json_message = """
    {
      "decls": [
        {
            "b": {}
        }
      ],
      "functions": [
        {
          "outputParams": [
            {
              "d": {}
            }
          ],
          "block": {
            "statements": [
              {
                "assignment": {
                    "ref_id": {
                        "b": {},
                        "i": {
                            "n": 256,
                            "sign": true
                        },
                        "varnum": 0
                    },
                    "expr": {
                        "boolExp": {
                            "intBoolBinOp": {
                                "op": "LESSEQ",
                                "left": {
                                    "lit": {
                                        "intval": 2
                                    }
                                },
                                "right": {
                                    "lit": {
                                        "intval": 5
                                    }
                                }
                            }
                        }
                    }
                }
              }
            ]
          }
        }
      ]
    }
    """
    expected = """x_BOOL_0 : bool

@external
@view
def func_0():
    self.x_BOOL_0 = 2 <= 5

"""
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected
