import os

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
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/var_decl_multiple_bytes_382/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/var_decl_multiple_bytes_382/out.vy", "r") as out_contract:
        expected = out_contract.read()
    conv = convert_message(json_message)
    assert conv.result == expected


def test_var_decl_multiple_bytes_382_and_ints():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/var_decl_multiple_bytes_382_and_ints/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/var_decl_multiple_bytes_382_and_ints/out.vy", "r") as out_contract:
        expected = out_contract.read()
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
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/function/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/function/out.vy", "r") as out_contract:
        expected = out_contract.read()
    mes = ""
    conv = TypedConverter(mes)
    mes = Parse(json_message, Func())
    address_type = Address()
    conv.type_stack.append(address_type)
    conv._var_tracker.register_global_variable("var0", address_type)

    res = conv.visit_func(mes)
    assert res == expected


def test_elif_cases():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/elif_cases/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/elif_cases/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()

    print(conv.result)
    assert conv.result == expected


def test_proto_converter():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/proto_converter/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/proto_converter/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


def test_assignment():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/assignment/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/assignment/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


def test_assignment_to_nonexistent_variable():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/assignment_to_nonexistent_variable/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/assignment_to_nonexistent_variable/out.vy", "r") as out_contract:
        expected = out_contract.read()
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


# TODO: trailing spaces may force error
def test_assert_statement():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/assert_statement/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/assert_statement/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


def test_assert_statement_if():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/assert_statement_if/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/assert_statement_if/out.vy", "r") as out_contract:
        expected = out_contract.read()
    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected


def test_contract_input_params():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/contract_input_params/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/contract_input_params/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)
    conv.visit()
    print(conv.result)
    assert conv.result == expected
