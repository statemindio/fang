import os

import pytest
from google.protobuf.json_format import Parse

from converters.typed_converters import TypedConverter
from types_d import Address, BytesM, String
from vyperProtoNew_pb2 import Contract, CreateMinimalProxy, CreateCopyOf, Sha256, Keccak256, Func


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
    expected = """x_INT_0: uint8

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
    expected = """x_INT_0: uint8

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
    expected = """x_INT_0: uint256

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
    expected = """x_INT_0: int256

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
    expected = """x_ADDRESS_0: address

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
    expected = """x_BOOL_0: bool

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
    expected = """x_DECIMAL_0: decimal

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
    expected = """x_BYTESM_0: bytes1

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
    expected = """x_BYTESM_0: bytes32

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
    expected = """x_STRING_0: String[1]

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
    expected = """x_STRING_0: String[382]

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
    expected = """x_BYTES_0: Bytes[1]

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
    expected = """x_BYTES_0: Bytes[382]

"""
    conv = convert_message(json_message)
    assert conv.result == expected


def test_visit_create_min_proxy_or_copy_of():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
{
    "target": {
        "varRef": {}
    }
}"""

    methods = [(CreateMinimalProxy(), "create_minimal_proxy_to"), (CreateCopyOf(), "create_copy_of")]

    address_type = Address()
    conv.type_stack.append(address_type)
    conv._var_tracker.register_global_variable("var0", address_type)

    for proto, name in methods:
        mes = Parse(json_message, proto)
        expected = f"{name}(self.var0)"
        res = conv.visit_create_min_proxy_or_copy_of(mes, name)
        assert res == expected

hashing = [(Sha256(), "sha256"), (Keccak256(), "keccak256")]

def test_visit_hash256():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "bmVal": {
            "varRef": {}
        }
    }"""

    bytes_m_type = BytesM(32)
    conv.type_stack.append(bytes_m_type)
    conv._var_tracker.register_global_variable("var0", bytes_m_type)

    for proto, name in hashing:
        mes = Parse(json_message, proto)

        expected = f"{name}(self.var0)"
        res = conv._visit_hash256(mes, name)
        assert res == expected


def test_visit_hash256_string():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "strVal": {
            "lit": {
                "strval": "hohohaha"
            }
        }
    }"""

    for proto, name in hashing:
        mes = Parse(json_message, proto)
        expected = f"{name}(\"hohohaha\")"
        res = conv._visit_hash256(mes, name)
        assert res == expected


def test_visit_hash256_string_varref():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "strVal": {
            "varRef": {
                "s": {}
            }
        }
    }"""
    string_type = String(100)
    conv.type_stack.append(string_type)
    conv._var_tracker.register_global_variable("var0", string_type)

    for proto, name in hashing:
        mes = Parse(json_message, proto)
        expected = f"{name}(self.var0)"
        res = conv._visit_hash256(mes, name)
        assert res == expected


def test_visit_hash256_bytes():
    mes = ""
    conv = TypedConverter(mes)
    json_message = """
    {
        "bVal": {
            "lit": {
                "barrval": 2
            }
        }
    }"""
    for proto, name in hashing:
        mes = Parse(json_message, proto)
        expected = f"{name}(b\"2\")"
        res = conv._visit_hash256(mes, name)
        assert res == expected


# def test_function():
#     current_dir = os.path.dirname(__file__)
#     with open(f"{current_dir}/cases/function/in.json", "r") as inp_json:
#         json_message = inp_json.read()
#     with open(f"{current_dir}/cases/function/out.vy", "r") as out_contract:
#         expected = out_contract.read()
#     mes = ""
#     conv = TypedConverter(mes)
#     mes = Parse(json_message, Func())
#     address_type = Address()
#     conv.type_stack.append(address_type)
#     conv._var_tracker.register_global_variable("var0", address_type)
#
#     res = conv.visit_func(mes)
#     assert res == expected


full_cases = [
    "assert_statement",
    "assert_statement_if",
    "assignment",
    "assignment_to_nonexistent_variable",
    "contract_input_params",
    "elif_cases",
    "proto_converter",
    "var_decl_multiple_bytes_382",
    "var_decl_multiple_bytes_382_and_ints",
    "else_case",
    "for_statement",
    "for_statement_variable",
    "for_statement_nonexistent_variable",
    "max_functions_restriction",
    "decimal_expression",
    "bytes_expression",
    "bytes_m_expression",
    "int_expression",
    "bool_expression",
    "create_from_blueprint",
    "create_min_proxy",
    "reentrancy",
    "empty_reentrancy_lock",
    "raise_statement",
    "max_functions_arguments",
    "variable_scoping",
    "function_variable_scoping",
    "for_statement_variable_write",
    "for_statement_boundaries",
    "init_payable",
    "immutable_no_init",
    "default_function",
    "invalid_string_literal_reentrancy",
    "invalid_string_literal_string",
    # "list_adjust_size_output",
    "list_expression",
    "variable_literal_overflow",
    "list_expression_ref_base_type",
    "list_expression_ref_list",
    "list_element_assignment",
    "invalid_string_literal_string",
    "func_call",
    "func_call_multiple",
    "func_call_multiple_cyclic",
    "list_element_assignment",
    "dynamic_array_constant_assignment",
    # "dynamic_array_element_assignment",
    "dynamic_array_assignment",
    "dynamic_array_statements",
    "send",
    "ecrecover",
    "raw_call",
    "raw_call_bytes_expression",
    "raw_call_bool_expression",
    "uint_negation",
    "func_call_var_mutability",
    "literal_expression_folding",
    "input_variable_tracker",
    "constant_only_literal",
    "constant_var_ref"
]


@pytest.mark.parametrize("case_name", full_cases)
def test_proto_converter(case_name):
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/{case_name}/in.json", "r") as inp_json:
        json_message = inp_json.read()
    with open(f"{current_dir}/cases/{case_name}/out.vy", "r") as out_contract:
        expected = out_contract.read()

    mes = Parse(json_message, Contract())
    conv = TypedConverter(mes)

    import random
    random.seed(1337)

    conv.visit()
    print(conv.result)
    assert conv.result == expected
