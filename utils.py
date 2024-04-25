import random
import math
import re

from vyper.utils import checksum_encode

import types_d as t

from data_types import Type
from data_types import Int, Bytes, Address, Decimal, String, Bool


BASE_TAB = "    "  # 4 spaces
VALID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
INVALID_PREFIX = "123456789"

def get_spaces(nesting_level):
    return BASE_TAB * nesting_level


def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)  # round returns 0

# THINK: instead of using random values, we can create big dictionaries and take randomly values from them


def get_random_element(arr):
    return random.choice(arr)


#  converting integers <-> decimal doesn't require size check of type
#  converting any integer <-> any integer doesn't require size check of type
#  converting numeric -> bytes require size check of type, size of bytes >= than numeric (can be made via triple convert)
#  converting bytes -> numeric doesn't require size check of type
#  LINKS:
#  https://github.com/vyperlang/vyper/issues/2507
#  https://docs.vyperlang.org/en/stable/types.html#type-conversions

def convert(instance, from_type, to_type, is_literal):
    if from_type == to_type:
        return instance
    
    from_type_obj = extract_type(from_type)
    to_type_obj = extract_type(to_type)

    intermediate = None

    if isinstance(from_type_obj, Bool) or isinstance(to_type_obj, Bool):
        return "convert(" + instance + ", " + to_type + ")"

    if isinstance(from_type_obj, Int | Decimal) and isinstance(to_type_obj, Int | Decimal):
        if is_literal:
            type = Type.DECIMAL
            if isinstance(from_type_obj, Int):
                type = Type.INT

            value = get_value_from_str(instance, type)
            if isinstance(to_type_obj, Int) and value > to_type_obj.get_max_value() or value < to_type_obj.get_min_value():  # TO-DO: check this case for decimal
                instance = str(adjust_value(value, to_type_obj.n, to_type_obj.is_signed))
    
        return "convert(" + instance + ", " + to_type + ")"
    
    if isinstance(from_type_obj, Address) and isinstance(to_type_obj, Int):
        # EXPLAINED: in this case we should convert firstly address to bytes
        intermediate = "convert(" + instance + ", bytes20)"
        return "convert(" + intermediate + ", " + to_type + ")"
    
    if isinstance(from_type_obj, Int) and isinstance(to_type_obj, Address):  # THINK: maybe make other conversions based on this scheme: 1) Check is literal, 2) Check dimensions 3) Check sign 
        if is_literal:

            value = get_value_from_str(instance, Type.INT)

            if value >= 2**(20 * 8):
                instance = str(adjust_value(value, 20 * 8))
            intermediate = "convert(" + instance + ", bytes20)"
        elif from_type_obj.n // 8 > 20:

            value = t.Int().generate()

            instance = str(adjust_value(value, 20 * 8))
        elif from_type_obj.is_signed:  

            intermediate = "convert(" + instance + ", bytes20)"
        if intermediate is not None:
            return "convert(" + intermediate + ", " + to_type + ")"
        else:
            return "convert(" + instance + ", " + to_type + ")"

    if isinstance(from_type_obj, Bytes) and isinstance(to_type_obj, Bytes):
        return "convert(" + instance + ", " + to_type + ")"


def get_value_from_str(value, type):
    try:
        if type == Type.INT:
            return int(value)
        elif type == Type.DECIMAL:
            return float(value)
    except Exception as e:
        raise e


# FIXME: the function below doesn't return a value :)
def adjust_value(value, bits, singed=False):

    if isinstance(value, int):
        
        if singed:
            value = value % 2**(bits - 1)
        else:
            value = value % 2**bits
    elif isinstance(value, str):

        if value[:2] == "0x":

            value = "0x" + value[2: (bits // 4)]
        elif value[0] == "b":

            value = "0x" + value[2: (bits // 4)]
        else:
            pass  # TO-DO: check how to adjust str to certain number of bits


def extract_type(_type):
    res = None
    if 'int' in _type:
        is_signed = _type[0] != 'u'

        n = re.search(r'\d+', _type).group(0)
        n = int(n)

        res = Int(is_signed, n)
    elif 'bytes' in _type.lower():
        l = re.search(r'\d+', _type).group(0)
        l = int(l)

        res = Bytes(l)
    elif 'address' in _type:

        res = Address()
    elif 'decimal' in _type:

        res = Decimal()
    elif 'string' in _type.lower():

        l = re.search(r'\d+', _type).group(0)
        l = int(l)

        res = String(l)
    elif 'bool' in _type:
        
        res = Bool()

    return res


# https://github.com/vyperlang/vyper/blob/158099b9c1a49b5472293c1fb7a4baf3cd015eb5/vyper/utils.py#L44C1-L51C67
try:
    from Crypto.Hash import keccak  # type: ignore

    keccak256 = lambda x: keccak.new(digest_bits=256, data=x).digest()  # noqa: E731
except ImportError:
    import sha3 as _sha3

    keccak256 = lambda x: _sha3.sha3_256(x).digest()  # noqa: E731


def fill_address(adr):
    if len(adr) < 42:
        adr += "0" * (42 - len(adr))
    return adr


def bytes_to_int(bytez):
    o = 0
    for b in bytez:
        o = o * 256 + b
    return o


def check_type_requirements(result, current_type, needed_types, length=None):
    if current_type in needed_types:
        return result, current_type, False

    current_type = get_random_element(needed_types)
    result = current_type.generate()
    result = str(result)

    return result, current_type, True
