import os
import random
import string
import math
import re

from data_types import Type
from data_types import Int, Bytes, Address, Decimal, String, Bool


BASE_TAB = "    "  # 4 spaces


def get_spaces(nesting_level):
    return BASE_TAB * nesting_level


def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)  # round returns 0

# THINK: instead of using random values, we can create big dictionaries and take randomly values from them


def get_random_token(type: Type):
    if type == Type.INT:
        
        return random.randint(0, 2**256 - 1), "uint256"
    elif type == Type.ADDRESS:

        rval = fill_address(hex(random.randint(0, 2**160 - 1)))
        return checksum_encode(rval), "address"
    elif type == Type.BYTEARRAY:

        rval = random.randint(0, 2**256 - 1)  # TO-DO: check range of random.randint
        hex_val = hex(rval)
        return f"b\"{hex_val}\"", f"Bytes[{len(hex_val) / 2}]"
    elif type == Type.BOOL:

        return bool(random.getrandbits(1)), "bool"
    elif type == Type.DECIMAL:
        
        return random.randint(0, 2**168 - 1) / 10**10 - (2**167 / 10**10), "decimal"
    elif type == Type.BytesM:

        m = random.randint(0, 32)
        return "0x" + os.urandom(m).hex(), f"bytes{m}"
    elif type == Type.STRING:

        l = random.randint(0, 2**256 - 1)  # EXPLAINED: randomly generate len of string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=l)), "String[{l}]"  # TO-DO: Add more characters, String can have not only letters and digits


def get_random_element(arr):
    return random.choice(arr)


#  converting integers <-> decimal doesn't require size check of type
#  converting any integer <-> any integer doesn't require size check of type
#  converting numeric -> bytes require size check of type, size of bytes >= than numeric (can be made via triple convert)
#  converting bytes -> numeric doesn't require size check of type

def convert(instance, from_type, to_type, is_literal):
    
    from_type_obj = extract_type(from_type)
    to_type_obj = extract_type(to_type)

    intermediate = None

    if isinstance(from_type_obj, Bool) or isinstance(to_type_obj, Bool):
        return "convert(" + instance + ", " + to_type + ")"

    if isinstance(from_type_obj, Int | Decimal) and isinstance(to_type_obj, Int | Decimal):
        if is_literal:
            type = None
            if isinstance(from_type_obj, Int):
                type = Type.INT
            else:
                type = Type.DECIMAL

            value = get_value_from_str(instance, type)
            if value > to_type_obj.get_max_value():  # TO-DO: check this case for decimal
                instance = str(adjust_value(value, to_type_obj.n))
    
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

            value, _ = get_random_token(Type.INT) 

            instance = str(adjust_value(value, 20 * 8))
        elif from_type_obj.is_signed:  

            intermediate = "convert(" + instance + ", bytes20)"
        if intermediate != None:
            return "convert(" + intermediate + ", " + to_type + ")"
        else:
            return "convert(" + instance + ", " + to_type + ")"


    if isinstance(from_type_obj, Bytes) and isinstance(to_type_obj, Bytes):
        return "convert(" + instance + ", " + to_type + ")"
    

def get_value_from_str(value, type):
    try:
        if type == Type.INT:
            return int(value)
        elif type == Type.Decimal:
            return float(value)
    except Exception as e:
        raise e 

def adjust_value(value, bits):

    if isinstance(value, int):

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

        n = re.match(r'\d+', _type).group(0)
        n = int(n)

        res = Int(is_signed, n)
    elif 'bytes' in _type.lower():
        l = re.match(r'\d+', _type).group(0)
        l = int(l)

        res = Bytes(l)
    elif 'address' in _type:

        res = Address()
    elif 'decimal' in _type:

        res = Decimal()
    elif 'string' in _type.lower():

        l = re.match(r'\d+', _type).group(0)
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

def checksum_encode(addr):  # Expects an input of the form 0x<40 hex chars>
    assert addr[:2] == "0x" and len(addr) == 42, addr
    o = ""
    v = bytes_to_int(keccak256(addr[2:].lower().encode("utf-8")))
    for i, c in enumerate(addr[2:]):
        if c in "0123456789":
            o += c
        else:
            o += c.upper() if (v & (2 ** (255 - 4 * i))) else c.lower()
    return "0x" + o
