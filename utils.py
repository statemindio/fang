import os
import random
import string
import math
from data_types import Type

BASE_TAB = "    "  # 4 spaces


def get_spaces(nesting_level):
    return BASE_TAB * nesting_level


def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)  # round returns 0

# THINK: instead of using random values, we can create big dictionaries and take randomly values from them


def get_random_token(type: Type):
    if type == Type.INT:
        
        return random.randint(0, 2**256 - 1)
    elif type == Type.ADDRESS:

        rval = fill_address(hex(random.randint(0, 2**160 - 1)))
        return checksum_encode(rval)
    elif type == Type.BYTEARRAY:

        rval = random.randint(0, 2**256 - 1)  # TO-DO: check range of random.randint
        return f"b\"{hex(rval)}\""
    elif type == Type.BOOL:

        return bool(random.getrandbits(1))
    elif type == Type.DECIMAL:

        return random.randint(0, 2**168 - 1) / 10**10 
    elif type == Type.BytesM:

        return "0x" + os.urandom(32).hex()
    elif type == Type.STRING:
        l = random.randint(0, 2**256 - 1)  # EXPLAINED: randomly generate len of string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=l))  # TO-DO: Add more characters, String can have not only letters and digits


def get_random_element(arr):
    return random.choice(arr)

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
