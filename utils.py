import random
import math
import re

from vyper.utils import checksum_encode

import types_d as t

from data_types import Type
from data_types import Int, Bytes, Address, Decimal, String, Bool


BASE_TAB = "    "  # 4 spaces
VALID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
INVALID_PREFIX = "0123456789"

_PYTHON_RESERVED_KEYWORDS = {
    "False",
    "None",
    "True",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
}
_PYTHON_RESERVED_KEYWORDS = {s.lower() for s in _PYTHON_RESERVED_KEYWORDS}

# Cannot be used for variable or member naming
RESERVED_KEYWORDS = _PYTHON_RESERVED_KEYWORDS | {
    # decorators
    "public",
    "external",
    "nonpayable",
    "constant",
    "immutable",
    "transient",
    "internal",
    "payable",
    "nonreentrant",
    # "class" keywords
    "interface",
    "struct",
    "event",
    "enum",
    # EVM operations
    "unreachable",
    # special functions (no name mangling)
    "init",
    "_init_",
    "___init___",
    "____init____",
    "default",
    "_default_",
    "___default___",
    "____default____",
    # more control flow and special operations
    "range",
    # more special operations
    "indexed",
    # denominations
    "ether",
    "wei",
    "finney",
    "szabo",
    "shannon",
    "lovelace",
    "ada",
    "babbage",
    "gwei",
    "kwei",
    "mwei",
    "twei",
    "pwei",
    # sentinal constant values
    # TODO remove when these are removed from the language
    "zero_address",
    "empty_bytes32",
    "max_int128",
    "min_int128",
    "max_decimal",
    "min_decimal",
    "max_uint256",
    "zero_wei",
}


def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)  # round returns 0

# THINK: instead of using random values, we can create big dictionaries and take randomly values from them

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
