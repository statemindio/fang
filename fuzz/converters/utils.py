import math

from fuzz.helpers.config import MAX_LIST_SIZE, MAX_BYTESTRING_SIZE
from fuzz.types_d import Bool, Decimal, BytesM, String, Address, Bytes, FixedList, DynArray, Int

def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)

def _has_field(instance, field):
    try:
        return instance.HasField(field)
    except ValueError:
        return False

def _get_sizes(type_):
    if isinstance(type_, Bytes):
        return [type_.m]
    if isinstance(type_, FixedList):
        return [type_.size, _get_sizes(type_._base_type)]
    if isinstance(type_, Int):
        return type_.n
    return 0

def extract_type(instance):
    if _has_field(instance, "b"):
        current_type = Bool()
    elif _has_field(instance, "d"):
        current_type = Decimal()
    elif _has_field(instance, "bM"):
        m = instance.bM.m % 32 + 1
        current_type = BytesM(m)
    elif _has_field(instance, "s"):
        max_len = 1 if instance.s.max_len == 0 else instance.s.max_len
        max_len = max_len if max_len < MAX_BYTESTRING_SIZE else MAX_BYTESTRING_SIZE
        current_type = String(max_len)
    elif _has_field(instance, "adr"):
        current_type = Address()
    elif _has_field(instance, "barr"):
        max_len = 1 if instance.barr.max_len == 0 else instance.barr.max_len
        max_len = max_len if max_len < MAX_BYTESTRING_SIZE else MAX_BYTESTRING_SIZE
        current_type = Bytes(max_len)
    elif _has_field(instance, "list"):
        list_len = 1 if instance.list.n == 0 else instance.list.n
        list_len = list_len if instance.list.n < MAX_LIST_SIZE else MAX_LIST_SIZE

        current_type = extract_type(instance.list)
        current_type = FixedList(list_len, current_type)
    elif _has_field(instance, "dyn"):
        list_len = 1 if instance.dyn.n == 0 else instance.dyn.n
        list_len = list_len if instance.dyn.n < MAX_LIST_SIZE else MAX_LIST_SIZE
        current_type = extract_type(instance.dyn)
        current_type = DynArray(list_len, current_type)
    else:
        n = instance.i.n % 256 + 1
        n = get_nearest_multiple(n, 8)
        current_type = Int(n, instance.i.sign)

    return current_type

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