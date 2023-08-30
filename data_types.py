from enum import Enum
from dataclasses import dataclass

class Type(Enum):
    INT = 0
    BOOL = 1
    DECIMAL = 2
    BytesM = 3
    STRING = 4
    ADDRESS = 5
    BYTEARRAY = 6

@dataclass
class Int:
    is_signed: bool
    n: int

@dataclass
class Bytes:
    s: int

@dataclass
class Address:
    pass

@dataclass
class Decimal:
    pass

@dataclass
class String:  # THINK: String is equal to Bytes
    s: int

@dataclass
class Bool:
    pass