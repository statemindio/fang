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

    def get_max_value(self):
        if self.is_signed:
            return 2**(self.n - 1) - 1
        else:
            return 2**self.n - 1

@dataclass
class Bytes:
    s: int

@dataclass
class Address:
    pass

@dataclass
class Decimal:
    n: int = 168
    def get_max_value(self):
        return (2**167 - 1) / 10**10

@dataclass
class String:  # THINK: String is equal to Bytes
    s: int

@dataclass
class Bool:
    pass