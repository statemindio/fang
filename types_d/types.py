from types_d.base import BaseType


class TypeRangeError(Exception):
    pass


class Bytes(BaseType):
    def __init__(self, m):
        if m < 0:
            raise TypeRangeError(m)
        self._m = m

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self._m == other.m

    @property
    def m(self):
        return self._m

    @property
    def vyper_type(self):
        return f"Bytes[{self._m}]"


class BytesM(Bytes):
    def __init__(self, m=32):
        super().__init__(m)
        if not 0 < m <= 32:
            raise TypeRangeError(m)

    @property
    def vyper_type(self):
        return f"bytes{self._m}"


class Int:
    def __init__(self, n=256, signed=False):
        if n not in [2 ** i for i in range(3, 9)]:
            raise TypeRangeError(n)
        self._n = 256
        self._signed = signed

    def __eq__(self, other):
        return isinstance(other, Int) and self._n == other.n and self._signed == other.signed

    @property
    def n(self):
        return self._n

    @property
    def signed(self):
        return self._signed

    @property
    def vyper_type(self):
        type_name = f"{'' if self._signed else 'u'}int{self._n}"
        return type_name


class Bool(BaseType):
    @property
    def vyper_type(self):
        return "bool"


class Decimal(BaseType):
    @property
    def vyper_type(self):
        return "decimal"


class String(Bytes):
    @property
    def vyper_type(self):
        return f"String[{self._m}]"


class Address(BaseType):
    @property
    def vyper_type(self):
        return "address"
