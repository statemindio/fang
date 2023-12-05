from types_d.base import BaseType
from types_d.value_generator import BytesMRandomGen, BytesRandomGen, IntRandomGen, BoolRandomGen, StringRandomGen, \
    AddressRandomGen, DecimalRandomGen


class TypeRangeError(Exception):
    pass


class Bytes(BaseType):
    def __init__(self, m):
        if m < 0:
            raise TypeRangeError(m)
        self._m = m
        self._value_generator = BytesRandomGen()

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self._m == other.m

    def __hash__(self):
        return hash(self.name)

    @property
    def m(self):
        return self._m

    @property
    def vyper_type(self):
        return f"Bytes[{self._m}]"

    def generate(self):
        return self._value_generator.generate(self._m)


class BytesM(Bytes):
    def __init__(self, m=32):
        super().__init__(m)
        if not 0 < m <= 32:
            raise TypeRangeError(m)
        self._value_generator = BytesMRandomGen()

    @property
    def vyper_type(self):
        return f"bytes{self._m}"


class Int(BaseType):
    def __init__(self, n=256, signed=False):
        if n % 8 != 0:
            raise TypeRangeError(n)
        self._n = n
        self._signed = signed
        self._value_generator = IntRandomGen()

    def __eq__(self, other):
        return isinstance(other, Int) and self._n == other.n and self._signed == other.signed

    def __hash__(self):
        return hash(self.name)

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

    def generate(self):
        return self._value_generator.generate(self._n, self._signed)


class Bool(BaseType):
    def __init__(self):
        self._value_generator = BoolRandomGen()

    @property
    def vyper_type(self):
        return "bool"


class Decimal(BaseType):
    def __init__(self):
        self._value_generator = DecimalRandomGen()

    @property
    def vyper_type(self):
        return "decimal"

    def generate(self):
        return self._value_generator.generate()


class String(Bytes):
    def __init__(self, m):
        super().__init__(m)
        self._value_generator = StringRandomGen()

    @property
    def vyper_type(self):
        return f"String[{self._m}]"


class Address(BaseType):
    def __init__(self):
        self._value_generator = AddressRandomGen()

    @property
    def vyper_type(self):
        return "address"

    def generate(self):
        return self._value_generator.generate()
