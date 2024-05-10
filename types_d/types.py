from types_d.base import BaseType
from types_d.value_generator import BytesMRandomGen, BytesRandomGen, IntRandomGen, BoolRandomGen, StringRandomGen, \
    AddressRandomGen, DecimalRandomGen
from types_d.literal_value_generator import BytesLiteralGen, AddressLiteralGen, BytesMLiteralGen, IntLiteralGen, \
    BoolLiteralGen, DecimalLiteralGen, StringLiteralGen


class TypeRangeError(Exception):
    pass


class Bytes(BaseType):
    def __init__(self, m):
        if m < 0:
            raise TypeRangeError(m)
        self._m = m
        self._value_generator = BytesRandomGen()
        self._literal_generator = BytesLiteralGen()

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self._m == other.m

    def __hash__(self):
        return hash(self.vyper_type)

    @property
    def m(self):
        return self._m

    @property
    def vyper_type(self):
        return f"Bytes[{self._m}]"

    def generate(self):
        return self._value_generator.generate(self._m)

    def generate_literal(self, value):
        return self._literal_generator.generate(self._m, value)


class BytesM(Bytes):
    def __init__(self, m=32):
        super().__init__(m)
        if not 0 < m <= 32:
            raise TypeRangeError(m)
        self._value_generator = BytesMRandomGen()
        self._literal_generator = BytesMLiteralGen()

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
        self._literal_generator = IntLiteralGen()

    def __eq__(self, other):
        return isinstance(other, Int) and self._n == other.n and self._signed == other.signed

    def __hash__(self):
        return hash(self.vyper_type)

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

    def generate_literal(self, value):
        return self._literal_generator.generate(self._n, self._signed, value)

    def check_binop_bounds(self, left, bin_op, right):
        try:
            val_left = eval(left)
        except:
            val_left = None  

        try:
            val_right = eval(right)
        except:
            val_right = None 

        # not sure how exactly change affected values
        if bin_op == "**":
            if val_right is not None and val_right < 0:
                right = f"-{right}"

            if val_right is None and val_left is None:
                left = "1"

        if bin_op == "<<" or bin_op == ">>":
            if val_right is not None and val_right > 256:
                right = f"{val_right % 257}"

        if bin_op == "/" or bin_op == "%":
            if val_right is not None and val_right == 0:
                right = "1"

        return left, bin_op, right

    def check_literal_bounds(self, value):
        try:
            e_val = eval(value)
            low, up = self._literal_generator._get_value_boundaries(self._n, self._signed)
            if low > e_val or e_val > up:
                return self._literal_generator.generate(self._n, self._signed, e_val)
        except:
            pass
        return value


class Bool(BaseType):
    def __init__(self):
        self._value_generator = BoolRandomGen()
        self._literal_generator = BoolLiteralGen()

    @property
    def vyper_type(self):
        return "bool"

    def generate(self):
        return self._value_generator.generate()

    def generate_literal(self, value):
        return self._literal_generator.generate(value)


class Decimal(BaseType):
    def __init__(self):
        self._value_generator = DecimalRandomGen()
        self._literal_generator = DecimalLiteralGen()

    @property
    def vyper_type(self):
        return "decimal"

    def generate(self):
        return self._value_generator.generate()

    def generate_literal(self, value):
        return self._literal_generator.generate(value)


class String(Bytes):
    def __init__(self, m):
        super().__init__(m)
        self._value_generator = StringRandomGen()
        self._literal_generator = StringLiteralGen()

    @property
    def vyper_type(self):
        return f"String[{self._m}]"


class Address(BaseType):
    def __init__(self):
        self._value_generator = AddressRandomGen()
        self._literal_generator = AddressLiteralGen()

    @property
    def vyper_type(self):
        return "address"

    def generate(self):
        return self._value_generator.generate()

    def generate_literal(self, value):
        return self._literal_generator.generate(value)


class FixedList(BaseType):
    def __init__(self, size, base_type: BaseType):
        self._base_type = base_type
        self._size = size

    def adjust_size(self, size):
        self._size = size

    @property
    def size(self):
        return self._size

    @property
    def base_type(self):
        return self._base_type

    @property
    def vyper_type(self):
        return f"{self._base_type.vyper_type}[{self._size}]"

    @property
    def name(self):
        #return self.__class__.__name__.upper() + self._base_type.name
        return "FL_" + self._base_type.name
    
class DynArray(FixedList):
    def __init__(self, size, base_type: BaseType, cur_size = 0):
        self._base_type = base_type
        self._size = cur_size
        self._max_size = size

    def adjust_max_size(self, size):
        self._max_size = size

    @property
    def max_size(self):
        return self._max_size

    @property
    def vyper_type(self):
        return f"DynArray[{self._base_type.vyper_type},{self._max_size}]"

    @property
    def name(self):
        #return self.__class__.__name__.upper() + self._base_type.name
        return "DA_" + self._base_type.name
