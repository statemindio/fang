from types_d import types, value_generator
from enum import Enum
import decimal

class InputStrategy(Enum):
    DEFAULT = 1
    ZEROS = 2

class InputGenerator:

    def __init__(self, strategy: InputStrategy):
        # set up type generators
        self.default = {
            type(types.Int): value_generator.IntRandomGen(),
            type(types.Bytes): value_generator.BytesRandomGen(),
            type(types.BytesM): value_generator.BytesMRandomGen(),
            type(types.Bool): value_generator.BoolRandomGen(),
            type(types.Decimal): value_generator.DecimalRandomGen(),
            type(types.String): value_generator.StringRandomGen(),
            type(types.Address): value_generator.AddressRandomGen()
        }
        self.zeroes = {}
        # set current strategy
        if strategy is InputStrategy.DEFAULT:
            self.gens = self.default

    def generate(self, input_types):
        values = []
        for itype in input_types:
            t_val = []
            if isinstance(itype, types.FixedList) or isinstance(itype, types.DynArray):
                t_val.append(self.generate([itype.base_type for i in range(itype.size)]))
            else:
                t_val = self.gens[type(itype)](itype)
                t_val = self._convert_gen_output(itype, t_val)
            values.append(t_val)
        return values

    def _convert_gen_output(self, typ, value):
        if isinstance(typ, types.Decimal):
            return decimal.Decimal(value)
        if isinstance(typ, types.BytesM):
            return bytes.fromhex(value[2:])
        if isinstance(typ, types.Bytes):
            return bytes.fromhex(value[2:-1])
        return value
        # Shouldn't catch types_d.String but not sure