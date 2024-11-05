from fuzz.types_d import types, value_generator
from enum import Enum
import decimal

class InputStrategy(Enum):
    DEFAULT = 1
    ZEROS = 2

class InputGenerator:

    def __init__(self, strategy: InputStrategy = InputStrategy.DEFAULT):
        # set up type generators
        self.default = {
            types.Int: value_generator.IntRandomGen(),
            types.Bytes: value_generator.BytesRandomGen(),
            types.BytesM: value_generator.BytesMRandomGen(),
            types.Bool: value_generator.BoolRandomGen(),
            types.Decimal: value_generator.DecimalRandomGen(),
            types.String: value_generator.StringRandomGen(),
            types.Address: value_generator.AddressRandomGen()
        }
        self.zeroes = {
            types.Int: value_generator.IntZeroGen(),
            types.Bytes: value_generator.BytesZeroGen(),
            types.BytesM: value_generator.BytesMZeroGen(),
            types.Bool: value_generator.BoolZeroGen(),
            types.Decimal: value_generator.DecimalZeroGen(),
            types.String: value_generator.StringZeroGen(),
            types.Address: value_generator.AddressZeroGen()
        }
        # set current strategy
        if strategy is InputStrategy.ZEROS:
            self.gens = self.zeroes
        else:
            self.gens = self.default

    def generate(self, input_types):
        values = []
        for itype in input_types:
            if isinstance(itype, types.FixedList) or isinstance(itype, types.DynArray):
                t_val = self.generate([itype.base_type for i in range(itype.size)])
            else:
                t_val = self.gens[itype.__class__].generate(itype)
                t_val = self._convert_gen_output(itype, t_val)
            values.append(t_val)
        return values

    def _convert_gen_output(self, typ, value):
        if isinstance(typ, types.Decimal):
            return decimal.Decimal(value)
        if isinstance(typ, types.BytesM):
            return bytes.fromhex(value[2:])
        #if type(typ) == types.Bytes:
        #    return bytes.fromhex(value[2:-1])
        return value

    def change_strategy(self, strategy: InputStrategy):
        if strategy is InputStrategy.ZEROS:
            self.gens = self.zeroes
        else:
            self.gens = self.default