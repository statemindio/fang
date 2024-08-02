import os
import random
import string

from vyper.utils import checksum_encode

from utils import fill_address


class BytesRandomGen:
    def generate(self, input_type):
        return random.randbytes(input_type.m)


class BytesMRandomGen:
    def generate(self, input_type):
        return "0x" + os.urandom(input_type.m).hex()


class IntRandomGen:
    @classmethod
    def _get_value_boundaries(cls, n, signed):
        low_limit = 0
        upper_limit = (2 ** n) - 1
        if signed:
            low_limit = -(2 ** (n - 1))
            upper_limit = (2 ** (n - 1)) - 1
        return low_limit, upper_limit

    def generate(self, input_type):
        low, up = self._get_value_boundaries(input_type.n, input_type.signed)
        return random.randint(low, up)


class BoolRandomGen:
    def generate(self, input_type):
        return bool(random.getrandbits(1))


class StringRandomGen:
    def generate(self, input_type):
        l = random.randint(0, 2 ** 8 - 1)  # EXPLAINED: randomly generate len of string
        if l > input_type.m:
            l = input_type.m
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=l)) # TODO: i think can use more chars
        return f"{s}"


class AddressRandomGen:
    def generate(self, input_type):
        val = fill_address(hex(random.randint(0, 2 ** 160 - 1)))
        return checksum_encode(val)


class DecimalRandomGen:
    def generate(self, input_type):
        return random.randint(0, 2 ** 168 - 1) / 10 ** 10 - (2 ** 167 / 10 ** 10)

class BytesZeroGen:
    def generate(self, input_type):
        return b''


class BytesMZeroGen:
    def generate(self, input_type):
        return "0x" + '00' * input_type.m


class IntZeroGen:
    def generate(self, input_type):
        return 0


class BoolZeroGen:
    def generate(self, input_type):
        return False


class StringZeroGen:
    def generate(self, input_type):
        return ""


class AddressZeroGen:
    def generate(self, input_type):
        return '0x0000000000000000000000000000000000000000'


class DecimalZeroGen:
    def generate(self, input_type):
        return 0.0