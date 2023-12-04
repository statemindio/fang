import os
import random
import string

from utils import fill_address, checksum_encode


class BytesRandomGen:
    def generate(self, m):
        # TODO: it must be checked whether hex representation is allowed for bytes array
        return "0x" + os.urandom(m).hex()


class BytesMRandomGen:
    def generate(self, m):
        return "0x" + os.urandom(m).hex()


class IntRandomGen:
    @classmethod
    def _get_value_boundaries(cls, n, signed):
        low_limit = 0
        upper_limit = (2 ** n) - 1
        if signed:
            low_limit = -(2 ** (n - 1))
            upper_limit = (2 ** (n - 1)) - 1
        return low_limit, upper_limit

    def generate(self, n, signed):
        low, up = self._get_value_boundaries(n, signed)
        return random.randint(low, up)


class BoolRandomGen:
    def generate(self):
        return bool(random.getrandbits(1))


class StringRandomGen:
    def generate(self, m):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=m))


class AddressRandomGen:
    def generate(self):
        val = fill_address(hex(random.randint(0, 2 ** 160 - 1)))
        return checksum_encode(val)


class DecimalRandomGen:
    def generate(self):
        return random.randint(0, 2 ** 168 - 1) / 10 ** 10 - (2 ** 167 / 10 ** 10)
