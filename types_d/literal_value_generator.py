from vyper.utils import checksum_encode
from utils import fill_address


class BytesLiteralGen:
    def generate(self, m, value):
        hex_val = hex(value)[2:]
        hex_val = hex_val if m > len(hex_val) else hex_val[:m]
        #hex_val = f"{'' if len(hex_val) % 2 == 0 else '0'}{hex_val}"
        result = f"b\"{hex_val}\""
        return result


class AddressLiteralGen:
    def generate(self, value):
        adr = str(hex(value))[:42]
        result = checksum_encode(fill_address(adr))
        return result


class BytesMLiteralGen:
    def generate(self, m, value):
        hex_val = value.hex()
        if len(hex_val) >= m * 2:
            hex_val = hex_val[:m * 2]
        hex_val = f"{'' if len(hex_val) % 2 == 0 else '0'}{hex_val}"
        if len(hex_val) < m * 2:
            hex_val += "00" * (m - len(hex_val) // 2)
        result = "0x" + hex_val
        return result


class IntLiteralGen:
    @classmethod
    def _get_value_boundaries(cls, n, signed):
        low_limit = 0
        upper_limit = (2 ** n) - 1
        if signed:
            low_limit = -(2 ** (n - 1))
            upper_limit = (2 ** (n - 1)) - 1
        return low_limit, upper_limit

    def generate(self, n, signed, value):
        # FIXME: the current implementation doesn't consider a concrete kind of int
        low, up = self._get_value_boundaries(n, signed)
        value = value % (up - low + 1) + low
        return str(value)


class BoolLiteralGen:
    def generate(self, value):
        return str(value)


class DecimalLiteralGen:
    def generate(self, value):
        result = f"{str(value)}.0"  # now `value` can be an integer value only
        return result


class StringLiteralGen:
    def generate(self, m, value):
        # 32 - space cant exist alone
        invalid_symbols = [0, 9, 10, 11, 12, 13, 28, 29, 30, 31, 34, 92, 133, 160]

        result = ""
        for c in value:
            if ord(c) >= 256 or ord(c) in invalid_symbols:
                continue
            result += c

        result = result if len(result) <= m else result[:m]
        return result
