from vyper.utils import checksum_encode
from utils import fill_address


class BytesLiteralGen:
    def generate(self, m, value):
        hex_val = hex(value)
        hex_val = hex_val if len(hex_val) > m * 2 else hex_val[:m * 2]
        hex_val = f"{'' if len(hex_val) % 2 == 0 else '0'}{hex_val}"
        result = f"b\"{hex_val}\""
        return result


class AddressLiteralGen:
    def generate(self, value):
        adr = str(hex(value))[:42]
        result = checksum_encode(fill_address(adr))
        return result
