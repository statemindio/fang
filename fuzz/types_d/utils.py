from vyper.utils import checksum_encode

def fill_address(adr):
    if len(adr) < 42:
        adr += "0" * (42 - len(adr))
    return adr
