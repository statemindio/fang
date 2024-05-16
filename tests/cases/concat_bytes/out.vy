@external
@pure
def func_0() -> Bytes[12]:
    return concat(b"fffffff", b"fffff")

@external
@pure
def func_1() -> Bytes[12]:
    return concat(0xd75d75d75d75d7, 0xdb6db6db6d)

@external
@pure
def func_2() -> Bytes[65]:
    return concat(b"ffffffffffffff", b"ffffffffff", 0xdb6db6db6db6db6db6db6db6db6db6db6db6db6db6db00000000000000000000, b"")

@external
@pure
def func_3() -> Bytes[33]:
    return concat(b"fffff", 0xdb6db6db6db6db6db6db6db6db6db6db6db6db6db6db0000000000, b"f")

@external
@pure
def func_4(x_BYTES_0: Bytes[7], x_BYTESM_0: bytes32, x_BYTESM_1: bytes1) -> Bytes[40]:
    return concat(x_BYTES_0, x_BYTESM_0, x_BYTESM_1)

