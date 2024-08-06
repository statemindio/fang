@external
@nonpayable
def func_0(x_BYTES_0: Bytes[32]):
    x_INT_0: uint64 = convert(x_BYTES_0, uint64)
    x_INT_1: uint256 = convert(x_BYTES_0, uint256)
    x_INT_2: int64 = convert(x_BYTES_0, int64)
    x_INT_3: int256 = convert(x_BYTES_0, int256)
    x_INT_4: uint256 = convert(raw_call(0x1000000000000000000000000000000000000000, b"0", max_outsize=32), uint256)


