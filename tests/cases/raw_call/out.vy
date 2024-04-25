@external
@view
def func_0(x_ADDRESS_0: address, x_BYTES_0: Bytes[100], x_INT_0: uint256) -> Bytes[32]:
    x_BOOL_0: bool = False
    x_BYTES_1: Bytes[32] = b""
    x_BOOL_0, x_BYTES_1 = raw_call(x_ADDRESS_0, x_BYTES_0, max_outsize=32, gas=1337, value=x_INT_0, is_static_call=True, revert_on_failure=False)
    return x_BYTES_1

@external
@nonpayable
def func_1(x_ADDRESS_1: address, x_BYTES_2: Bytes[100]):
    raw_call(x_ADDRESS_1, x_BYTES_2)


@external
@nonpayable
def func_2():
    x_BOOL_1: bool = raw_call(0x0000000000000000000000000000000000000000, b"0", gas=288230376151711744, revert_on_failure=False)


@external
@nonpayable
def func_3():
    x_BOOL_2: bool = raw_call(0x0000000000000000000000000000000000000000, b"0", revert_on_failure=False)
    x_BOOL_2 = raw_call(0x0000000000000000000000000000000000000000, b"0", revert_on_failure=False)
    x_BYTES_3: Bytes[20] = raw_call(0x0000000000000000000000000000000000000000, b"0", max_outsize=20)
    x_BYTES_3 = raw_call(0x0000000000000000000000000000000000000000, b"0", max_outsize=20)


