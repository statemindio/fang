@external
@view
def func_0(x_ADDRESS_0: address, x_BYTES_0: Bytes[100], x_INT_0: uint256):
    assert raw_call(x_ADDRESS_0, x_BYTES_0, gas=1337, value=x_INT_0, is_static_call=True, revert_on_failure=False)


