@external
@nonpayable
def func_0(x_BYTESM_0: bytes32) -> address:
    x_ADDRESS_0: address = create_minimal_proxy_to(0x1337000000000000000000000000000000000000, value = 0, salt = x_BYTESM_0)
    return x_ADDRESS_0

