x_INT_0: uint8

@external
@nonreentrant("test")
@nonpayable
def func_0() -> decimal:
    selfdestruct(0x0000000000000000000000000000000000000000)

@external
@nonreentrant("tes1t2")
@nonpayable
def func_1():
    selfdestruct(0x0000000000000000000000000000000000000000)

