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

@external
@nonpayable
def func_2():
    selfdestruct(0x0000000000000000000000000000000000000000)

@external
@nonpayable
def func_3():
    selfdestruct(0x0000000000000000000000000000000000000000)

@external
@nonreentrant("return123")
@nonpayable
def func_4():
    selfdestruct(0x0000000000000000000000000000000000000000)

