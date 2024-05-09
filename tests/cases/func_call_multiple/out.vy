IM_DECIMAL_0: immutable(decimal)
x_INT_0: uint8
x_BYTES_0: Bytes[382]
x_BYTES_1: Bytes[382]

@external
def __init__():
    IM_DECIMAL_0 = 0.0
    return

@internal
@nonpayable
def func_0(x_INT_1: uint8) -> (uint8, decimal):
    self.x_INT_0 = 0
    return 0,0.0

@external
@nonpayable
def func_1(x_INT_2: uint8):
    x_INT_3: uint8 = empty(uint8)
    x_DECIMAL_1: decimal = empty(decimal)
    x_INT_3, x_DECIMAL_1 = self.func_0(0)


