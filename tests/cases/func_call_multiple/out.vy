x_INT_0 : uint8
x_BYTES_0 : Bytes[382]
x_BYTES_1 : Bytes[382]

@external
@nonpayable
def func_0(x_INT_1: uint8) -> (uint8, decimal):
    self.x_INT_0 = 0
    return 0,0.0

@external
@nonpayable
def func_1(x_INT_2: uint8):
    x_DECIMAL_0 : decimal = empty(decimal)
    self.x_INT_0, x_DECIMAL_0 = self.func_0(0)


