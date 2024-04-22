x_INT_0: uint8

@external
@nonreentrant("test")
@nonpayable
def __default__() -> (bool, uint8):
    self.x_INT_0 = 5
    return False,0

