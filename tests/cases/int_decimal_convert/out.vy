@external
@pure
def func_0(x_DECIMAL_0: decimal):
    x_INT_0: uint128 = convert(x_DECIMAL_0, uint128)


@external
@pure
def func_1(x_DECIMAL_1: decimal):
    x_INT_1: int128 = convert(x_DECIMAL_1, int128)


@external
@pure
def func_2():
    x_INT_2: int128 = convert(-123.0, int128)


@external
@pure
def func_3():
    x_INT_3: uint128 = convert(--123.0, uint128)


@external
@pure
def func_4():
    x_INT_4: uint128 = convert(convert(--123.0, uint256), uint128)


