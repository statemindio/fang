@external
@pure
def func_0(x_DECIMAL_0: decimal):
    x_BOOL_0: bool = convert(x_DECIMAL_0, bool)


@external
@pure
def func_1(x_DECIMAL_1: decimal):
    x_BOOL_1: bool = convert(x_DECIMAL_1, bool)


@external
@pure
def func_2():
    x_BOOL_2: bool = convert(-123.0, bool)


@external
@pure
def func_3():
    x_BOOL_3: bool = convert(-123.0, bool)


@external
@pure
def func_4():
    x_BOOL_4: bool = convert(convert(--123.0, uint256), bool)


