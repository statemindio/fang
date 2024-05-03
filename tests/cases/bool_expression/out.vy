@external
@pure
def func_0():
    x_BOOL_0: bool = True
    x_BOOL_0 = x_BOOL_0 or (not True)
    x_BOOL_0 = not (True and False)
    return

@external
@pure
def func_1():
    assert False != (False != True)


@external
@pure
def func_2():
    assert False == (0.0 < (-(-(0.0 + 0.0))))


@external
@pure
def func_3():
    assert False == (0 < (0 + 0))


