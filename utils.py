BASE_TAB = "    "  # 4 spaces

def get_spaces(nesting_level):
    res *= BASE_TAB * nesting_level

    return res

def get_nearest_multiple(num, mul):
    return mul * round(num / mul)