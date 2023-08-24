import math
BASE_TAB = "    "  # 4 spaces

def get_spaces(nesting_level):
    return BASE_TAB * nesting_level

def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul) # round returns 0