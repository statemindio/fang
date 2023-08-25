import random

from data_types import Type


BASE_TAB = "    "  # 4 spaces

def get_spaces(nesting_level):
    res *= BASE_TAB * nesting_level

    return res

def get_nearest_multiple(num, mul):
    return mul * round(num / mul)

# THIS IMLEMENTATION USES RANDOM VALUES
# IF NEEDED DIFFERENT DICTIONARIES FOR DIFFERENT TYPE COULD BE CREATED
def get_random_token(type: Type):
    if type == Type.INT:
        return random.randint(0, 2**256 - 1)  # returns only positive values, not very good for ints. Maybe return hex ?
    elif type == Type.BOOL:
        return bool(random.getrandbits(1))
    
def get_random_element(arr):
    return random.choice(arr)
