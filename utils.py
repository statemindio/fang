import os
import random
import string
import math
from data_types import Type

BASE_TAB = "    "  # 4 spaces


def get_spaces(nesting_level):
    return BASE_TAB * nesting_level


def get_nearest_multiple(num, mul):
    return mul * math.ceil(num / mul)  # round returns 0

# THIS IMLEMENTATION USES RANDOM VALUES
# IF NEEDED DIFFERENT DICTIONARIES FOR DIFFERENT TYPE COULD BE CREATED


def get_random_token(type: Type):
    if type == Type.INT:
        # returns only positive values, not very good for ints. Hex not working 
        return random.randint(0, 2**256 - 1)
    elif type == Type.BOOL:
        return bool(random.getrandbits(1))
    elif type == Type.DECIMAL:
        return random.randint(0, 2**168 - 1) / 10**10 
    elif type == Type.BytesM:
        return "0x" + os.urandom(32).hex()
    elif type == Type.STRING:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=10000))


def get_random_element(arr):
    return random.choice(arr)