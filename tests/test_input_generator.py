from decimal import Decimal

import pytest

from runners.input_generation import InputGenerator, InputStrategy
from types_d import types as t

data = [
    ([t.Int()], [84747631942840761409198475171043116002924132430274400095798688737583350222083]),
    ([t.String(30), t.Bytes(10)], ['"JTWuNw9yRV1wAN3FP3zTtbvhpk0Q5L"', b'2p\t\x802']),
    ([t.Decimal()], [Decimal('6258789235018001536341366667573813313536')])
]


@pytest.mark.parametrize("types, expected", data)
def test_input_generator_default_int(types, expected):
    import random
    random.seed(1337)

    igen = InputGenerator(InputStrategy.DEFAULT)
    generated_value = igen.generate(types)
    assert generated_value == expected
