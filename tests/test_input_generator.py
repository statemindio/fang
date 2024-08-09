import json
from decimal import Decimal

import pytest

from input_generation import InputGenerator, InputStrategy
from runners.simple_runner import handle_compilation
from types_d import types as t
from json_encoders import ExtendedEncoder, ExtendedDecoder

data = [
    ([t.Int()], [84747631942840761409198475171043116002924132430274400095798688737583350222083]),
    ([t.String(30), t.Bytes(10)], ['JTWuNw9yRV1wAN3FP3zTtbvhpk0Q5L', b'\xf6_y\x9au\x9d\xcdC\xd2\xcd']),
    ([t.Decimal()], [Decimal('6258789235018001536341366667573813313536')]),
    (
        [t.FixedList(1, t.Address()), t.String(100)],
        [
            ['0xd30a286Ec6737B8b2A6a7B5fBb5d75b895f628F2'],
            'Nw9yRV1wAN3FP3zTtbvhpk0Q5LLXHN88Ve73dbmgmU9Ja6uJoc8Tt3LlGlPURK8bGHO5TXNqR64teBHpdjvS4cr8dCxmONqniyAp'
        ]
    )
]

data_zeros = [
    ([t.Int()], [0]),
    ([t.String(30), t.Bytes(10)], ['', b'']),
    ([t.Decimal()], [Decimal('0.0')]),
    (
        [t.FixedList(1, t.Address()), t.String(100)],
        [
            ['0x0000000000000000000000000000000000000000'],
            ''
        ]
    )
]


@pytest.mark.parametrize("types, expected", data)
def test_input_generator_default(types, expected):
    import random
    random.seed(1337)

    igen = InputGenerator(InputStrategy.DEFAULT)
    generated_value = igen.generate(types)
    assert generated_value == expected


@pytest.mark.parametrize("types, expected", data_zeros)
def test_input_generator_zero(types, expected):
    igen = InputGenerator(InputStrategy.ZEROS)
    generated_value = igen.generate(types)
    assert generated_value == expected


def test_handle_compilation():
    igen = InputGenerator(InputStrategy.DEFAULT)
    compilation = """
  {
    "_id": {"$oid": "669ff18a0ee20d835e7a0ebf"},
    "abi": [
      {
        "stateMutability": "nonpayable",
        "type": "constructor",
        "inputs": [
          {
            "name": "x_BYTES_0",
            "type": "bytes"
          }
        ],
        "outputs": []
      },
      {
        "stateMutability": "pure",
        "type": "function",
        "name": "func_0",
        "inputs": [],
        "outputs": []
      }
    ],
    "bytecode": "0x3461004857602061007c5f395f51600160208261007c015f395f511161004857602060208261007c015f395f5101808261007c01604039505061001e61004c60623961001e6062f35b5f80fd5f3560e01c6329b9c7e48118610016573461001a57005b5f5ffd5b5f80fd84181e8000a16576797065728300030a0012",
    "generation_id": "669ff18aa9c64fcd85e18039",
    "ran": false
  }"""
    input_types = {'__init__': [t.Bytes(1)], 'func_0': []}
    input_values = {}
    for name, types in input_types.items():
        input_values[name] = igen.generate(types)
    input_values = json.dumps(input_values, cls=ExtendedEncoder)

    compilation_obj = json.loads(compilation)
    compilation_obj['function_input_values'] = input_values

    compilation_result = handle_compilation(compilation_obj)
    assert compilation_result == [
        {'state': ['0', '0', '0', '0', '0', '0', '0', '0', '0', '0'], 'memory': '', 'consumed_gas': 48,
         'return_value': 'None'}]


json_data = [
    ([t.Bytes(1), t.Bytes(10), t.Bytes(32)], 'bytes', lambda x: x.hex()),
    ([t.Decimal(), t.Decimal(), t.Decimal()], 'Decimal', str),
]


@pytest.mark.parametrize("types, type_name, fn", json_data)
def test_extended_json(types, type_name, fn):
    igen = InputGenerator(InputStrategy.DEFAULT)

    generated_value = igen.generate(types)

    for i in range(len(types)):
        enc = json.dumps(generated_value[i], cls=ExtendedEncoder)
        assert enc == '{"_type": "%s", "value": "%s"}' % (type_name, fn(generated_value[i]))
        dec = json.loads(enc, cls=ExtendedDecoder)
        assert dec == generated_value[i]
