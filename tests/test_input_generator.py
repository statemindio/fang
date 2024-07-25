import json
from decimal import Decimal

import pytest

from input_generation import InputGenerator, InputStrategy
from runners.simple_runner import handle_compilation
from types_d import types as t

data = [
    ([t.Int()], [84747631942840761409198475171043116002924132430274400095798688737583350222083]),
    ([t.String(30), t.Bytes(10)], ['"JTWuNw9yRV1wAN3FP3zTtbvhpk0Q5L"', b'2p\t\x802']),
    ([t.Decimal()], [Decimal('6258789235018001536341366667573813313536')]),
    (
        [t.FixedList(1, t.Address()), t.String(100)],
        [
            ['0xd30a286Ec6737B8b2A6a7B5fBb5d75b895f628F2'],
            '"Nw9yRV1wAN3FP3zTtbvhpk0Q5LLXHN88Ve73dbmgmU9Ja6uJoc8Tt3LlGlPURK8bGHO5TXNqR64teBHpdjvS4cr8dCxmONqniyAp"'
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
    "function_input_types": "800495d8000000000000007d94288c085f5f696e69745f5f945d948c0d74797065735f642e7479706573948c0542797465739493942981947d94288c025f6d944b018c105f76616c75655f67656e657261746f72948c1774797065735f642e76616c75655f67656e657261746f72948c0e427974657352616e646f6d47656e9493942981948c125f6c69746572616c5f67656e657261746f72948c1f74797065735f642e6c69746572616c5f76616c75655f67656e657261746f72948c0f42797465734c69746572616c47656e9493942981947562618c0666756e635f30945d94752e",
    "generation_id": "669ff18aa9c64fcd85e18039",
    "ran": false
  }"""

    compilation_obj = json.loads(compilation)

    compilation_result = handle_compilation(compilation_obj, igen)
    assert compilation_result == [
        {'state': ['0', '0', '0', '0', '0', '0', '0', '0', '0', '0'], 'memory': '', 'consumed_gas': 48,
         'return_value': 'null'}]
