import json

from config import Config
from verifiers.simple_verifier import reshape_data, verify_results, verify_two_results

data = """
    {
    "_id": {"$oid": "66b178d8b7f5f3dfa365a9e1"},
    "generation_id": "66b178d8b7f5f3dfa365a9e0",
    "result_0_3_10_opt_codesize": [
      {
        "func_0": [
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 48,
            "return_value": "null"
          },
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 48,
            "return_value": "null"
          }
        ],
        "__default__": [
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 49,
            "return_value": "null"
          }
        ]
      }
    ],
    "result_0_3_10_opt_gas": [
      {
        "func_0": [
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 48,
            "return_value": "null"
          },
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 48,
            "return_value": "null"
          }
        ],
        "__default__": [
          {
            "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "memory": "",
            "consumed_gas": 49,
            "return_value": "null"
          }
        ]
      }
    ]
  }"""
expected = {
    "func_0": [
        [
            [
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 48,
                    "return_value": "null"
                },
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 48,
                    "return_value": "null"
                }
            ],
            [
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 48,
                    "return_value": "null"
                },
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 48,
                    "return_value": "null"
                }
            ]
        ]
    ],
    "__default__": [
        [
            [
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 49,
                    "return_value": "null"
                },
                {
                    "state": [
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0",
                        "0"
                    ],
                    "memory": "",
                    "consumed_gas": 49,
                    "return_value": "null"
                }
            ]
        ]
    ]
}

conf = Config()  # TODO: create MockConfig


def test_reshape_data():
    data_dict = json.loads(data)
    reshaped = reshape_data(conf, data_dict)

    print(reshaped)
    assert reshaped == expected


def test_verify_two_result():
    res0 = {
        "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        "memory": "",
        "consumed_gas": 48,
        "return_value": "null"
    }
    res1 = {
        "state": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        "memory": "",
        "consumed_gas": 48,
        "return_value": "null"
    }
    expected_res = {
        'Gas': None,
        'Memory': None,
        'Return_Value': None,
        'Storage': None
    }
    r = verify_two_results(res0, res1)
    assert r == expected_res


def test_verify_results():
    from pprint import pprint
    data_dict = json.loads(data)
    expected_res = [{'compilers': ('result_0_3_10_opt_gas', 'result_0_3_10_opt_codesize'),
                     'deployment': 0,
                     'function': 'func_0',
                     'params_set': 0,
                     'results': {'Gas': None,
                                 'Memory': None,
                                 'Return_Value': None,
                                 'Storage': None}},
                    {'compilers': ('result_0_3_10_opt_gas', 'result_0_3_10_opt_codesize'),
                     'deployment': 0,
                     'function': 'func_0',
                     'params_set': 1,
                     'results': {'Gas': None,
                                 'Memory': None,
                                 'Return_Value': None,
                                 'Storage': None}},
                    {'compilers': ('result_0_3_10_opt_gas', 'result_0_3_10_opt_codesize'),
                     'deployment': 0,
                     'function': '__default__',
                     'params_set': 0,
                     'results': {'Gas': None,
                                 'Memory': None,
                                 'Return_Value': None,
                                 'Storage': None}}]
    reshaped = reshape_data(conf, data_dict)
    r = verify_results(conf, reshaped)
    pprint(r)
    assert expected_res == r
