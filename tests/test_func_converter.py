import os

from google.protobuf.json_format import Parse

import fuzz.helpers.proto_loader as proto
from fuzz.converters.function_converter import FunctionConverter
from fuzz.converters.typed_converters import TypedConverter


def test__find_func():
    current_dir = os.path.dirname(__file__)
    with open(f"{current_dir}/cases/func_call_multiple_cyclic_deep/in.json", "r") as inp_json:
        json_message = inp_json.read()
    mes = Parse(json_message, proto.Contract())
    typed_converter = TypedConverter(mes)
    func_conv = FunctionConverter(typed_converter._func_tracker)
    typed_converter._func_tracker.register_functions(mes.functions)
    order = func_conv.setup_order(mes.functions)

    assert func_conv._call_tree == {0: [1], 1: [], 2: [1]}
    assert order == [1, 0, 2]
