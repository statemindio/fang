import pytest

from func_tracker import FuncTracker
from vyperProtoNew_pb2 import Func


@pytest.fixture
def func_tracker():
    return FuncTracker()


def test_func_tracker_register(func_tracker):
    name = "test0"
    mutability = Func.Mutability.PURE
    visibility = Func.Visibility.EXTERNAL
    input_parameters = []
    output_parameters = []
    func_tracker.register_function(name, mutability, visibility, input_parameters, output_parameters)

    assert func_tracker.current_id == 0
    assert func_tracker[0].name == name
    assert func_tracker[0].mutability == 0
