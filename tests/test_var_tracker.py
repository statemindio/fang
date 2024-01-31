import pytest

from types_d import Int, Decimal, FixedList, DynArray
from var_tracker import VarTracker


@pytest.fixture
def var_tracker():
    return VarTracker()


def test_var_tracker_add_function_variable(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 0, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    assert var_tracker.get_all_allowed_vars(1, var_type) == ["foo1", "foo0"]
    assert var_tracker.get_all_allowed_vars(2, var_type) == ["foo1", "foo0"]
    assert var_tracker.get_all_allowed_vars(3, var_type) == ["foo1", "foo0", "foo2"]

def test_var_tracker_add_function_variable_and_list(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 0, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    list_type = FixedList(2, var_type)
    var_tracker.register_function_variable("baz0", 1, list_type, mutable)
    var_tracker.register_function_variable("baz1", 0, list_type, mutable)
    var_tracker.register_function_variable("baz2", 3, list_type, mutable)

    assert var_tracker.get_all_allowed_vars(1, var_type) == ["foo1", "foo0", "baz1[0]", "baz1[1]",
                                                             "baz0[0]", "baz0[1]"]
    assert var_tracker.get_all_allowed_vars(2, var_type) == ["foo1", "foo0", "baz1[0]", "baz1[1]",
                                                             "baz0[0]", "baz0[1]"]
    assert var_tracker.get_all_allowed_vars(3, var_type) == ["foo1", "foo0", "foo2",
                                                             "baz1[0]", "baz1[1]", "baz0[0]",
                                                             "baz0[1]",  "baz2[0]", "baz2[1]"]

def test_var_tracker_add_function_variable_and_dynamic_array(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 0, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    list_type = DynArray(2, var_type)
    var_tracker.register_function_variable("baz0", 1, list_type, mutable)
    var_tracker.register_function_variable("baz1", 0, list_type, mutable)
    var_tracker.register_function_variable("baz2", 3, list_type, mutable)

    assert var_tracker.get_all_allowed_vars(1, var_type) == ["foo1", "foo0", "baz1[0]", "baz1[1]",
                                                             "baz0[0]", "baz0[1]"]
    assert var_tracker.get_all_allowed_vars(2, var_type) == ["foo1", "foo0", "baz1[0]", "baz1[1]",
                                                             "baz0[0]", "baz0[1]"]
    assert var_tracker.get_all_allowed_vars(3, var_type) == ["foo1", "foo0", "foo2",
                                                             "baz1[0]", "baz1[1]", "baz0[0]",
                                                             "baz0[1]",  "baz2[0]", "baz2[1]"]

def test_var_tracker_add_global_and_function_variables(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_global_variable("g_bar0", var_type)
    var_tracker.register_global_variable("g_bar2", var_type)
    var_tracker.register_global_variable("g_bar1", var_type)

    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 0, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    assert var_tracker.get_global_vars(var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1"]
    assert var_tracker.get_all_allowed_vars(0, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "foo1"]
    assert var_tracker.get_all_allowed_vars(4, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "foo1",
                                                             "foo0", "foo2"]


def test_var_tracker_add_global_and_function_variables_and_list(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_global_variable("g_bar0", var_type)
    var_tracker.register_global_variable("g_bar2", var_type)
    var_tracker.register_global_variable("g_bar1", var_type)

    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 0, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    list_type = FixedList(2, var_type)
    var_tracker.register_global_variable("g_baz0", list_type)
    var_tracker.register_global_variable("g_baz1", list_type)

    var_tracker.register_function_variable("qux0", 1, list_type, mutable)
    var_tracker.register_function_variable("qux1", 0, list_type, mutable)
    var_tracker.register_function_variable("qux2", 3, list_type, mutable)

    assert var_tracker.get_global_vars(var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1",
                                                     "self.g_baz0[0]", "self.g_baz0[1]",
                                                     "self.g_baz1[0]", "self.g_baz1[1]"]
    assert var_tracker.get_all_allowed_vars(0, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1",
                                                             "self.g_baz0[0]", "self.g_baz0[1]",
                                                             "self.g_baz1[0]", "self.g_baz1[1]",
                                                             "foo1", "qux1[0]", "qux1[1]"]
    assert var_tracker.get_all_allowed_vars(4, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1",
                                                             "self.g_baz0[0]", "self.g_baz0[1]",
                                                             "self.g_baz1[0]", "self.g_baz1[1]",
                                                             "foo1", "foo0", "foo2", "qux1[0]", "qux1[1]",
                                                             "qux0[0]", "qux0[1]", "qux2[0]", "qux2[1]"]


def test_var_tracker_add_different_types(var_tracker):
    var_type_uint256 = Int()
    var_type_int128 = Int(128, True)
    var_type_decimal = Decimal()
    mutable = True

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_function_variable("foo_uint256_0", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_1", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_2", 3, var_type_uint256, mutable)

    var_tracker.register_global_variable("g_bar_int128", var_type_int128)
    var_tracker.register_function_variable("foo_int128_0", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_1", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_2", 3, var_type_int128, mutable)

    var_tracker.register_global_variable("g_bar_decimal", var_type_decimal)
    var_tracker.register_function_variable("foo_decimal_0", 0, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_1", 0, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_2", 3, var_type_decimal, mutable)

    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256"]
    assert var_tracker.get_all_allowed_vars(2, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]
    assert var_tracker.get_all_allowed_vars(3, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1", "foo_uint256_2"]

    assert var_tracker.get_global_vars(var_type_int128) == ["self.g_bar_int128"]
    assert var_tracker.get_all_allowed_vars(2, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1"]
    assert var_tracker.get_all_allowed_vars(3, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1", "foo_int128_2"]

    assert var_tracker.get_global_vars(var_type_decimal) == ["self.g_bar_decimal"]
    assert var_tracker.get_all_allowed_vars(2, var_type_decimal) == ["self.g_bar_decimal", "foo_decimal_0",
                                                                     "foo_decimal_1"]
    assert var_tracker.get_all_allowed_vars(3, var_type_decimal) == ["self.g_bar_decimal", "foo_decimal_0",
                                                                     "foo_decimal_1", "foo_decimal_2"]


def test_var_tracker_remove_level(var_tracker):
    var_type_uint256 = Int()
    var_type_int128 = Int(128, True)
    mutable = True

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_function_variable("foo_uint256_0", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_1", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_2", 3, var_type_uint256, mutable)

    var_tracker.register_global_variable("g_bar_int128", var_type_int128)
    var_tracker.register_function_variable("foo_int128_0", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_1", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_2", 3, var_type_int128, mutable)

    var_tracker.remove_function_level(3, True)
    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256"]
    assert var_tracker.get_all_allowed_vars(2, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]
    assert var_tracker.get_all_allowed_vars(3, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]

    assert var_tracker.get_global_vars(var_type_int128) == ["self.g_bar_int128"]
    assert var_tracker.get_all_allowed_vars(2, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1"]
    assert var_tracker.get_all_allowed_vars(3, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1"]


def test_var_tracker_index(var_tracker):
    var_type_uint256 = Int()
    var_type_int128 = Int(128, True)
    var_type_decimal = Decimal()
    mutable = True
    
    assert var_tracker.current_id(var_type_uint256) == -1
    assert var_tracker.next_id(var_type_uint256) == 0

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_function_variable("foo_uint256_0", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_1", 0, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_2", 3, var_type_uint256, mutable)

    var_tracker.register_global_variable("g_bar_int128", var_type_int128)
    var_tracker.register_function_variable("foo_int128_0", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_1", 0, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_2", 3, var_type_int128, mutable)

    var_tracker.register_global_variable("g_bar_decimal", var_type_decimal)
    var_tracker.register_function_variable("foo_decimal_0", 0, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_1", 0, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_2", 3, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_3", 3, var_type_decimal, mutable)

    assert var_tracker.current_id(var_type_uint256) == 7
    assert var_tracker.next_id(var_type_uint256) == 8
    assert var_tracker.current_id(var_type_int128) == 7
    assert var_tracker.next_id(var_type_int128) == 8
    assert var_tracker.current_id(var_type_decimal) == 4
    assert var_tracker.next_id(var_type_decimal) == 5
