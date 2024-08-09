import pytest

from types_d import Int, Decimal, FixedList, DynArray, Bytes
from var_tracker import VarTracker
from config import MAX_LIST_SIZE


@pytest.fixture
def var_tracker():
    return VarTracker()


def test_var_tracker_add_function_variable(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 1, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    assert var_tracker.get_mutable_variables(1, var_type) == ["foo0", "foo1"]
    assert var_tracker.get_mutable_variables(2, var_type) == ["foo0", "foo1"]
    assert var_tracker.get_mutable_variables(3, var_type) == ["foo0", "foo1", "foo2"]


def test_var_tracker_add_function_variable_and_list(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 1, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    list_type = FixedList(2, var_type)
    var_tracker.register_function_variable("baz0", 1, list_type, mutable)
    var_tracker.register_function_variable("baz1", 1, list_type, mutable)
    var_tracker.register_function_variable("baz2", 3, list_type, mutable)

    assert var_tracker.get_mutable_variables(1, var_type) == ["foo0", "foo1", "baz0[0]", "baz0[1]",
                                                             "baz1[0]", "baz1[1]"]
    assert var_tracker.get_mutable_variables(2, var_type) == ["foo0", "foo1", "baz0[0]", "baz0[1]",
                                                             "baz1[0]", "baz1[1]"]
    assert var_tracker.get_mutable_variables(3, var_type) == ["foo0", "foo1", "foo2",
                                                             "baz0[0]", "baz0[1]", "baz1[0]",
                                                             "baz1[1]", "baz2[0]", "baz2[1]"]


def test_var_tracker_add_function_variable_and_dynamic_array(var_tracker):
    var_type = Int()
    mutable = True

    list_type_0 = DynArray(2, var_type)
    list_type_1 = DynArray(3, var_type)
    list_type_2 = DynArray(4, var_type)
    list_type_3 = DynArray(4, var_type)
    list_type_4 = DynArray(3, var_type)
    list_type_5 = DynArray(2, var_type)

    # alias of register_function_variable(name, 0, type, True)
    var_tracker.register_global_variable("bar0", list_type_0)
    var_tracker.register_global_variable("bar1", list_type_1)
    var_tracker.register_global_variable("bar2", list_type_2)

    var_tracker.register_function_variable("foo0", 1, list_type_3, mutable)
    var_tracker.register_function_variable("foo1", 3, list_type_4, mutable)
    var_tracker.register_function_variable("foo2", 4, list_type_5, mutable)

    list_type_dec = DynArray(2, Decimal())
    all_types = DynArray(MAX_LIST_SIZE, None)

    var_tracker.register_function_variable("baz0", 2, list_type_dec, mutable)

    assert var_tracker.get_mutable_variables(3, list_type_4) == ["self.bar0", "self.bar1", "foo1"]
    assert var_tracker.get_mutable_variables(3, all_types) == ["self.bar0", "self.bar1", "self.bar2", "foo0", "foo1",
                                                              "baz0"]
    assert var_tracker.get_dyn_array_base_type("baz0", mutable) == Decimal()


def test_var_tracker_add_function_variable_and_dynamic_array_list(var_tracker):
    var_type = Int()
    mutable = True
    list_type = FixedList(2, var_type)

    list_type_0 = DynArray(2, list_type, 1)
    list_type_1 = DynArray(3, list_type, 2)
    list_type_2 = DynArray(2, list_type, 1)
    list_type_3 = DynArray(3, list_type, 1)

    var_tracker.register_global_variable("bar0", list_type_0)
    var_tracker.register_global_variable("bar1", list_type_1)

    var_tracker.register_function_variable("foo0", 2, list_type_2, mutable)
    var_tracker.register_function_variable("foo1", 3, list_type_3, mutable)

    list_type_dec = DynArray(2, FixedList(1, Decimal()))

    var_tracker.register_function_variable("baz0", 2, list_type_dec, mutable)

    assert var_tracker.get_mutable_variables(1, var_type) == ["self.bar0[0][0]", "self.bar0[0][1]", "self.bar1[0][0]",
                                                             "self.bar1[0][1]", "self.bar1[1][0]", "self.bar1[1][1]"]
    assert var_tracker.get_mutable_variables(2, var_type) == ["self.bar0[0][0]", "self.bar0[0][1]", "self.bar1[0][0]",
                                                             "self.bar1[0][1]", "self.bar1[1][0]", "self.bar1[1][1]",
                                                             "foo0[0][0]", "foo0[0][1]"]


def test_var_tracker_add_global_and_function_variables(var_tracker):
    var_type = Int()
    mutable = True
    var_tracker.register_global_variable("g_bar0", var_type)
    var_tracker.register_global_variable("g_bar2", var_type)
    var_tracker.register_global_variable("g_bar1", var_type)

    var_tracker.register_function_variable("foo0", 1, var_type, mutable)
    var_tracker.register_function_variable("foo1", 1, var_type, mutable)
    var_tracker.register_function_variable("foo2", 3, var_type, mutable)

    assert var_tracker.get_global_vars(var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1"]
    assert var_tracker.get_mutable_variables(0, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1"]
    assert var_tracker.get_mutable_variables(4, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "foo0",
                                                             "foo1", "foo2"]


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
    var_tracker.register_function_variable("qux1", 1, list_type, mutable)
    var_tracker.register_function_variable("qux2", 3, list_type, mutable)

    assert var_tracker.get_global_vars(list_type) == ["self.g_baz0", "self.g_baz1"]
    assert var_tracker.get_mutable_variables(1, list_type) == ["self.g_baz0", "self.g_baz1", "qux0", "qux1"]
    assert var_tracker.get_mutable_variables(4, list_type) == ["self.g_baz0", "self.g_baz1", "qux0", "qux1", "qux2"]

    assert var_tracker.get_global_vars(var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "self.foo1",
                                                     "self.g_baz0[0]", "self.g_baz0[1]",
                                                     "self.g_baz1[0]", "self.g_baz1[1]"]

    assert var_tracker.get_mutable_variables(1, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "self.foo1",
                                                             "foo0", "self.g_baz0[0]", "self.g_baz0[1]",
                                                             "self.g_baz1[0]", "self.g_baz1[1]",
                                                             "qux0[0]", "qux0[1]", "qux1[0]", "qux1[1]"]
    assert var_tracker.get_mutable_variables(4, var_type) == ["self.g_bar0", "self.g_bar2", "self.g_bar1", "self.foo1",
                                                             "foo0", "foo2", "self.g_baz0[0]", "self.g_baz0[1]",
                                                             "self.g_baz1[0]", "self.g_baz1[1]",
                                                             "qux0[0]", "qux0[1]", "qux1[0]", "qux1[1]",
                                                             "qux2[0]", "qux2[1]"]


def test_var_tracker_add_different_types(var_tracker):
    var_type_uint256 = Int()
    var_type_int128 = Int(128, True)
    var_type_decimal = Decimal()
    mutable = True

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_function_variable("foo_uint256_0", 1, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_1", 1, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_2", 3, var_type_uint256, mutable)

    var_tracker.register_global_variable("g_bar_int128", var_type_int128)
    var_tracker.register_function_variable("foo_int128_0", 1, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_1", 1, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_2", 3, var_type_int128, mutable)

    var_tracker.register_global_variable("g_bar_decimal", var_type_decimal)
    var_tracker.register_function_variable("foo_decimal_0", 1, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_1", 1, var_type_decimal, mutable)
    var_tracker.register_function_variable("foo_decimal_2", 3, var_type_decimal, mutable)

    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]
    assert var_tracker.get_mutable_variables(3, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1", "foo_uint256_2"]

    assert var_tracker.get_global_vars(var_type_int128) == ["self.g_bar_int128"]
    assert var_tracker.get_mutable_variables(2, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1"]
    assert var_tracker.get_mutable_variables(3, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1", "foo_int128_2"]

    assert var_tracker.get_global_vars(var_type_decimal) == ["self.g_bar_decimal"]
    assert var_tracker.get_mutable_variables(2, var_type_decimal) == ["self.g_bar_decimal", "foo_decimal_0",
                                                                     "foo_decimal_1"]
    assert var_tracker.get_mutable_variables(3, var_type_decimal) == ["self.g_bar_decimal", "foo_decimal_0",
                                                                     "foo_decimal_1", "foo_decimal_2"]


def test_var_tracker_remove_level(var_tracker):
    var_type_uint256 = Int()
    var_type_int128 = Int(128, True)
    mutable = True

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_function_variable("foo_uint256_0", 1, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_1", 1, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_uint256_2", 3, var_type_uint256, mutable)

    var_tracker.register_global_variable("g_bar_int128", var_type_int128)
    var_tracker.register_function_variable("foo_int128_0", 1, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_1", 1, var_type_int128, mutable)
    var_tracker.register_function_variable("foo_int128_2", 3, var_type_int128, mutable)

    var_tracker.remove_function_level(3, True)
    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]
    assert var_tracker.get_mutable_variables(3, var_type_uint256) == ["self.g_bar_uint256", "foo_uint256_0",
                                                                     "foo_uint256_1"]

    assert var_tracker.get_global_vars(var_type_int128) == ["self.g_bar_int128"]
    assert var_tracker.get_mutable_variables(2, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
                                                                    "foo_int128_1"]
    assert var_tracker.get_mutable_variables(3, var_type_int128) == ["self.g_bar_int128", "foo_int128_0",
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


def test_var_reset_function_variables(var_tracker):
    var_type_uint256 = Int()
    var_type_bytes10 = Bytes(10)
    var_type_uint256_da = DynArray(2, var_type_uint256)
    mutable = True

    var_tracker.register_global_variable("g_bar_uint256", var_type_uint256)
    var_tracker.register_global_variable("g_bar_bytes10", var_type_bytes10)
    var_tracker.register_global_variable("g_bar_uint256_da", var_type_uint256_da)
    var_tracker.register_function_variable("foo_uint256_0", 1, var_type_uint256, mutable)
    var_tracker.register_function_variable("foo_bytes10_1", 1, var_type_bytes10, mutable)
    var_tracker.register_function_variable("foo_uint256_da", 1, var_type_uint256_da, mutable)

    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256",
                                                             "self.g_bar_uint256_da[0]",
                                                             "self.g_bar_uint256_da[1]"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256) == ["self.g_bar_uint256",
                                                                      "foo_uint256_0", 
                                                                      "self.g_bar_uint256_da[0]", 
                                                                      "self.g_bar_uint256_da[1]",
                                                                      "foo_uint256_da[0]",
                                                                      "foo_uint256_da[1]"]

    assert var_tracker.get_global_vars(var_type_bytes10) == ["self.g_bar_bytes10"]
    assert var_tracker.get_mutable_variables(2, var_type_bytes10) == ["self.g_bar_bytes10",
                                                                      "foo_bytes10_1"]

    assert var_tracker.get_global_vars(var_type_uint256_da) == ["self.g_bar_uint256_da"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256_da) == ["self.g_bar_uint256_da",
                                                                         "foo_uint256_da"]

    var_tracker.reset_function_variables()

    assert var_tracker.get_global_vars(var_type_uint256) == ["self.g_bar_uint256",
                                                             "self.g_bar_uint256_da[0]", 
                                                             "self.g_bar_uint256_da[1]"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256) == ["self.g_bar_uint256",
                                                                      "self.g_bar_uint256_da[0]", 
                                                                      "self.g_bar_uint256_da[1]"]

    assert var_tracker.get_global_vars(var_type_bytes10) == ["self.g_bar_bytes10"]
    assert var_tracker.get_mutable_variables(2, var_type_bytes10) == ["self.g_bar_bytes10"]

    assert var_tracker.get_global_vars(var_type_uint256_da) == ["self.g_bar_uint256_da"]
    assert var_tracker.get_mutable_variables(2, var_type_uint256_da) == ["self.g_bar_uint256_da"]
