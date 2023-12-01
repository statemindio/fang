import pytest

from types_d import BytesM, String, Int, TypeRangeError, Bytes, Bool, Decimal, Address

data = [
    [i, f"bytes{i}"] for i in range(1, 33)
]


@pytest.mark.parametrize("m,vyper_type", data)
def test_bytes_m_type(m, vyper_type):
    bt = BytesM(m)
    assert bt.m == m
    assert bt.vyper_type == vyper_type


def test_bytes_m_eq():
    bt = BytesM(8)
    bt1 = BytesM(8)
    bt2 = BytesM(9)
    st = String(8)

    assert bt == bt1
    assert bt != bt2
    assert bt != st


def test_bytes_m_boundaries():
    with pytest.raises(TypeRangeError):
        bt = BytesM(33)
    with pytest.raises(TypeRangeError):
        bt = BytesM(0)


int_data = [[2 ** i, s, f"int{2 ** i}" if s else f"uint{2 ** i}"] for i in range(3, 9) for s in (True, False)]


@pytest.mark.parametrize("n,signed,vyper_type", int_data)
def test_int_type(n, signed, vyper_type):
    it = Int(n, signed)
    assert it.vyper_type == vyper_type
    assert str(it) == vyper_type


def test_int_boundaries():
    with pytest.raises(TypeRangeError):
        it = Int(3)
    with pytest.raises(TypeRangeError):
        it = Int(10)


def test_int_eq():
    it = Int(8, True)
    it1 = Int(8, True)
    assert it == it1

    it2 = Int(8, False)
    assert it != it2

    it3 = Int(16, True)
    it4 = Int(16, False)
    it5 = Int(16, False)
    assert it != it3
    assert it3 != it4
    assert it4 == it5


bytes_array_data = [
    [m, f"Bytes[{m}]"] for m in range(80, 110, 4)
]


@pytest.mark.parametrize("m,vyper_type", bytes_array_data)
def test_bytes_array_type(m, vyper_type):
    bt = Bytes(m)
    assert bt.vyper_type == vyper_type
    assert str(bt) == vyper_type


def test_bytes_array_eq():
    bt = Bytes(8)
    bt1 = Bytes(8)
    bt2 = Bytes(9)
    st = String(8)

    assert bt == bt1
    assert bt != bt2
    assert bt != st


def test_bool_type():
    b = Bool()
    assert b.vyper_type == "bool"
    assert str(b) == "bool"


def test_decimal_type():
    d = Decimal()
    assert d.vyper_type == "decimal"
    assert str(d) == "decimal"


def test_address_type():
    a = Address()
    assert a.vyper_type == "address"
    assert str(a) == "address"
