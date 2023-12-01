import pytest

from types_d import BytesM, String, Int, TypeRangeError

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
