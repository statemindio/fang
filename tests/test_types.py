import pytest

from types_d import BytesM, String, TypeRangeError

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
