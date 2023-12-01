import pytest

from types_d import BytesM, String, TypeRangeError

def test_bytes_m_type():
    bt = BytesM()
    assert bt.m == 32
    assert bt.vyper_type == "bytes32"


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
