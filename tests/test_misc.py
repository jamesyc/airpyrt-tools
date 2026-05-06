import pytest

from acp.misc import cast_u32


def test_cast_u32_accepts_signed_and_unsigned_32_bit_values():
    assert cast_u32(-1) == 0xFFFFFFFF
    assert cast_u32(0xFFFFFFFF) == 0xFFFFFFFF
    assert cast_u32(0x80000000) == 0x80000000


def test_cast_u32_rejects_values_outside_32_bit_range():
    with pytest.raises(Exception, match="outside u32 range"):
        cast_u32(0x100000000)
