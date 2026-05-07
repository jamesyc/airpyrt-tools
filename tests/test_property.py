import builtins

import pytest

from acp.exception import ACPPropertyError
from acp.property import ACPProperty


def test_parse_raw_element_header_decodes_name_from_wire_bytes():
    assert ACPProperty.parse_raw_element_header(b"syNm\x00\x00\x00\x00\x00\x00\x00\x06") == (
        "syNm",
        0,
        6,
    )


def test_compose_raw_element_for_string_property_returns_bytes():
    raw = ACPProperty.compose_raw_element(0, ACPProperty("syNm", "router"))

    assert raw == b"syNm\x00\x00\x00\x00\x00\x00\x00\x06router"


def test_parse_raw_element_for_string_property_decodes_value():
    prop = ACPProperty.parse_raw_element(b"syNm\x00\x00\x00\x00\x00\x00\x00\x06router")

    assert prop.name == "syNm"
    assert prop.value == "router"
    assert str(prop) == "router"


def test_string_property_rejects_malformed_utf8_as_property_error():
    with pytest.raises(ACPPropertyError, match="invalid UTF-8 string"):
        ACPProperty.parse_raw_element(b"syNm\x00\x00\x00\x00\x00\x00\x00\x01\xff")


def test_parse_raw_element_rejects_size_mismatches():
    with pytest.raises(ACPPropertyError, match="shorter than declared size"):
        ACPProperty.parse_raw_element(b"syNm\x00\x00\x00\x00\x00\x00\x00\x06rou")

    with pytest.raises(ACPPropertyError, match="extra data found"):
        ACPProperty.parse_raw_element(b"syNm\x00\x00\x00\x00\x00\x00\x00\x03router")


def test_integer_property_accepts_wire_bytes_and_composes_big_endian_value():
    prop = ACPProperty("syUT", b"\x00\x00\x00\x2a")

    assert prop.value == 42
    assert str(prop) == "42"
    assert ACPProperty.compose_raw_element(0, prop) == (
        b"syUT\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x2a"
    )


def test_mac_property_accepts_text_or_wire_bytes_and_formats_hex_pairs():
    assert ACPProperty("raMA", "aa:bb:cc:dd:ee:ff").value == b"\xaa\xbb\xcc\xdd\xee\xff"
    assert str(ACPProperty("raMA", b"\xaa\xbb\xcc\xdd\xee\xff")) == "aa:bb:cc:dd:ee:ff"


def test_bin_property_requires_bytes_and_formats_hex():
    prop = ACPProperty("diag", b"\xde\xad\xbe\xef")

    assert prop.value == b"\xde\xad\xbe\xef"
    assert str(prop) == "deadbeef"

    with pytest.raises(ACPPropertyError):
        ACPProperty("diag", "deadbeef")


def test_log_property_formats_null_delimited_bytes():
    prop = ACPProperty("logm", b"one\x00two\x00")

    assert str(prop) == "one\ntwo\n"


def test_property_validation_uses_structured_rules_without_eval(monkeypatch):
    def fail_eval(*_args, **_kwargs):
        raise AssertionError("eval should not be used for property validation")

    monkeypatch.setattr(builtins, "eval", fail_eval)

    assert ACPProperty("LEDc", 3).value == 3
    assert ACPProperty("GPIs", b"\x00" * 8).value == b"\x00" * 8


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LEDc", 4),
        ("acRB", 1),
        ("dbug", 0x100000000),
        ("GPIs", b"\x00" * 7),
    ],
)
def test_property_validation_rejects_out_of_range_values(name, value):
    with pytest.raises(ACPPropertyError, match="invalid value"):
        ACPProperty(name, value)


def test_compose_raw_element_rejects_integer_values_outside_u32():
    with pytest.raises(ACPPropertyError, match="fit unsigned 32-bit"):
        ACPProperty.compose_raw_element(0, ACPProperty("syUT", 0x100000000))


def test_null_property_marker_round_trips_to_empty_property():
    prop = ACPProperty.parse_raw_element(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00"
    )

    assert prop.name is None
    assert prop.value is None
    assert ACPProperty.compose_raw_element(0, prop) == (
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00"
    )


def test_property_element_flag_helpers_name_supported_and_unknown_bits():
    assert ACPProperty.element_has_error(ACPProperty.ELEMENT_FLAG_ERROR) is True
    assert ACPProperty.unsupported_element_flags(0) == 0
    assert ACPProperty.unsupported_element_flags(ACPProperty.ELEMENT_FLAG_ERROR) == 0
    assert ACPProperty.unsupported_element_flags(0x2) == 0x2
    assert ACPProperty.unsupported_element_flags(0x3) == 0x2
