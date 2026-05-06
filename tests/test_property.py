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


def test_null_property_marker_round_trips_to_empty_property():
    prop = ACPProperty.parse_raw_element(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00"
    )

    assert prop.name is None
    assert prop.value is None
    assert ACPProperty.compose_raw_element(0, prop) == (
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00"
    )
