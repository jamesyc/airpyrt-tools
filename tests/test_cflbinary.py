from collections import OrderedDict

import pytest

from acp.cflbinary import CFLBinaryPListComposer, CFLBinaryPListParseError, CFLBinaryPListParser


def round_trip(value):
    return CFLBinaryPListParser.parse(CFLBinaryPListComposer.compose(value))


@pytest.mark.parametrize("value", [None, False, True, 1, 255, 256, 1.5, b"blob", "router"])
def test_compose_and_parse_scalar_values_round_trip(value):
    assert round_trip(value) == value


def test_compose_returns_bytes_with_cfb_header_and_footer():
    data = CFLBinaryPListComposer.compose("hi")

    assert data == b"CFB0phi\x00END!"


def test_compose_and_parse_list_round_trips():
    assert round_trip([1, "x", b"yz"]) == [1, "x", b"yz"]


def test_compose_and_parse_ordered_dict_round_trips():
    value = OrderedDict([("state", 1), ("blob", b"ab")])

    assert round_trip(value) == value


def test_parser_rejects_bad_header_and_footer():
    with pytest.raises(CFLBinaryPListParseError, match="bad header magic"):
        CFLBinaryPListParser.parse(b"BAD!\x00END!")

    with pytest.raises(CFLBinaryPListParseError, match="bad footer magic"):
        CFLBinaryPListParser.parse(b"CFB0\x00BAD!")


def test_parser_rejects_unterminated_utf8_string():
    with pytest.raises(CFLBinaryPListParseError, match="unterminated UTF-8 string"):
        CFLBinaryPListParser.parse(b"CFB0pabcEND!")


def test_parser_rejects_malformed_utf8_string():
    with pytest.raises(CFLBinaryPListParseError, match="failed to decode UTF-8 string"):
        CFLBinaryPListParser.parse(b"CFB0p\xff\x00END!")


def test_parser_rejects_truncated_int_and_real_values():
    with pytest.raises(CFLBinaryPListParseError, match="failed to unpack int value"):
        CFLBinaryPListParser.parse(b"CFB0\x12\x00END!")

    with pytest.raises(CFLBinaryPListParseError, match="failed to unpack float value"):
        CFLBinaryPListParser.parse(b"CFB0#abcEND!")


def test_parser_rejects_truncated_data_value():
    with pytest.raises(CFLBinaryPListParseError, match="failed to unpack data value"):
        CFLBinaryPListParser.parse(b"CFB0CabEND!")


def test_parser_rejects_invalid_extended_count_marker():
    with pytest.raises(CFLBinaryPListParseError, match="expected count"):
        CFLBinaryPListParser.parse(b"CFB0Opcount\x00END!")
