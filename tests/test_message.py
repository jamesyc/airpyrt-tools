import struct

import pytest

from acp.exception import ACPMessageError
from acp.message import ACPMessage, _generate_acp_header_key


def test_generate_acp_header_key_encrypts_password_to_fixed_width(assert_hex):
    key = _generate_acp_header_key("password")

    assert isinstance(key, bytes)
    assert len(key) == 32
    assert_hex(
        key,
        "7e588b76b36e272b0cac857d868ab517"
        "3e09c835f431657f3c9cb56d969aa507",
    )


def test_compose_feat_command_matches_known_wire_bytes(assert_hex):
    packet = ACPMessage.compose_feat_command(0)

    assert isinstance(packet, bytes)
    assert len(packet) == ACPMessage.header_size
    assert_hex(
        packet,
        "6163707000030001e790132700000001ffffffff00000000000000000000001b"
        "000000000000000000000000000000000e39f805c401554f0cac857d868ab517"
        "3e09c835f431657f3c9cb56d969aa50700000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
    )


def test_compose_and_parse_message_with_body_round_trips_bytes():
    packet = ACPMessage.compose_getprop_command(4, "pw", b"abcd")
    message = ACPMessage.parse_raw(packet)

    assert message.command == 0x14
    assert message.flags == 4
    assert message.body == b"abcd"
    assert message.body_size == 4
    assert isinstance(message.key, bytes)


def test_parse_rejects_bad_magic():
    packet = bytearray(ACPMessage.compose_feat_command(0))
    packet[:4] = b"bad!"

    with pytest.raises(ACPMessageError, match="bad header magic"):
        ACPMessage.parse_raw(bytes(packet))


def test_parse_rejects_bad_body_checksum():
    packet = bytearray(ACPMessage.compose_getprop_command(4, "pw", b"abcd"))
    body_checksum_offset = 12
    packet[body_checksum_offset : body_checksum_offset + 4] = struct.pack("!i", 1)

    with pytest.raises(ACPMessageError, match="header checksum"):
        ACPMessage.parse_raw(bytes(packet))
