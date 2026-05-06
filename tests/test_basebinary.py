import gzip
import struct
import zlib

import pytest
from Cryptodome.Cipher import AES

from acp.basebinary import Basebinary, BasebinaryError, _derive_key


def test_derive_key_returns_model_specific_bytes(assert_hex):
    assert_hex(_derive_key(107), "4b53d84d1f95eedd0af3a7ba0d94180c")
    assert _derive_key(999) is None


def test_parse_header_accepts_wire_header_bytes():
    header = Basebinary._header_format.pack(Basebinary._header_magic, 1, 107, 2, 3, 4, 5, 0, 6)

    assert Basebinary.parse_header(header) == (1, 107, 2, 3, 4, 5, 0, 6)


def test_parse_rejects_bad_header_magic():
    header = Basebinary._header_format.pack(b"BAD-FIRMWARE!!\x00", 1, 107, 2, 3, 4, 5, 0, 6)

    with pytest.raises(BasebinaryError, match="bad header magic"):
        Basebinary.parse_header(header)


def test_parse_header_rejects_short_header_as_basebinary_error():
    with pytest.raises(BasebinaryError, match="failed to parse firmware header"):
        Basebinary.parse_header(b"short")


def test_parse_returns_inner_bytes_when_checksum_matches():
    inner = b"abc"
    header = Basebinary._header_format.pack(Basebinary._header_magic, 1, 107, 2, 3, 4, 5, 0, 6)
    checksum = zlib.adler32(header + inner) & 0xFFFFFFFF

    assert Basebinary.parse(header + inner + struct.pack(">I", checksum)) == inner


def test_decrypt_chunk_decrypts_full_blocks_and_leaves_odd_tail_plaintext():
    key = _derive_key(107)
    iv = Basebinary._header_magic + b"\x01"
    plaintext = b"0123456789abcdef"
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext) + b"tail"

    assert Basebinary.decrypt_chunk(encrypted, key, iv) == plaintext + b"tail"


def test_extract_finds_gzip_payload_inside_bytes():
    payload = gzip.compress(b"hello")

    assert Basebinary.extract(b"prefix" + payload) == b"hello"


def test_extract_rejects_missing_gzip_payload_as_basebinary_error():
    with pytest.raises(BasebinaryError, match="gzip payload not found"):
        Basebinary.extract(b"no gzip payload")


def test_extract_rejects_invalid_gzip_payload_as_basebinary_error():
    with pytest.raises(BasebinaryError, match="failed to decompress gzip payload"):
        Basebinary.extract(b"prefix\x1f\x8b\x08invalid")
