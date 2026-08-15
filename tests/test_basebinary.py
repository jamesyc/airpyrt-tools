import gzip
import struct
import zlib

import pytest
from Cryptodome.Cipher import AES

from acp.basebinary import Basebinary, BasebinaryError, _derive_key


def test_derive_key_returns_model_specific_bytes(assert_hex):
    assert_hex(_derive_key(107), "4b53d84d1f95eedd0af3a7ba0d94180c")
    assert _derive_key(999) is None


@pytest.mark.parametrize(
    ("model", "expected_key"),
    [
        (104, "f560a1fe0c9f843368aa2e0410846a50"),
        (105, "9eef344bd86df754b894f5b8ab6deca3"),
        (106, "482607b9a21d4e07127d5f01b38c0782"),
        (108, "a267f0156dc6f10e21d865ef391a2ea6"),
        (109, "d6ab410907278799a28787ae8fa3b9a8"),
        (113, "d93fe5e63e3eafc9a4fd8f3443b2fc62"),
        (114, "bf743d22666b0d628d5d83ed2c77ca20"),
        (116, "840842f294ec950cee8465b3889d66bb"),
        (117, "6d0b864d9fd9bc37fa2205c0bbdbc0b2"),
        (119, "a8832cc1d666acd170c6c390a4bec18f"),
        (120, "7196c6270675c2822694ede65674b5fa"),
    ],
)
def test_derive_key_supports_timecapsulesmb_models(assert_hex, model, expected_key):
    assert_hex(_derive_key(model), expected_key)


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
