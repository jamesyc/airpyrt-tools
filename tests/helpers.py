"""Shared wire-format builders for tests.

Helpers here construct valid protocol blobs so individual test modules can
focus on behavior. Fakes/mocks stay local to the test module that uses them.
"""

import struct
import zlib

from Cryptodome.Cipher import AES

from acp.basebinary import Basebinary, _derive_key


def make_basebinary_header(
    magic=Basebinary._header_magic,
    byte_0x0f=1,
    model=107,
    version=2,
    byte_0x18=3,
    byte_0x19=4,
    byte_0x1a=5,
    flags=0,
    unk_0x1c=6,
):
    return Basebinary._header_format.pack(
        magic,
        byte_0x0f,
        model,
        version,
        byte_0x18,
        byte_0x19,
        byte_0x1a,
        flags,
        unk_0x1c,
    )


def make_basebinary_blob(inner, **header_kwargs):
    header = make_basebinary_header(**header_kwargs)
    checksum = zlib.adler32(header + inner) & 0xFFFFFFFF
    return header + inner + struct.pack(">I", checksum)


def make_encrypted_basebinary_blob(inner, model=107, byte_0x0f=1, **header_kwargs):
    """Build a flags=2 blob whose checksum covers the plaintext inner bytes.

    parse() decrypts before checksumming, so the stored checksum must be
    computed over header + plaintext, not header + ciphertext.
    """
    header_kwargs["model"] = model
    header_kwargs["byte_0x0f"] = byte_0x0f
    header_kwargs["flags"] = 2
    header = make_basebinary_header(**header_kwargs)
    checksum = zlib.adler32(header + inner) & 0xFFFFFFFF
    encrypted = encrypt_basebinary_inner(inner, model, byte_0x0f)
    return header + encrypted + struct.pack(">I", checksum)


def encrypt_basebinary_inner(inner, model=107, byte_0x0f=1):
    """Encrypt inner bytes the way Basebinary.decrypt expects to decrypt them.

    Mirrors decrypt's 0x8000-byte chunking with a fresh AES-CBC cipher per
    chunk, leaving a sub-16-byte tail unencrypted, so the output round-trips
    through Basebinary.parse with the encrypted flag set.
    """
    key = _derive_key(model)
    assert key is not None, f"missing basebinary key for model {model}"
    iv = Basebinary._header_magic + bytes([byte_0x0f])
    encrypted_chunks = []
    for offset in range(0, len(inner), 0x8000):
        piece = inner[offset : offset + 0x8000]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block_aligned = piece[: len(piece) // 16 * 16]
        encrypted_chunks.append(cipher.encrypt(block_aligned) + piece[len(block_aligned) :])
    return b"".join(encrypted_chunks)
