"""Shared wire-format builders for tests.

Helpers here construct valid protocol blobs so individual test modules can
focus on behavior. Fakes/mocks stay local to the test module that uses them.
"""

import struct
import zlib

from acp.basebinary import Basebinary


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
