import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_legacy_python2_hex_codecs_are_removed_from_package_source():
    source = "\n".join(path.read_text() for path in (ROOT / "acp").rglob("*.py"))

    assert '.decode("hex")' not in source
    assert '.encode("hex")' not in source


def test_legacy_crypto_namespace_is_removed_from_package_source():
    source = "\n".join(path.read_text() for path in (ROOT / "acp").rglob("*.py"))

    assert not re.search(r"^\s*from\s+Crypto(\.|\s+)", source, re.MULTILINE)
    assert not re.search(r"^\s*import\s+Crypto(\.|\s|$)", source, re.MULTILINE)
