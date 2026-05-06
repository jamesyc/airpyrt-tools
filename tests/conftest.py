import pytest


def unhex(value):
    return bytes.fromhex("".join(value.split()))


@pytest.fixture
def assert_hex():
    def _assert_hex(actual, expected):
        assert actual.hex() == "".join(expected.split()).lower()

    return _assert_hex
