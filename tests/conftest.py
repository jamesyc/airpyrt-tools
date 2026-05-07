import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--live-device",
        action="store_true",
        default=False,
        help="run tests that connect to a real ACP device",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--live-device"):
        return

    skip_live_device = pytest.mark.skip(reason="requires --live-device")
    for item in items:
        if "live_device" in item.keywords:
            item.add_marker(skip_live_device)


def unhex(value):
    return bytes.fromhex("".join(value.split()))


@pytest.fixture
def assert_hex():
    def _assert_hex(actual, expected):
        assert actual.hex() == "".join(expected.split()).lower()

    return _assert_hex
