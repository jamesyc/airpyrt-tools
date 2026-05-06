import os
from pathlib import Path

import pytest

from acp.client import ACPClient

pytestmark = pytest.mark.live_device


def _read_dotenv(path):
    values = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _live_config():
    keys = ["TC_HOST", "TC_PASSWORD", "TC_EXPECTED_SYNM"]
    env_values = {
        key: os.environ.get(key)
        for key in keys
        if os.environ.get(key) is not None
    }
    dotenv_values = _read_dotenv(Path(__file__).resolve().parents[1] / ".env")

    values = {}
    for key in keys:
        values[key] = env_values.get(key, dotenv_values.get(key))

    if not values["TC_HOST"] or not values["TC_PASSWORD"]:
        pytest.skip("TC_HOST and TC_PASSWORD are required for live ACP device tests")

    return {
        "host": _normalize_acp_host(values["TC_HOST"]),
        "password": values["TC_PASSWORD"],
        "expected_synm": values["TC_EXPECTED_SYNM"],
    }


def _normalize_acp_host(host):
    return host.rsplit("@", 1)[-1]


def _connected_srp_client():
    config = _live_config()
    client = ACPClient(config["host"], config["password"])
    client.connect()
    client.authenticate_srp()
    return client, config


def _read_property(client, name):
    props = client.get_properties([name])
    assert len(props) == 1
    assert props[0].name == name
    return props[0]


def test_live_srp_reads_device_name():
    client, config = _connected_srp_client()
    try:
        prop = _read_property(client, "syNm")
    finally:
        client.close()

    assert isinstance(prop.value, str)
    assert prop.value
    if config["expected_synm"]:
        assert prop.value == config["expected_synm"]


def test_live_srp_reads_property_catalog():
    client, _config = _connected_srp_client()
    try:
        prop = _read_property(client, "prop")
    finally:
        client.close()

    assert isinstance(prop.value, str)
    assert "syNm" in prop.value
