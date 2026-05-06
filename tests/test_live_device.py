import os
from pathlib import Path

import pytest

from acp.client import ACPClient
from acp.exception import ACPSessionError
from acp.property import ACPProperty

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
    env_values = {
        key: os.environ.get(key)
        for key in ["TC_HOST", "TC_PASSWORD", "TC_LIVE_WRITES"]
        if os.environ.get(key) is not None
    }
    dotenv_values = _read_dotenv(Path(__file__).resolve().parents[1] / ".env")

    values = {}
    for key in ["TC_HOST", "TC_PASSWORD", "TC_LIVE_WRITES"]:
        values[key] = env_values.get(key, dotenv_values.get(key))

    if not values["TC_HOST"] or not values["TC_PASSWORD"]:
        pytest.skip("TC_HOST and TC_PASSWORD are required for live ACP device tests")

    return {
        "host": _normalize_acp_host(values["TC_HOST"]),
        "password": values["TC_PASSWORD"],
        "live_writes": values.get("TC_LIVE_WRITES") == "1",
    }


def _normalize_acp_host(host):
    return host.rsplit("@", 1)[-1]


def _connected_client():
    config = _live_config()
    client = ACPClient(config["host"], config["password"])
    client.connect()
    return client, config


def _connected_srp_client(config):
    client = ACPClient(config["host"], config["password"])
    client.connect()
    client.authenticate_srp()
    return client


def _read_property(client, name):
    props = client.get_properties([name])
    assert len(props) == 1
    assert props[0].name == name
    return props[0]


def _set_property_over_srp(config, name, value):
    client = _connected_srp_client(config)
    try:
        try:
            client.set_properties({name: ACPProperty(name, value)})
        except ACPSessionError:
            # Some devices apply syNm and then close the encrypted session before replying.
            pass
    finally:
        client.close()


def test_live_srp_auth_enables_encrypted_property_read():
    client, _config = _connected_client()
    try:
        client.authenticate_srp()
        prop = _read_property(client, "syNm")
    finally:
        client.close()

    assert isinstance(prop.value, str)
    assert prop.value


def test_live_srp_reversible_synm_write_restore():
    client, config = _connected_client()
    if not config["live_writes"]:
        client.close()
        pytest.skip("TC_LIVE_WRITES=1 is required for live write tests")

    try:
        client.authenticate_srp()
        original = _read_property(client, "syNm").value
    finally:
        client.close()
    temporary = f"{original}-srp-v2-test"
    if temporary == original:
        temporary = f"{original}-test"

    try:
        _set_property_over_srp(config, "syNm", temporary)
        verify_client = _connected_srp_client(config)
        try:
            assert _read_property(verify_client, "syNm").value == temporary
        finally:
            verify_client.close()
    finally:
        _set_property_over_srp(config, "syNm", original)
