import logging
import struct
import sys

import pytest

from acp.client import ACPClient
from acp.exception import ACPClientError, ACPSessionError
from acp.message import ACPMessage
from acp.property import ACPProperty


class FakeACPServer:
    def __init__(
        self,
        *,
        get_props=None,
        get_prop_errors=None,
        error_code=0,
        max_chunk=None,
        truncate_reply_to=None,
    ):
        self.get_props = get_props or []
        self.get_prop_errors = get_prop_errors or []
        self.error_code = error_code
        self.max_chunk = max_chunk
        self.truncate_reply_to = truncate_reply_to
        self.requests = []

    def handle_request(self, data):
        request = ACPMessage.parse_raw(data)
        self.requests.append(request)
        if request.command == 0x14:
            reply = stream_header(0x14, self.error_code)
            if self.error_code == 0:
                for name, error_code in self.get_prop_errors:
                    reply += ACPProperty.compose_raw_element_header(name, 1, 4)
                    reply += struct.pack(">I", error_code)
                for prop in self.get_props:
                    reply += ACPProperty.compose_raw_element(0, prop)
                reply += ACPProperty.compose_raw_element(0, ACPProperty())
        elif request.command == 0x15:
            reply = stream_header(0x15, self.error_code)
            if self.error_code == 0:
                reply += ACPProperty.compose_raw_element(0, ACPProperty())
        else:
            raise AssertionError(f"unexpected command: {request.command:#x}")
        if self.truncate_reply_to is not None:
            return reply[: self.truncate_reply_to]
        return reply


class FakeACPServerSocket:
    def __init__(self, server):
        self.server = server
        self.reply = bytearray()
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)
        self.reply += self.server.handle_request(data)

    def recv(self, size):
        if self.server.max_chunk is not None:
            size = min(size, self.server.max_chunk)
        chunk = bytes(self.reply[:size])
        del self.reply[:size]
        return chunk

    def close(self):
        self.closed = True


def stream_header(command, error_code=0):
    return ACPMessage(
        0x00030001,
        0,
        0,
        command,
        error_code,
        b"\x00" * 32,
        None,
        -1,
    )._compose_header()


def client_with_fake_server(server):
    client = ACPClient("target", "password")
    client.session.sock = FakeACPServerSocket(server)
    return client


def test_get_properties_uses_fake_server_and_parses_chunked_property_reply():
    server = FakeACPServer(get_props=[ACPProperty("syNm", "router")], max_chunk=3)
    client = client_with_fake_server(server)

    props = client.get_properties(["syNm"])

    assert props[0].name == "syNm"
    assert props[0].value == "router"
    assert isinstance(client.session.sock.sent[0], bytes)
    assert server.requests[0].command == 0x14
    assert server.requests[0].body.startswith(b"syNm")


def test_set_properties_uses_fake_server_and_sends_bytes_payload():
    server = FakeACPServer()
    client = client_with_fake_server(server)

    client.set_properties({"syNm": ACPProperty("syNm", "router")})

    assert isinstance(client.session.sock.sent[0], bytes)
    assert server.requests[0].command == 0x15
    assert b"router" in server.requests[0].body


def test_get_properties_raises_client_error_for_reply_error_code():
    client = client_with_fake_server(FakeACPServer(error_code=0x1234))

    with pytest.raises(ACPClientError, match="get_properties failed"):
        client.get_properties(["syNm"])


def test_get_properties_logs_property_error_and_continues(caplog):
    server = FakeACPServer(
        get_prop_errors=[("syNm", 0x5678)],
        get_props=[ACPProperty("syUT", 42)],
    )
    client = client_with_fake_server(server)

    with caplog.at_level(logging.WARNING):
        props = client.get_properties(["syNm", "syUT"])

    assert [prop.name for prop in props] == ["syUT"]
    assert props[0].value == 42
    assert "error requesting value for property \"syNm\": 0x5678" in caplog.text


def test_get_properties_raises_session_error_for_short_server_reply():
    server = FakeACPServer(get_props=[ACPProperty("syNm", "router")], truncate_reply_to=4)
    client = client_with_fake_server(server)

    with pytest.raises(ACPSessionError, match="connection closed"):
        client.get_properties(["syNm"])


def test_importing_client_does_not_load_applesrp_framework(monkeypatch):
    import acp.client as client_module

    monkeypatch.delitem(sys.modules, "acp.clibs.AppleSRP", raising=False)
    monkeypatch.delitem(sys.modules, "acp.clibs", raising=False)

    __import__("importlib").reload(client_module)

    assert "acp.clibs.AppleSRP" not in sys.modules


def test_authenticate_applesrp_reports_unavailable_framework(monkeypatch):
    import acp.srp as srp_module

    real_import_module = srp_module.importlib.import_module

    def fake_import_module(name):
        if name == "acp.clibs.AppleSRP":
            raise OSError("AppleSRP framework missing")
        return real_import_module(name)

    monkeypatch.setattr(srp_module.importlib, "import_module", fake_import_module)

    with pytest.raises(ACPClientError, match="private macOS AppleSRP framework"):
        ACPClient("target", "password").authenticate_AppleSRP()
