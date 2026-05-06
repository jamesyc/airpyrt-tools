import builtins
import struct

import pytest

from acp.client import ACPClient
from acp.exception import ACPClientError, ACPSessionError
from acp.message import ACPMessage
from acp.property import ACPProperty


class FakeACPServer:
    def __init__(self, *, get_props=None, error_code=0, max_chunk=None, truncate_reply_to=None):
        self.get_props = get_props or []
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


def test_get_properties_raises_client_error_for_property_error_flag():
    error_element = (
        ACPProperty.compose_raw_element_header("syNm", 1, 4) + struct.pack(">I", 0x5678)
    )
    server = FakeACPServer(get_props=[])
    client = client_with_fake_server(server)
    client.session.sock.reply += stream_header(0x14) + error_element

    with pytest.raises(ACPClientError, match="error requesting value"):
        client.get_properties(["syNm"])


def test_get_properties_raises_session_error_for_short_server_reply():
    server = FakeACPServer(get_props=[ACPProperty("syNm", "router")], truncate_reply_to=4)
    client = client_with_fake_server(server)

    with pytest.raises(ACPSessionError, match="connection closed"):
        client.get_properties(["syNm"])


def test_authenticate_applesrp_reports_unavailable_framework(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.endswith("clibs") and "AppleSRP" in fromlist:
            raise OSError("AppleSRP framework missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ACPClientError, match="AppleSRP authentication is unavailable"):
        ACPClient("target", "password").authenticate_AppleSRP()
