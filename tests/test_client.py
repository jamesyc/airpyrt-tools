import logging
import struct
from collections import OrderedDict

import pytest

from acp.cflbinary import CFLBinaryPListComposer, CFLBinaryPListParser
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
        auth_challenge=None,
        auth_response=b"server-proof",
        auth_iv=b"server-iv-123456",
        auth_error_code=0,
        max_chunk=None,
        truncate_reply_to=None,
    ):
        self.get_props = get_props or []
        self.get_prop_errors = get_prop_errors or []
        self.error_code = error_code
        self.auth_challenge = auth_challenge or OrderedDict(
            [
                ("modulus", b"\x0b"),
                ("generator", b"\x02"),
                ("salt", b"salt"),
                ("publicKey", b"\x08"),
            ]
        )
        self.auth_response = auth_response
        self.auth_iv = auth_iv
        self.auth_error_code = auth_error_code
        self.max_chunk = max_chunk
        self.truncate_reply_to = truncate_reply_to
        self.requests = []
        self.auth_requests = []

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
        elif request.command == 0x1A:
            auth_request = CFLBinaryPListParser.parse(request.body)
            self.auth_requests.append(auth_request)
            if auth_request["state"] == 1:
                reply = message_packet(
                    0x1A,
                    CFLBinaryPListComposer.compose(self.auth_challenge),
                    self.auth_error_code,
                )
            elif auth_request["state"] == 3:
                reply = message_packet(
                    0x1A,
                    CFLBinaryPListComposer.compose(
                        OrderedDict(
                            [
                                ("response", self.auth_response),
                                ("iv", self.auth_iv),
                            ]
                        )
                    ),
                    self.auth_error_code,
                )
            else:
                raise AssertionError(f"unexpected auth state: {auth_request['state']!r}")
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


def message_packet(command, payload, error_code=0):
    return ACPMessage(
        0x00030001,
        0,
        0,
        command,
        error_code,
        b"\x00" * 32,
        payload,
    )._compose_raw_packet()


def client_with_fake_server(server):
    client = ACPClient("target", "password")
    client.session.sock = FakeACPServerSocket(server)
    return client


class FakeSRPClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.challenge = None
        self.server_proof = None
        self.closed = False

    def process_challenge(self, modulus, generator, salt, server_public_key):
        self.challenge = (modulus, generator, salt, server_public_key)
        return b"client-public", b"client-proof", b"session-key"

    def verify_server_proof(self, server_proof):
        self.server_proof = server_proof
        return True

    def close(self):
        self.closed = True


class PassthroughEncryption:
    def __init__(self, key, client_iv, server_iv):
        self.key = key
        self.client_iv = client_iv
        self.server_iv = server_iv

    def client_encrypt(self, data):
        return data

    def server_decrypt(self, data):
        return data


class PrefixEncryption(PassthroughEncryption):
    def client_encrypt(self, data):
        return b"encrypted:" + data

    def server_decrypt(self, data):
        return data.removeprefix(b"encrypted:")


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


def test_authenticate_srp_exchanges_auth_plists(monkeypatch):
    monkeypatch.setattr("acp.client.os.urandom", lambda size: b"client-iv-123456")
    instances = []

    def srp_client_factory(username, password):
        instance = FakeSRPClient(username, password)
        instances.append(instance)
        return instance

    server = FakeACPServer()
    client = client_with_fake_server(server)

    session_key, client_iv, server_iv = client.authenticate_srp(
        username="admin",
        srp_client_factory=srp_client_factory,
    )

    assert session_key == b"session-key"
    assert client_iv == b"client-iv-123456"
    assert server_iv == b"server-iv-123456"
    assert len(server.auth_requests) == 2
    assert server.auth_requests[0] == {"state": 1, "username": "admin"}
    assert server.auth_requests[1] == {
        "iv": b"client-iv-123456",
        "publicKey": b"client-public",
        "state": 3,
        "response": b"client-proof",
    }
    assert instances[0].username == "admin"
    assert instances[0].password == "password"
    assert instances[0].challenge == (
        b"\x0b",
        b"\x02",
        b"salt",
        b"\x08",
    )
    assert instances[0].server_proof == b"server-proof"
    assert client.session.encrypt_method is not None
    assert client.session.decrypt_method is not None
    assert instances[0].closed is True


def test_authenticate_srp_enables_encrypted_session_for_followup_reads(monkeypatch):
    monkeypatch.setattr("acp.client.os.urandom", lambda size: b"client-iv-123456")
    monkeypatch.setattr("acp.session.ACPEncryption", PassthroughEncryption)
    server = FakeACPServer(get_props=[ACPProperty("syNm", "router")])
    client = client_with_fake_server(server)

    client.authenticate_srp(srp_client_factory=FakeSRPClient)
    props = client.get_properties(["syNm"])

    assert props[0].value == "router"
    assert client.session.encryption_context.key == b"session-key"
    assert client.session.encryption_context.client_iv == b"client-iv-123456"
    assert client.session.encryption_context.server_iv == b"server-iv-123456"
    assert [request.command for request in server.requests] == [0x1A, 0x1A, 0x14]


def test_close_clears_srp_encryption_before_reusing_client(monkeypatch):
    monkeypatch.setattr("acp.client.os.urandom", lambda size: b"client-iv-123456")
    monkeypatch.setattr("acp.session.ACPEncryption", PrefixEncryption)
    first_server = FakeACPServer()
    second_server = FakeACPServer()
    client = client_with_fake_server(first_server)

    client.authenticate_srp(srp_client_factory=FakeSRPClient)
    client.close()
    client.session.sock = FakeACPServerSocket(second_server)
    client.authenticate_srp(srp_client_factory=FakeSRPClient)

    first_auth = first_server.requests[0]
    second_auth = second_server.requests[0]
    assert first_auth.command == 0x1A
    assert second_auth.command == 0x1A
    assert not client.session.sock.sent[0].startswith(b"encrypted:")


def test_authenticate_srp_reports_missing_challenge_field():
    server = FakeACPServer(auth_challenge={"modulus": b"\x0b"})
    client = client_with_fake_server(server)

    with pytest.raises(ACPClientError, match='missing required field "generator"'):
        client.authenticate_srp(srp_client_factory=FakeSRPClient)


def test_authenticate_srp_reports_reply_error_code():
    server = FakeACPServer(auth_error_code=0x1234)
    client = client_with_fake_server(server)

    with pytest.raises(ACPClientError, match="authenticate_srp failed"):
        client.authenticate_srp(srp_client_factory=FakeSRPClient)
