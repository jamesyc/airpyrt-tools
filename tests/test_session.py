import pytest

from acp import session
from acp.exception import ACPSessionError
from acp.session import ACPClientSession, _ACPSession


class FakeSocket:
    def __init__(self, data=b""):
        self.data = bytearray(data)
        self.sent = []
        self.blocking = []
        self.closed = False

    def recv(self, size):
        chunk = bytes(self.data[:size])
        del self.data[:size]
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def setblocking(self, value):
        self.blocking.append(value)

    def close(self):
        self.closed = True


class FakeEncryption:
    def __init__(self, key, client_iv, server_iv):
        self.key = key
        self.client_iv = client_iv
        self.server_iv = server_iv

    def client_encrypt(self, data):
        return b"client:" + data

    def server_decrypt(self, data):
        return data.removeprefix(b"server:")


def test_recv_size_joins_socket_chunks_as_bytes():
    acp_session = _ACPSession("target", "password")
    acp_session.sock = FakeSocket(b"abcdef")

    assert acp_session.recv(4) == b"abcd"


def test_recv_raises_when_socket_closes_before_requested_size():
    acp_session = _ACPSession("target", "password")
    acp_session.sock = FakeSocket(b"abc")

    with pytest.raises(ACPSessionError, match="connection closed"):
        acp_session.recv(4)


def test_recv_timeout_restores_blocking_mode(monkeypatch):
    class BlockingSocket(FakeSocket):
        def recv(self, size):
            raise BlockingIOError

    monotonic_times = iter([0.0, 0.0, 0.002])
    monkeypatch.setattr(session.time, "monotonic", lambda: next(monotonic_times))
    monkeypatch.setattr(session.time, "sleep", lambda _seconds: None)
    acp_session = _ACPSession("target", "password")
    acp_session.sock = BlockingSocket()

    with pytest.raises(ACPSessionError, match="timed out"):
        acp_session.recv(1, timeout=0.001)

    assert acp_session.sock.blocking == [0, 1]


def test_recv_timeout_does_not_retry_fatal_socket_errors():
    class ResetSocket(FakeSocket):
        def recv(self, size):
            raise ConnectionResetError("connection reset")

    acp_session = _ACPSession("target", "password")
    acp_session.sock = ResetSocket()

    with pytest.raises(ConnectionResetError, match="connection reset"):
        acp_session.recv(1, timeout=1)

    assert acp_session.sock.blocking == [0, 1]


def test_recv_without_socket_returns_empty_bytes():
    assert _ACPSession("target", "password").recv(4) == b""


def test_send_passes_bytes_to_socket():
    acp_session = _ACPSession("target", "password")
    acp_session.sock = FakeSocket()

    acp_session.send(b"payload")

    assert acp_session.sock.sent == [b"payload"]


def test_client_session_enable_encryption_sets_bound_methods(monkeypatch):
    monkeypatch.setattr(session, "ACPEncryption", FakeEncryption)
    acp_session = ACPClientSession("target", "password")

    acp_session.enable_encryption(b"key", b"client-iv", b"server-iv")

    assert acp_session.encrypt_method(b"payload") == b"client:payload"
    assert acp_session.decrypt_method(b"server:payload") == b"payload"


def test_close_clears_socket_and_encryption_state(monkeypatch):
    monkeypatch.setattr(session, "ACPEncryption", FakeEncryption)
    acp_session = ACPClientSession("target", "password")
    fake_socket = FakeSocket()
    acp_session.sock = fake_socket
    acp_session.enable_encryption(b"key", b"client-iv", b"server-iv")

    acp_session.close()

    assert fake_socket.closed is True
    assert acp_session.sock is None
    assert acp_session.encryption_context is None
    assert acp_session.encrypt_method is None
    assert acp_session.decrypt_method is None
