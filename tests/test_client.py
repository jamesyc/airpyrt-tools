from acp.client import ACPClient
from acp.message import ACPMessage
from acp.property import ACPProperty


class FakeSession:
    def __init__(self, recv_chunks):
        self.recv_chunks = list(recv_chunks)
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(data)

    def recv(self, size):
        chunk = self.recv_chunks.pop(0)
        assert len(chunk) == size
        return chunk

    def connect(self):
        pass

    def close(self):
        self.closed = True


def stream_header(command):
    return ACPMessage(0x00030001, 0, 0, command, 0, b"\x00" * 32, None, -1)._compose_header()


def test_get_properties_sends_bytes_and_parses_property_reply():
    prop = ACPProperty.compose_raw_element(0, ACPProperty("syNm", "router"))
    end = ACPProperty.compose_raw_element(0, ACPProperty())
    fake_session = FakeSession(
        [
            stream_header(0x14),
            prop[: ACPProperty.element_header_size],
            prop[ACPProperty.element_header_size :],
            end[: ACPProperty.element_header_size],
            end[ACPProperty.element_header_size :],
        ]
    )
    client = ACPClient("target", "password")
    client.session = fake_session

    props = client.get_properties(["syNm"])

    assert props[0].name == "syNm"
    assert props[0].value == "router"
    assert isinstance(fake_session.sent[0], bytes)
    assert fake_session.sent[0].startswith(b"acpp")


def test_set_properties_sends_bytes_payload():
    end = ACPProperty.compose_raw_element(0, ACPProperty())
    fake_session = FakeSession(
        [
            stream_header(0x15),
            end[: ACPProperty.element_header_size],
            end[ACPProperty.element_header_size :],
        ]
    )
    client = ACPClient("target", "password")
    client.session = fake_session

    client.set_properties({"syNm": ACPProperty("syNm", "router")})

    assert isinstance(fake_session.sent[0], bytes)
    assert b"router" in fake_session.sent[0]
