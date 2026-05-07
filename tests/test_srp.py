import hashlib

import pytest

from acp.exception import ACPClientError
from acp.srp import RFC2945_KEY_LEN, SRP6aClient


def _unhex(value):
    return bytes.fromhex("".join(value.split()))


def _mgf1_sha1(seed, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output += hashlib.sha1(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(output[:length])


def _sha1_int(*parts):
    digest = hashlib.sha1()
    for part in parts:
        digest.update(part)
    return int.from_bytes(digest.digest(), "big")


def _zero_base_server_public_key(username, password, modulus, generator, salt):
    n = int.from_bytes(modulus, "big")
    g = int.from_bytes(generator, "big")
    password_hash = hashlib.sha1(username + b":" + password).digest()
    x = _sha1_int(salt, password_hash)
    k = _sha1_int(modulus, generator)
    return (k * pow(g, x, n)) % n


RFC5054_1024_N = """
    EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
    9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
    8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
    7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
    FD5138FE 8376435B 9FC61D2F C0EB06E3
"""

RFC5054_SALT = "BEB25379 D1A8581E B5A72767 3A2441EE"

RFC5054_A = """
    61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
    4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
    8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
    BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
    B349EF5D 76988A36 72FAC47B 0769447B
"""

RFC5054_A_SECRET = """
    60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
    DA2D4393
"""

RFC5054_B = """
    BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
    BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
    6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
    37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
    EB4012B7 D7665238 A8E3FB00 4B117B58
"""

RFC5054_PREMASTER_SECRET = """
    B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
    233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
    41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
    3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
    C346D7E4 74B29EDE 8A469FFE CA686E5A
"""

STANFORD_SRP_SESSION_KEY = """
    44EBB4AB 646ABBB1 23287F37 6DB03FE0 EEB92902 9C2ED935 925C128C
    CA3808A6 F22D00AD D6BBAE62
"""


def test_srp6a_matches_rfc5054_public_key_and_premaster_secret(assert_hex):
    client = SRP6aClient("alice", "password123", private_key=_unhex(RFC5054_A_SECRET))

    public_key, proof, session_key = client.process_challenge(
        _unhex(RFC5054_1024_N),
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    assert_hex(public_key, RFC5054_A)
    assert_hex(client.premaster_secret, RFC5054_PREMASTER_SECRET)
    assert_hex(session_key, STANFORD_SRP_SESSION_KEY)
    assert len(proof) == 20
    assert len(session_key) == RFC2945_KEY_LEN


def test_srp6a_pads_client_public_key_to_modulus_size():
    client = SRP6aClient("alice", "password123", private_key=1)
    modulus = _unhex(RFC5054_1024_N)

    public_key, _proof, _session_key = client.process_challenge(
        modulus,
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    assert len(public_key) == len(modulus)
    assert public_key[:-1] == b"\x00" * (len(modulus) - 1)
    assert public_key[-1:] == b"\x02"
    assert client.client_public_key == public_key


def test_srp6a_pads_premaster_secret_before_session_key_derivation():
    client = SRP6aClient("alice", "password123", private_key=209)
    modulus = _unhex(RFC5054_1024_N)

    _public_key, _proof, session_key = client.process_challenge(
        modulus,
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    assert len(client.premaster_secret) == len(modulus)
    assert client.premaster_secret.startswith(b"\x00")
    assert session_key == _mgf1_sha1(client.premaster_secret, RFC2945_KEY_LEN)
    assert session_key != _mgf1_sha1(
        client.premaster_secret.lstrip(b"\x00"),
        RFC2945_KEY_LEN,
    )


def test_srp6a_verifies_matching_server_proof():
    client = SRP6aClient("alice", "password123", private_key=_unhex(RFC5054_A_SECRET))
    client.process_challenge(
        _unhex(RFC5054_1024_N),
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    assert client.verify_server_proof(client.expected_server_proof) is True


def test_srp6a_close_clears_sensitive_instance_state():
    client = SRP6aClient("alice", "password123", private_key=_unhex(RFC5054_A_SECRET))
    client.process_challenge(
        _unhex(RFC5054_1024_N),
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    assert client.password is not None
    assert client.private_key is not None
    assert client.premaster_secret is not None
    assert client.session_key is not None
    assert client.expected_server_proof is not None

    client.close()
    client.close()

    for attr in [
        "username",
        "password",
        "private_key",
        "premaster_secret",
        "session_key",
        "client_public_key",
        "server_public_key",
        "client_proof",
        "expected_server_proof",
    ]:
        assert getattr(client, attr) is None


def test_srp6a_rejects_wrong_server_proof():
    client = SRP6aClient("alice", "password123", private_key=_unhex(RFC5054_A_SECRET))
    client.process_challenge(
        _unhex(RFC5054_1024_N),
        b"\x02",
        _unhex(RFC5054_SALT),
        _unhex(RFC5054_B),
    )

    with pytest.raises(ACPClientError, match="server proof verification failed"):
        client.verify_server_proof(b"\x00" * 20)


def test_srp6a_rejects_zero_modulo_server_public_key():
    client = SRP6aClient("alice", "password123", private_key=1)

    with pytest.raises(ACPClientError, match="server public key"):
        client.process_challenge(
            _unhex(RFC5054_1024_N),
            b"\x02",
            _unhex(RFC5054_SALT),
            _unhex(RFC5054_1024_N),
        )


def test_srp6a_rejects_zero_premaster_base():
    modulus = b"\x17"
    generator = b"\x02"
    salt = b"salt"
    server_public_key_int = _zero_base_server_public_key(
        b"alice",
        b"password123",
        modulus,
        generator,
        salt,
    )
    assert server_public_key_int != 0
    client = SRP6aClient("alice", "password123", private_key=1)

    with pytest.raises(ACPClientError, match="premaster base"):
        client.process_challenge(
            modulus,
            generator,
            salt,
            bytes([server_public_key_int]),
        )


def test_srp6a_rejects_generator_not_less_than_modulus():
    client = SRP6aClient("alice", "password123", private_key=1)

    with pytest.raises(ACPClientError, match="generator"):
        client.process_challenge(b"\x17", b"\x17", b"salt", b"\x01")


def test_srp6a_rejects_non_positive_private_key():
    client = SRP6aClient("alice", "password123", private_key=0)

    with pytest.raises(ACPClientError, match="private key"):
        client.process_challenge(
            _unhex(RFC5054_1024_N),
            b"\x02",
            _unhex(RFC5054_SALT),
            _unhex(RFC5054_B),
        )
