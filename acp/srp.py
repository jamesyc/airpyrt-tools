import hashlib
import hmac
import secrets

from .exception import ACPClientError

RFC2945_KEY_LEN = 40


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("expected str or bytes")


def _int_from_bytes(value):
    return int.from_bytes(value, "big")


def _int_to_bytes(value, length=None):
    if value < 0:
        raise ValueError("cannot encode negative integers")

    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)

    try:
        return value.to_bytes(length, "big")
    except OverflowError as e:
        raise ValueError("integer does not fit in the requested length") from e


def _pad_int(value, length):
    return _int_to_bytes(value, length)


def _sha1(*parts):
    digest = hashlib.sha1()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _sha1_int(*parts):
    return _int_from_bytes(_sha1(*parts))


def _xor_bytes(left, right):
    if len(left) != len(right):
        raise ValueError("byte strings must have equal length")
    pairs = zip(left, right)  # noqa: B905 - lengths checked above; strict is 3.10+.
    return bytes(left_byte ^ right_byte for left_byte, right_byte in pairs)


def _calculate_x(username, password, salt):
    inner_hash = _sha1(username, b":", password)
    return _sha1_int(salt, inner_hash)


def _calculate_k(modulus, generator, modulus_size):
    return _sha1_int(_pad_int(modulus, modulus_size), _pad_int(generator, modulus_size))


def _calculate_u(client_public_key, server_public_key, modulus_size):
    return _sha1_int(
        _pad_int(client_public_key, modulus_size),
        _pad_int(server_public_key, modulus_size),
    )


def _mgf1_sha1(seed, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output += _sha1(seed, counter.to_bytes(4, "big"))
        counter += 1
    return bytes(output[:length])


def _client_proof(
    username,
    modulus_bytes,
    generator_bytes,
    salt,
    client_public_key,
    server_public_key,
    session_key,
):
    modulus_hash = _sha1(modulus_bytes)
    generator_hash = _sha1(generator_bytes)
    username_hash = _sha1(username)
    return _sha1(
        _xor_bytes(modulus_hash, generator_hash),
        username_hash,
        salt,
        client_public_key,
        server_public_key,
        session_key,
    )


def _server_proof(client_public_key, client_proof, session_key):
    return _sha1(client_public_key, client_proof, session_key)


class SRP6aClient:
    def __init__(self, username, password, private_key=None):
        self.username = _as_bytes(username)
        self.password = _as_bytes(password)
        if isinstance(private_key, bytes):
            private_key = _int_from_bytes(private_key)
        self.private_key = private_key
        self.premaster_secret = None
        self.session_key = None
        self.client_public_key = None
        self.server_public_key = None
        self.client_proof = None
        self.expected_server_proof = None

    def _private_key(self, modulus):
        if self.private_key is not None:
            if self.private_key <= 0:
                raise ACPClientError("SRP private key must be positive")
            return self.private_key
        return secrets.randbelow(modulus - 1) + 1

    def process_challenge(self, modulus, generator, salt, server_public_key):
        modulus_bytes = _as_bytes(modulus)
        generator_bytes = _as_bytes(generator)
        salt = _as_bytes(salt)
        server_public_key_bytes = _as_bytes(server_public_key)

        n = _int_from_bytes(modulus_bytes)
        g = _int_from_bytes(generator_bytes)
        server_public_key_int = _int_from_bytes(server_public_key_bytes)

        if n <= 0:
            raise ACPClientError("SRP modulus must be positive")
        if g <= 1 or g >= n:
            raise ACPClientError("SRP generator must be greater than one and less than N")
        if server_public_key_int == 0 or server_public_key_int >= n:
            raise ACPClientError("SRP server public key must not be zero modulo N")

        modulus_size = len(modulus_bytes)
        private_key = self._private_key(n)
        client_public_key_int = pow(g, private_key, n)
        if client_public_key_int % n == 0:
            raise ACPClientError("SRP client public key must not be zero modulo N")

        x = _calculate_x(self.username, self.password, salt)
        multiplier = _calculate_k(n, g, modulus_size)
        scrambling_parameter = _calculate_u(
            client_public_key_int,
            server_public_key_int,
            modulus_size,
        )
        if scrambling_parameter == 0:
            raise ACPClientError("SRP scrambling parameter must not be zero")

        verifier_component = pow(g, x, n)
        base = (server_public_key_int - multiplier * verifier_component) % n
        if base == 0:
            raise ACPClientError("SRP premaster base must not be zero modulo N")
        exponent = private_key + scrambling_parameter * x
        premaster_secret_int = pow(base, exponent, n)
        premaster_secret = _pad_int(premaster_secret_int, modulus_size)
        session_key = _mgf1_sha1(premaster_secret, RFC2945_KEY_LEN)

        client_public_key = _pad_int(client_public_key_int, modulus_size)
        server_public_key = _pad_int(server_public_key_int, modulus_size)
        client_proof = _client_proof(
            self.username,
            modulus_bytes,
            generator_bytes,
            salt,
            client_public_key,
            server_public_key,
            session_key,
        )

        self.premaster_secret = premaster_secret
        self.session_key = session_key
        self.client_public_key = client_public_key
        self.server_public_key = server_public_key
        self.client_proof = client_proof
        self.expected_server_proof = _server_proof(
            client_public_key,
            client_proof,
            session_key,
        )

        return client_public_key, client_proof, session_key

    def verify_server_proof(self, server_proof):
        server_proof = _as_bytes(server_proof)
        if self.expected_server_proof is None:
            raise ACPClientError("SRP server proof received before client proof")
        if not hmac.compare_digest(server_proof, self.expected_server_proof):
            raise ACPClientError("SRP server proof verification failed")
        return True

    def close(self):
        self.username = None
        self.password = None
        self.private_key = None
        self.premaster_secret = None
        self.session_key = None
        self.client_public_key = None
        self.server_public_key = None
        self.client_proof = None
        self.expected_server_proof = None
