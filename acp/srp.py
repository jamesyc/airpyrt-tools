import hashlib
import hmac
import importlib
import logging
import secrets

from .exception import ACPClientError


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
    return bytes(
        left_byte ^ right_byte for left_byte, right_byte in zip(left, right, strict=True)
    )


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
    # AppleSRP's Stanford-derived SRP6a backend returns RFC2945_KEY_LEN bytes here.
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


def _load_applesrp_modules():
    try:
        ctypes = importlib.import_module("ctypes")
        apple_srp = importlib.import_module("acp.clibs.AppleSRP")
    except (ImportError, OSError, AttributeError) as e:
        raise ACPClientError(
            "AppleSRP authentication is unavailable on this system; "
            "Apple's private macOS AppleSRP framework is required"
        ) from e
    return ctypes, apple_srp


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
        if g <= 1:
            raise ACPClientError("SRP generator must be greater than one")
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
        exponent = private_key + scrambling_parameter * x
        premaster_secret_int = pow(base, exponent, n)
        premaster_secret = _int_to_bytes(premaster_secret_int)
        session_key = _mgf1_sha1(premaster_secret, 40)

        client_public_key = _int_to_bytes(client_public_key_int)
        client_proof = _client_proof(
            self.username,
            modulus_bytes,
            generator_bytes,
            salt,
            client_public_key,
            server_public_key_bytes,
            session_key,
        )

        self.premaster_secret = _pad_int(premaster_secret_int, modulus_size)
        self.session_key = session_key
        self.client_public_key = client_public_key
        self.server_public_key = server_public_key_bytes
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
        return None


class AppleSRPClient:
    def __init__(self, username, password, ctypes_module=None, apple_srp_module=None):
        if ctypes_module is None or apple_srp_module is None:
            ctypes_module, apple_srp_module = _load_applesrp_modules()
        self.ctypes = ctypes_module
        self.apple_srp = apple_srp_module
        self.username = _as_bytes(username)
        self.password = _as_bytes(password)
        self.context = None
        self.client_public_key_ptr = None
        self.session_key_ptr = None
        self.client_proof_ptr = None

    def _log_result(self, name, value):
        logging.debug("%s: %s", name, value)
        return value

    def process_challenge(self, modulus, generator, salt, server_public_key):
        modulus = _as_bytes(modulus)
        generator = _as_bytes(generator)
        salt = _as_bytes(salt)
        server_public_key = _as_bytes(server_public_key)

        self.context = self.apple_srp.SRP_new(self.apple_srp.SRP6a_client_method())
        self._log_result(
            "SRP_set_username",
            self.apple_srp.SRP_set_username(self.context, self.username),
        )
        self._log_result(
            "SRP_set_params",
            self.apple_srp.SRP_set_params(
                self.context,
                modulus,
                len(modulus),
                generator,
                len(generator),
                salt,
                len(salt),
            ),
        )

        self.client_public_key_ptr = self.apple_srp.cstr_new()
        self._log_result(
            "SRP_gen_pub",
            self.apple_srp.SRP_gen_pub(
                self.context,
                self.ctypes.byref(self.client_public_key_ptr),
            ),
        )
        client_public_key = self.client_public_key_ptr.contents.get_data_buffer()

        self._log_result(
            "SRP_set_auth_password",
            self.apple_srp.SRP_set_auth_password(
                self.context,
                self.password,
                len(self.password),
            ),
        )

        self.session_key_ptr = self.apple_srp.cstr_new()
        self._log_result(
            "SRP_compute_key",
            self.apple_srp.SRP_compute_key(
                self.context,
                self.ctypes.byref(self.session_key_ptr),
                server_public_key,
                len(server_public_key),
            ),
        )
        session_key = self.session_key_ptr.contents.get_data_buffer()

        self.client_proof_ptr = self.apple_srp.cstr_new()
        self._log_result(
            "SRP_respond",
            self.apple_srp.SRP_respond(
                self.context,
                self.ctypes.byref(self.client_proof_ptr),
            ),
        )
        client_proof = self.client_proof_ptr.contents.get_data_buffer()

        return client_public_key, client_proof, session_key

    def verify_server_proof(self, server_proof):
        server_proof = _as_bytes(server_proof)
        return self._log_result(
            "SRP_verify",
            self.apple_srp.SRP_verify(self.context, server_proof, len(server_proof)),
        )

    def close(self):
        for ptr in [
            self.client_public_key_ptr,
            self.session_key_ptr,
            self.client_proof_ptr,
        ]:
            if ptr is not None:
                self.apple_srp.cstr_free(ptr)
        if self.context is not None:
            self._log_result("SRP_free", self.apple_srp.SRP_free(self.context))
