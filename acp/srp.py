import importlib
import logging

from .exception import ACPClientError


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("expected str or bytes")


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
