from acp.encryption import ACPEncryption, PBKDF_salt0, PBKDF_salt1


def test_pbkdf_salts_are_bytes():
    assert PBKDF_salt0 == bytes.fromhex("F072FA3F66B410A135FAE8E6D1D43D5F")
    assert PBKDF_salt1 == bytes.fromhex("BD0682C9FE79325BC73655F4174B996C")


def test_client_encryption_round_trips_with_fresh_contexts():
    key = b"k" * 16
    client_iv = bytes(range(16))
    server_iv = bytes(range(16, 32))

    encrypted = ACPEncryption(key, client_iv, server_iv).client_encrypt(b"payload")

    assert ACPEncryption(key, client_iv, server_iv).client_decrypt(encrypted) == b"payload"


def test_server_encryption_round_trips_with_fresh_contexts():
    key = b"k" * 16
    client_iv = bytes(range(16))
    server_iv = bytes(range(16, 32))

    encrypted = ACPEncryption(key, client_iv, server_iv).server_encrypt(b"payload")

    assert ACPEncryption(key, client_iv, server_iv).server_decrypt(encrypted) == b"payload"
