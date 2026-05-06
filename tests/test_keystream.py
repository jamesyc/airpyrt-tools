from acp.keystream import ACP_STATIC_KEY, generate_acp_keystream


def test_static_key_is_bytes():
    assert ACP_STATIC_KEY == bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")


def test_generate_acp_keystream_returns_expected_bytes(assert_hex):
    assert isinstance(generate_acp_keystream(32), bytes)
    assert_hex(
        generate_acp_keystream(32),
        "0e39f805c401554f0cac857d868ab517"
        "3e09c835f431657f3c9cb56d969aa507",
    )


def test_generate_acp_keystream_can_return_empty_bytes():
    assert generate_acp_keystream(0) == b""
