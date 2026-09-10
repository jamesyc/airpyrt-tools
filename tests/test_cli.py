import gzip
import io
import logging

import pytest
from helpers import make_basebinary_blob

from acp import cli
from acp.exception import ACPClientError, ACPCommandLineError
from acp.property import ACPProperty


class FakeClient:
    def __init__(self, target="target", password="password", props=None, fail_get=False):
        self.target = target
        self.password = password
        self.props = None
        self.props_store = {"prop": "abcdwxyz"} if props is None else props
        self.connected = False
        self.closed = False
        self.fail_get = fail_get
        self.srp_authenticated = False

    def set_properties(self, props):
        self.props = props

    def get_properties(self, names):
        if self.fail_get:
            raise ACPClientError("router rejected request")
        return [ACPProperty(name, self.props_store[name]) for name in names]

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True

    def authenticate_srp(self):
        self.srp_authenticated = True

    def get_features(self):
        return {"feature": True}


class FakeClientFactory:
    def __init__(self, *, fail_get=False):
        self.fail_get = fail_get
        self.clients = []

    def __call__(self, target, password=""):
        client = FakeClient(target, password, fail_get=self.fail_get)
        self.clients.append(client)
        return client


def test_cmd_setprop_converts_bin_hex_input_to_bytes():
    client = FakeClient()

    cli._cmd_setprop(client, ["diag", "deadbeef"])

    assert client.props["diag"].value == b"\xde\xad\xbe\xef"


def test_cmd_acpprop_prints_four_character_property_chunks(capsys):
    cli._cmd_acpprop(FakeClient(), None)

    assert capsys.readouterr().out == "abcd\nwxyz\n"


def test_run_listprop_returns_success_and_prints_supported_properties():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--listprop"], stdout=stdout, stderr=stderr)

    assert status == 0
    assert "Supported properties" in stdout.getvalue()
    assert "syNm: Device name" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_run_requires_exactly_one_command():
    stdout = io.StringIO()
    stderr = io.StringIO()

    assert cli.run([], stdout=stdout, stderr=stderr) == 1
    assert "must specify a command" in stderr.getvalue()

    stderr = io.StringIO()
    assert cli.run(["--listprop", "--helpprop", "syNm"], stdout=stdout, stderr=stderr) == 1
    assert "multiple commands" in stderr.getvalue()


def test_run_requires_remote_admin_target_and_password():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--getprop", "syNm", "-t", "router"], stdout=stdout, stderr=stderr)

    assert status == 1
    assert "must specify a target and administrator password" in stderr.getvalue()


def test_run_uses_legacy_auth_mode_by_default():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--acpprop", "-t", "router", "-p", "password"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert factory.clients[0].srp_authenticated is False


def test_run_srp_auth_mode_authenticates_before_remote_command():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--acpprop", "-t", "router", "-p", "password", "--auth-mode", "srp"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert factory.clients[0].srp_authenticated is True
    assert stdout.getvalue() == "abcd\nwxyz\n"


def test_run_srp_auth_mode_requires_admin_password():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(
        ["--do-feat-command", "-t", "router", "--auth-mode", "srp"],
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert "must specify a target and administrator password" in stderr.getvalue()


def test_run_legacy_noauth_command_requires_only_target():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--do-feat-command", "-t", "router"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert factory.clients[0].target == "router"
    assert factory.clients[0].password == ""
    assert stdout.getvalue() == "{'feature': True}\n"


def test_run_closes_remote_client_when_handler_raises():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory(fail_get=True)

    status = cli.run(
        ["--getprop", "prop", "-t", "router", "-p", "password"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert "router rejected request" in stderr.getvalue()
    assert factory.clients[0].connected is True
    assert factory.clients[0].closed is True


def test_run_rejects_invalid_setprop_value_without_sending():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--setprop", "LEDc", "not-an-int", "-t", "router", "-p", "password"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert "value for \"LEDc\" must be an integer" in stderr.getvalue()
    assert factory.clients[0].props is None
    assert factory.clients[0].closed is True


def test_run_parser_errors_return_argparse_status_code():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--helpprop"], stdout=stdout, stderr=stderr)

    assert status == 2
    assert "expected 1 argument" in stderr.getvalue()


def test_run_help_shows_metavars_for_short_and_long_options():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--help"], stdout=stdout, stderr=stderr)

    assert status == 0
    assert "-t address, --target address" in stdout.getvalue()
    assert "-p password, --password password" in stdout.getvalue()
    assert "--auth-mode {legacy,srp}" in stdout.getvalue()


def test_run_reconfigures_logging_for_each_stderr_stream(monkeypatch):
    def handler(unused):
        logging.warning("handler warning")

    monkeypatch.setitem(cli.COMMANDS, "listprop", (cli.LOCAL, handler))
    stdout = io.StringIO()
    first_stderr = io.StringIO()
    second_stderr = io.StringIO()

    assert cli.run(["--listprop"], stdout=stdout, stderr=first_stderr) == 0
    assert cli.run(["--listprop"], stdout=stdout, stderr=second_stderr) == 0

    assert first_stderr.getvalue() == "WARNING:handler warning\n"
    assert second_stderr.getvalue() == "WARNING:handler warning\n"


def test_main_exits_with_run_status(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda argv=None: 7)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--listprop"])

    assert excinfo.value.code == 7


def test_run_decrypt_writes_parsed_inner_bytes(tmp_path):
    inpath = tmp_path / "in.bin"
    outpath = tmp_path / "out.bin"
    inpath.write_bytes(make_basebinary_blob(b"abc"))
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--decrypt", str(inpath), str(outpath)], stdout=stdout, stderr=stderr)

    assert status == 0
    assert outpath.read_bytes() == b"abc"


def test_run_extract_writes_decompressed_payload(tmp_path):
    inpath = tmp_path / "in.bin"
    outpath = tmp_path / "out.bin"
    inpath.write_bytes(b"prefix" + gzip.compress(b"hello"))
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--extract", str(inpath), str(outpath)], stdout=stdout, stderr=stderr)

    assert status == 0
    assert outpath.read_bytes() == b"hello"


def test_run_decrypt_missing_input_reports_error(tmp_path):
    outpath = tmp_path / "out.bin"
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(
        ["--decrypt", str(tmp_path / "missing.bin"), str(outpath)],
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert "error:" in stderr.getvalue()
    assert not outpath.exists()


def test_run_rejects_invalid_hex_setprop_value_without_sending():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--setprop", "dbug", "not-hex", "-t", "router", "-p", "password"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert 'value for "dbug" must be a hexadecimal integer' in stderr.getvalue()
    assert factory.clients[0].props is None
    assert factory.clients[0].closed is True


def test_run_rejects_invalid_bin_setprop_value_without_sending():
    stdout = io.StringIO()
    stderr = io.StringIO()
    factory = FakeClientFactory()

    status = cli.run(
        ["--setprop", "diag", "not hex!!", "-t", "router", "-p", "password"],
        client_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 1
    assert 'value for "diag" must be hexadecimal bytes' in stderr.getvalue()
    assert factory.clients[0].props is None
    assert factory.clients[0].closed is True


def test_run_rejects_unknown_helpprop_property():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--helpprop", "nope"], stdout=stdout, stderr=stderr)

    assert status == 1
    assert "unknown property: nope" in stderr.getvalue()


def test_cmd_reboot_sends_reboot_flag():
    client = FakeClient()

    cli._cmd_reboot(client, None)

    assert list(client.props) == ["acRB"]
    assert client.props["acRB"].value == 0


def test_cmd_factory_reset_sends_ordered_reset_flags():
    client = FakeClient()

    cli._cmd_factory_reset(client, None)

    assert list(client.props) == ["acRF", "acRB"]
    assert [prop.value for prop in client.props.values()] == [0, 0]


def test_validate_remote_credentials_rejects_unknown_command_type():
    with pytest.raises(ACPCommandLineError, match="unknown command type"):
        cli._validate_remote_credentials("bogus", "router", "password", cli.AUTH_LEGACY)


def test_validate_remote_credentials_noauth_requires_target_only():
    cli._validate_remote_credentials(cli.REMOTE_NOAUTH, "router", None, cli.AUTH_LEGACY)

    with pytest.raises(ACPCommandLineError, match="must specify a target"):
        cli._validate_remote_credentials(cli.REMOTE_NOAUTH, None, None, cli.AUTH_LEGACY)


def test_cmd_not_implemented_raises():
    with pytest.raises(ACPCommandLineError, match="not implemented"):
        cli._cmd_not_implemented()


def test_system_exit_code_none_is_zero():
    assert cli._system_exit_code(SystemExit(None)) == 0
