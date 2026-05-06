import io
import logging

import pytest

from acp import cli
from acp.exception import ACPClientError
from acp.property import ACPProperty


class FakeClient:
    def __init__(self, target="target", password="password", fail_get=False):
        self.target = target
        self.password = password
        self.props = None
        self.connected = False
        self.closed = False
        self.fail_get = fail_get

    def set_properties(self, props):
        self.props = props

    def get_properties(self, names):
        if self.fail_get:
            raise ACPClientError("router rejected request")
        assert names == ["prop"]
        return [ACPProperty("prop", "abcdwxyz")]

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True


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


def test_run_help_hides_experimental_srp_command():
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = cli.run(["--help"], stdout=stdout, stderr=stderr)

    assert status == 0
    assert "--srp-test" not in stdout.getvalue()


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
