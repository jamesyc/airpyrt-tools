from acp import cli
from acp.property import ACPProperty


class FakeClient:
    def __init__(self):
        self.props = None

    def set_properties(self, props):
        self.props = props

    def get_properties(self, names):
        assert names == ["prop"]
        return [ACPProperty("prop", "abcdwxyz")]


def test_cmd_setprop_converts_bin_hex_input_to_bytes():
    client = FakeClient()

    cli._cmd_setprop(client, ["diag", "deadbeef"])

    assert client.props["diag"].value == b"\xde\xad\xbe\xef"


def test_cmd_acpprop_prints_four_character_property_chunks(capsys):
    cli._cmd_acpprop(FakeClient(), None)

    assert capsys.readouterr().out == "abcd\nwxyz\n\n"
