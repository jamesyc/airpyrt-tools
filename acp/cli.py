import argparse
import logging
import sys
from collections import OrderedDict
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from .basebinary import Basebinary, BasebinaryError
from .client import ACPClient
from .exception import ACPCommandLineError, ACPError
from .property import ACPProperty

LOCAL = "local"
REMOTE_NOAUTH = "remote_noauth"
REMOTE_ADMIN = "remote_admin"
AUTH_LEGACY = "legacy"
AUTH_SRP = "srp"


class _ArgParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, f"error: {message}\n")


class _HelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            (metavar,) = self._metavar_formatter(action, default)(1)
            return metavar

        if action.nargs == 0:
            return ", ".join(action.option_strings)

        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(
            f"{option_string} {args_string}" for option_string in action.option_strings
        )


def _cmd_not_implemented(*unused):
    raise ACPCommandLineError("command handler not implemented")


def _require_property_name(prop_name):
    if prop_name not in ACPProperty.get_supported_property_names():
        raise ACPCommandLineError(f"unknown property: {prop_name}")


def _get_property_info(prop_name, key):
    _require_property_name(prop_name)
    return ACPProperty.get_property_info_string(prop_name, key)


def _cmd_listprop(unused):
    print("\nSupported properties:\n")
    prop_names = ACPProperty.get_supported_property_names()
    for name in prop_names:
        description = ACPProperty.get_property_info_string(name, "description")
        print(f"{name}: {description}")
    print()


def _cmd_helpprop(args):
    prop_name = args[0]
    description = _get_property_info(prop_name, "description")
    prop_type = _get_property_info(prop_name, "type")
    validation = _get_property_info(prop_name, "validation")
    s = f"{description} ({prop_type}"
    if validation:
        s += f", {validation})"
    else:
        s += ")"
    print(s)


def _cmd_getprop(client, args):
    prop_name = args[0]
    _require_property_name(prop_name)
    props = client.get_properties([prop_name])
    if props:
        print(ACPProperty(prop_name, props[0].value))


def _parse_integer_property(prop_name, prop_value):
    try:
        return int(prop_value)
    except ValueError as e:
        raise ACPCommandLineError(
            f"value for \"{prop_name}\" must be an integer"
        ) from e


def _parse_hex_property(prop_name, prop_value):
    try:
        return int(prop_value, 16)
    except ValueError as e:
        raise ACPCommandLineError(
            f"value for \"{prop_name}\" must be a hexadecimal integer"
        ) from e


def _parse_bin_property(prop_name, prop_value):
    try:
        return bytes.fromhex(prop_value)
    except ValueError as e:
        raise ACPCommandLineError(
            f"value for \"{prop_name}\" must be hexadecimal bytes"
        ) from e


def _cmd_setprop(client, args):
    prop_name, prop_value = args
    prop_type = _get_property_info(prop_name, "type")

    if prop_type == "dec":
        prop = ACPProperty(prop_name, _parse_integer_property(prop_name, prop_value))
    elif prop_type == "hex":
        prop = ACPProperty(prop_name, _parse_hex_property(prop_name, prop_value))
    elif prop_type == "mac":
        prop = ACPProperty(prop_name, prop_value)
    elif prop_type == "bin":
        prop = ACPProperty(prop_name, _parse_bin_property(prop_name, prop_value))
    elif prop_type == "str":
        prop = ACPProperty(prop_name, prop_value)
    elif prop_type in ["cfb", "log"]:
        raise ACPCommandLineError(
            f"setting \"{prop_type}\" properties is not supported by this CLI"
        )
    else:
        raise ACPCommandLineError(f"unsupported property type: {prop_type}")

    client.set_properties({prop_name: prop})


def _cmd_dumpprop(client, unused):
    prop_names = ACPProperty.get_supported_property_names()
    properties = client.get_properties(prop_names)
    for prop in properties:
        padded_description = ACPProperty.get_property_info_string(
            prop.name,
            "description",
        ).ljust(32, " ")
        print(f"{padded_description}: {prop}")


def _cmd_acpprop(client, unused):
    props_reply = client.get_properties(["prop"])
    if not props_reply:
        raise ACPCommandLineError("router did not return the acpprop list")
    props_raw = props_reply[0].value
    props = "\n".join(
        props_raw[i * 4 : i * 4 + 4] for i in range(len(props_raw) // 4)
    )
    print(props)


def _cmd_dump_syslog(client, unused):
    props = client.get_properties(["logm"])
    if not props:
        raise ACPCommandLineError("router did not return the system log")
    print(f"{props[0]}")


def _cmd_reboot(client, unused):
    print("Rebooting device")
    client.set_properties({"acRB": ACPProperty("acRB", 0)})


def _cmd_factory_reset(client, unused):
    print("Performing factory reset")
    client.set_properties(
        OrderedDict(
            [
                ("acRF", ACPProperty("acRF", 0)),
                ("acRB", ACPProperty("acRB", 0)),
            ]
        )
    )


def _cmd_flash_primary(client, args):
    fw_path = Path(args[0])
    if not fw_path.is_file():
        raise ACPCommandLineError(f"Basebinary not readable at path: {fw_path}")
    fw_data = fw_path.read_bytes()
    print("Flashing primary firmware partition")
    client.flash_primary(fw_data)


def _cmd_do_feat_command(client, unused):
    print(client.get_features())


def _cmd_decrypt(args):
    inpath, outpath = args
    indata = Path(inpath).read_bytes()
    outdata = Basebinary.parse(indata)
    Path(outpath).write_bytes(outdata)


def _cmd_extract(args):
    inpath, outpath = args
    indata = Path(inpath).read_bytes()
    outdata = Basebinary.extract(indata)
    Path(outpath).write_bytes(outdata)


COMMANDS = {
    "listprop": (LOCAL, _cmd_listprop),
    "helpprop": (LOCAL, _cmd_helpprop),
    "getprop": (REMOTE_ADMIN, _cmd_getprop),
    "setprop": (REMOTE_ADMIN, _cmd_setprop),
    "dumpprop": (REMOTE_ADMIN, _cmd_dumpprop),
    "acpprop": (REMOTE_ADMIN, _cmd_acpprop),
    "dump_syslog": (REMOTE_ADMIN, _cmd_dump_syslog),
    "reboot": (REMOTE_ADMIN, _cmd_reboot),
    "factory_reset": (REMOTE_ADMIN, _cmd_factory_reset),
    "flash_primary": (REMOTE_ADMIN, _cmd_flash_primary),
    "do_feat_command": (REMOTE_NOAUTH, _cmd_do_feat_command),
    "decrypt": (LOCAL, _cmd_decrypt),
    "extract": (LOCAL, _cmd_extract),
}


def build_parser():
    parser = _ArgParser(prog="acp", formatter_class=_HelpFormatter)

    parameters_group = parser.add_argument_group("AirPort client parameters")
    parameters_group.add_argument(
        "-t",
        "--target",
        metavar="address",
        help="IP address or hostname of the target router",
    )
    parameters_group.add_argument(
        "-p",
        "--password",
        metavar="password",
        help="router admin password",
    )
    parameters_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    parameters_group.add_argument(
        "--auth-mode",
        choices=[AUTH_LEGACY, AUTH_SRP],
        default=AUTH_LEGACY,
        help="remote authentication mode",
    )

    airport_client_group = parser.add_argument_group("AirPort client commands")
    airport_client_group.add_argument(
        "--listprop",
        action="store_const",
        const=True,
        help="list supported properties",
    )
    airport_client_group.add_argument(
        "--helpprop",
        metavar="property",
        nargs=1,
        help="print the description of the specified property",
    )
    airport_client_group.add_argument(
        "--getprop",
        metavar="property",
        nargs=1,
        help="get the value of the specified property",
    )
    airport_client_group.add_argument(
        "--setprop",
        metavar=("property", "value"),
        nargs=2,
        help="set the value of the specified property",
    )
    airport_client_group.add_argument(
        "--dumpprop",
        action="store_const",
        const=True,
        help="dump values of all supported properties",
    )
    airport_client_group.add_argument(
        "--acpprop",
        action="store_const",
        const=True,
        help="get acp acpprop list",
    )
    airport_client_group.add_argument(
        "--dump-syslog",
        action="store_const",
        const=True,
        help="dump the router system log",
    )
    airport_client_group.add_argument(
        "--reboot",
        action="store_const",
        const=True,
        help="reboot device",
    )
    airport_client_group.add_argument(
        "--factory-reset",
        action="store_const",
        const=True,
        help="RESET EVERYTHING and reboot; you have been warned!",
    )
    airport_client_group.add_argument(
        "--flash-primary",
        metavar="firmware_path",
        nargs=1,
        help="flash primary partition firmware",
    )
    airport_client_group.add_argument(
        "--do-feat-command",
        action="store_const",
        const=True,
        help="send 0x1b (feat) command",
    )

    basebinary_group = parser.add_argument_group("Basebinary commands")
    basebinary_group.add_argument(
        "--decrypt",
        metavar=("inpath", "outpath"),
        nargs=2,
        help="decrypt the basebinary",
    )
    basebinary_group.add_argument(
        "--extract",
        metavar=("inpath", "outpath"),
        nargs=2,
        help="extract the gzimg contents",
    )

    return parser


def _configure_logging(verbose):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s:%(message)s",
        level=level,
        force=True,
    )


def _selected_commands(args_dict):
    return [
        (name, args_dict[name])
        for name in COMMANDS
        if args_dict.get(name) is not None
    ]


def _run_local(handler, arg):
    handler(arg)


def _remote_requires_admin_password(mode, auth_mode):
    return auth_mode == AUTH_SRP or mode == REMOTE_ADMIN


def _validate_remote_credentials(mode, target, password, auth_mode):
    if mode not in (REMOTE_NOAUTH, REMOTE_ADMIN):
        raise ACPCommandLineError(f"unknown command type: {mode}")

    if _remote_requires_admin_password(mode, auth_mode):
        if target is None or password is None:
            raise ACPCommandLineError("must specify a target and administrator password")
    elif target is None:
        raise ACPCommandLineError("must specify a target")


def _run_remote(handler, arg, mode, target, password, auth_mode, client_factory):
    _validate_remote_credentials(mode, target, password, auth_mode)
    if _remote_requires_admin_password(mode, auth_mode):
        client = client_factory(target, password)
    else:
        client = client_factory(target)

    try:
        client.connect()
        if auth_mode == AUTH_SRP:
            client.authenticate_srp()
        handler(client, arg)
    finally:
        client.close()


def _run_args(args, client_factory):
    args_dict = vars(args)
    command_args = _selected_commands(args_dict)

    if len(command_args) == 0:
        raise ACPCommandLineError("must specify a command")
    if len(command_args) > 1:
        raise ACPCommandLineError("multiple commands not supported, choose only one")

    cmd, arg = command_args[0]
    mode, handler = COMMANDS.get(cmd, (None, _cmd_not_implemented))
    if mode == LOCAL:
        _run_local(handler, arg)
    else:
        _run_remote(
            handler,
            arg,
            mode,
            args.target,
            args.password,
            args.auth_mode,
            client_factory,
        )


def _system_exit_code(exc):
    if exc.code is None:
        return 0
    if isinstance(exc.code, int):
        return exc.code
    return 1


def run(argv=None, client_factory=ACPClient, stdout=None, stderr=None):
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr

    parser = build_parser()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            args = parser.parse_args(argv)
            _configure_logging(args.verbose)
            _run_args(args, client_factory)
    except SystemExit as e:
        return _system_exit_code(e)
    except (ACPError, BasebinaryError, OSError, ValueError) as e:
        print(f"error: {e}", file=stderr)
        return 1

    return 0


def main(argv=None):
    sys.exit(run(argv))
