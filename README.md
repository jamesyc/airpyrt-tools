# AirPyrt Tools

### License

See LICENSE


### Requirements

- Python 3.9 or newer
- Tested on Python 3.9 through 3.14
- pycryptodomex

Python 3.9 support is for compatibility with older platforms. Python 3.9 is
upstream end-of-life, so use Python 3.11 or newer when practical.


### Installation

`pipx install .`

`python -m pip install .`

For local development:

```
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```


### Usage

`acp`

`python -m acp`

`python -m acp --help`

    usage: acp [-h] [-t address] [-p password] [-v] [--auth-mode {legacy,srp}]
               [--listprop] [--helpprop property] [--getprop property]
               [--setprop property value] [--dumpprop] [--acpprop] [--dump-syslog]
               [--reboot] [--factory-reset] [--flash-primary firmware_path]
               [--do-feat-command] [--decrypt inpath outpath]
               [--extract inpath outpath]

    options:
      -h, --help            show this help message and exit

    AirPort client parameters:
      -t address, --target address
                            IP address or hostname of the target router
      -p password, --password password
                            router admin password
      -v, --verbose         enable debug logging
      --auth-mode {legacy,srp}
                            remote authentication mode

    AirPort client commands:
      --listprop            list supported properties
      --helpprop property   print the description of the specified property
      --getprop property    get the value of the specified property
      --setprop property value
                            set the value of the specified property
      --dumpprop            dump values of all supported properties
      --acpprop             get acp acpprop list
      --dump-syslog         dump the router system log
      --reboot              reboot device
      --factory-reset       RESET EVERYTHING and reboot; you have been warned!
      --flash-primary firmware_path
                            flash primary partition firmware
      --do-feat-command     send 0x1b (feat) command

    Basebinary commands:
      --decrypt inpath outpath
                            decrypt the basebinary
      --extract inpath outpath
                            extract the gzimg contents

### Examples

List supported property names:

```
acp --listprop
```

Inspect a supported property:

```
acp --helpprop syNm
```

Read or set a router property:

```
acp --getprop syNm --target 10.0.1.1 --password "$AIRPORT_PASSWORD"
acp --setprop syNm "Office Router" --target 10.0.1.1 --password "$AIRPORT_PASSWORD"
```

Use portable SRP/protocol v2 authentication for normal remote commands:

```
acp --auth-mode srp --getprop syNm --target 10.0.1.1 --password "$AIRPORT_PASSWORD"
```

Work with basebinary firmware files:

```
acp --decrypt firmware.bin decrypted.bin
acp --extract decrypted.bin rootfs.img
```

Commands return a nonzero status and print `error: ...` to stderr when arguments,
router replies, sockets, or input files fail validation. Add `--verbose` to enable
debug logging while investigating failures.


### Development

```
python -m pytest
python -m coverage run -m pytest
python -m coverage report
python -m ruff check acp setup.py tests
python -m compileall -q acp
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
python -m pip check
```

The ruff target covers the package, packaging shim, and tests.


### Notes

**IMPORTANT**

The default remote authentication mode still uses the old ACP protocol
implementation, which puts the admin password of the device over the wire in a
trivially recoverable format. Use `--auth-mode srp` to authenticate with
portable SRP/protocol v2 and enable full-session encryption before running the
selected remote command. Treat the legacy mode as unsafe on untrusted networks.

The original project grew organically out of the author's understanding of various
pieces of the ACP protocol. It was restructured a few times as that understanding
improved, but there are still gaps in the implementation and some code smell.
This fork keeps that exploratory history intact while modernizing the package for
current Python 3.

Return value of 0xfffffff6 when using --getprop means the property is not
available/readable.

## TODO (very incomplete list in no particular order)

- add IP address type for properties, make sure it supports IPv4 and IPv6
- specify RO/WO/RW attribute for properties
- exception handling:
  - audit malformed struct/protocol field coverage
  - improve error messages for unsupported device replies
- improve logging structure and message consistency
- review and update docstrings
- broaden SRP/protocol v2 device coverage beyond the current Time Capsule tests
- basebinary repacking/reencryption
- basebinary rootfs mounting
- threaded server
- handle protocol v1 (for old firmwares/devices)
- bonjour announcement/discovery
- ACPMonitorSession support
- ACPRPC support
