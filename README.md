# AirPyrt Tools

### License

See LICENSE


### Requirements

- Python 3.11 or newer
- Tested on Python 3.11 through 3.14
- pycryptodomex


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

    usage: acp [-h] [-t address] [-p password] [-v] [--listprop]
               [--helpprop property] [--getprop property]
               [--setprop property value] [--dumpprop] [--acpprop]
               [--dump-syslog] [--reboot] [--factory-reset]
               [--flash-primary firmware_path] [--do-feat-command]
               [--decrypt inpath outpath] [--extract inpath outpath]
               [--srp-test]

    options:
      -h, --help            show this help message and exit

    AirPort client parameters:
      -t, --target address  IP address or hostname of the target router
      -p, --password password
                            router admin password
      -v, --verbose         enable debug logging

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

    Test arguments:
      --srp-test            SRP (requires OS X)


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
python -m ruff check acp/cli.py setup.py tests
python -m compileall -q acp
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
python -m pip check
```

The current ruff target covers the package entrypoint, packaging shim, and tests.
The older protocol modules still need a separate whole-package lint cleanup pass.


### Notes

**IMPORTANT**

This still uses the old ACP protocol implementation, which puts the admin password
of the device over the wire in a trivially recoverable format. The newer protocol
uses SRP authentication and better encryption of requests to/from the device.
Until SRP/protocol v2 authentication and full session encryption are implemented,
remote administration with this tool should be treated as unsafe on untrusted
networks.

The original project grew organically out of the author's understanding of various
pieces of the ACP protocol. It was restructured a few times as that understanding
improved, but there are still gaps in the implementation and some code smell.
This fork keeps that exploratory history intact while modernizing the package for
current Python 3.

Return value of 0xfffffff6 when using --getprop means the property is not
available/readable.

The AppleSRP ctypes path is experimental and depends on Apple's private macOS
AppleSRP framework. It remains available through --srp-test for protocol
experiments; portable SRP support is still future work.

SRP/protocol v2 authentication and full session encryption are not implemented.


## TODO (very incomplete list in no particular order)

- add IP address type for properties, make sure it supports IPv4 and IPv6
- specify RO/WO/RW attribute for properties
- exception handling:
  - invalid struct fields aren't handled well in many cases
  - finish adding custom exception classes and make sure we're using them
- logging (mostly done, still looks horrible) with verbosity controls
- review and update docstrings
- SRP support (fix pysrp because ctypes hax, while fun, are horrible and non-portable)
- ACP protocol version 2 (full session encryption)
- handle encrypted property elements
- basebinary repacking/reencryption
- basebinary rootfs mounting
- threaded server
- handle protocol v1 (for old firmwares/devices)
- bonjour announcement/discovery
- options to specify no encryption, old method, and new (SRP) method
- ACPMonitorSession support
- ACPRPC support
