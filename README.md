# AirPyrt Tools

AirPyrt Tools is a Python package and `acp` command-line tool for working with
Apple AirPort ACP properties and basebinary firmware files.

The project has been ported from Python 2 to modern Python 3. The current test
suite covers the core protocol bytes/text boundaries, message headers, property
packing, CFL binary plist parsing/composition, basebinary parsing, encryption
vectors, sessions, and the CLI dispatcher.


## Requirements

- Python 3.11 or newer
- Tested on Python 3.11 through 3.14
- `pycryptodomex`


## Installation

From a checkout, install the CLI into an isolated environment with `pipx`:

```bash
pipx install .
```

You can also install into the active Python environment:

```bash
python -m pip install .
```

For local development:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```


## Development

Useful verification commands:

```bash
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


## Usage

The installed console script is `acp`:

```bash
acp --help
```

The module entrypoint is equivalent:

```bash
python -m acp --help
```

Common examples:

```bash
acp --listprop
acp --helpprop syNm
acp --getprop syNm --target 10.0.1.1 --password "$AIRPORT_PASSWORD"
acp --setprop syNm "Office Router" --target 10.0.1.1 --password "$AIRPORT_PASSWORD"
acp --decrypt firmware.bin decrypted.bin
acp --extract decrypted.bin rootfs.img
```

Commands return a nonzero status and print `error: ...` to stderr when arguments,
router replies, sockets, or input files fail validation. Add `--verbose` to enable
debug logging while investigating failures.


## Security

Remote router commands currently use the old ACP authentication scheme. That
scheme puts the admin password on the wire in a trivially recoverable form. Treat
remote administration with this tool as unsafe on untrusted networks, and avoid
using it across any network path you do not control.

SRP/protocol v2 authentication and full session encryption are not implemented.
The old AppleSRP ctypes experiment depends on Apple's private macOS AppleSRP
framework and is not a supported user feature.


## Known Limitations

- ACP protocol v2 and portable SRP authentication are not supported.
- Encrypted property elements are not supported.
- Basebinary repacking and reencryption are not supported.
- Bonjour discovery is not implemented.
- Some property metadata is incomplete or inferred from old protocol research.
- Return value `0xfffffff6` from `--getprop` means the property is not available
  or is not readable on that device.


## License

See [LICENSE](LICENSE).
