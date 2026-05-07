# Python 3.9 Support Plan

## Goal

Add best-effort Python 3.9 support for users on systems that still ship Python
3.9, while keeping the current Python 3.11-3.14 behavior unchanged.

Python 3.9 reached upstream end-of-life on October 31, 2025, so this should be
documented as compatibility support rather than a security recommendation. Users
who can install a newer Python should still prefer the currently supported
Python releases. Source: https://devguide.python.org/versions/

## Current Findings

- The package source and tests parse with Python 3.9 grammar.
- The project metadata currently declares `requires-python = ">=3.11"`.
- The CI matrix currently tests Python 3.11, 3.12, 3.13, and 3.14.
- Ruff is configured with `target-version = "py311"`.
- README currently says Python 3.11 or newer.
- `tests/test_project_metadata.py` imports `tomllib`, which is available in the
  standard library starting in Python 3.11. Python 3.9 needs `tomli` as a test
  dependency or a compatibility fallback.
- Test-only use of `bytes.removeprefix()` is compatible with Python 3.9.

## Proposed Changes

1. Add Python 3.9 to supported metadata.
   - Change `requires-python` from `>=3.11` to `>=3.9`.
   - Add Python 3.9 and 3.10 classifiers.
   - Update metadata tests to expect the new support floor.

2. Update CI.
   - Add Python 3.9 and 3.10 to the GitHub Actions matrix.
   - Keep packaging and Twine checks on one representative version.
   - Run the existing test suite on every supported version.

3. Update Ruff configuration.
   - Change `target-version` from `py311` to `py39`.
   - Keep the current narrow lint target: `acp/cli.py acp/srp.py setup.py tests`.
   - Fix any resulting lint findings without broad refactors.

4. Add test-time TOML compatibility.
   - Prefer stdlib `tomllib` when available.
   - Fall back to `tomli` on Python 3.9 and 3.10.
   - Add `tomli` to the `dev` extra with a version marker:
     `tomli>=2; python_version < "3.11"`.

5. Update README.
   - Change prerequisites to Python 3.9 or newer.
   - Document that Python 3.9 is compatibility support for older platforms and
     is upstream EOL.
   - Keep Python 3.11+ as the recommended runtime where practical.

6. Validate install and packaging behavior.
   - Build sdist and wheel.
   - Install the wheel in a Python 3.9 virtualenv.
   - Run `acp --help` and `pip check` from the installed wheel.

## Acceptance Criteria

- `python -m pytest` passes on Python 3.9, 3.10, 3.11, 3.12, 3.13, and 3.14.
- `python -m ruff check acp/cli.py acp/srp.py setup.py tests` passes with
  `target-version = "py39"`.
- `python -m compileall -q acp` passes.
- `python -m build` and `python -m twine check dist/*` pass.
- A wheel installs cleanly on Python 3.9.
- Installed `acp --help` works on Python 3.9.
- `python -m pip check` passes after wheel installation.
- README, `pyproject.toml`, and CI agree on the supported Python range.

## Non-Goals

- Do not support Python 3.8 or older.
- Do not revive Python 2 compatibility.
- Do not broaden the Ruff cleanup beyond the existing cleaned surfaces.
- Do not change SRP, encryption, or ACP wire behavior except to fix a Python 3.9
  compatibility bug found by tests.
- Do not add platform-specific macOS behavior; Python 3.9 support should remain
  Linux-clean.

## Suggested Commit Structure

1. `Add Python 3.9 metadata and TOML test fallback`
2. `Run CI across Python 3.9 through 3.14`
3. `Document Python 3.9 compatibility support`
