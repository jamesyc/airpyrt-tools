import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_pyproject():
    with (ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)


def read_project_file(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_project_metadata_defines_package_and_cli_entrypoint():
    pyproject = load_pyproject()

    assert pyproject["project"]["name"] == "acp"
    assert pyproject["project"]["requires-python"] == ">=3.11"
    assert pyproject["project"]["scripts"]["acp"] == "acp.cli:main"
    assert "pycryptodomex>=3.20" in pyproject["project"]["dependencies"]
    assert "twine>=5.1" in pyproject["project"]["optional-dependencies"]["dev"]


def test_setuptools_package_discovery_includes_subpackages():
    pyproject = load_pyproject()

    assert pyproject["tool"]["setuptools"]["packages"]["find"]["include"] == ["acp", "acp.*"]


def test_readme_documents_supported_python_and_release_workflow():
    readme = read_project_file("README.md")

    assert "Python 3.11 through 3.14" in readme
    assert "pipx install ." in readme
    assert "python -m build" in readme
    assert "python -m twine check dist/*" in readme
    assert "python -m acp --help" in readme
    assert "usage: acp [-h] [-t address] [-p password] [-v] [--listprop]" in readme
    assert "--flash-primary firmware_path" in readme
    assert "Basebinary commands:" in readme
    assert (
        "SRP/protocol v2 authentication and full session encryption are not implemented"
        in readme
    )
    assert "--srp-test" not in readme


def test_ci_exercises_supported_python_versions():
    workflow = read_project_file(".github/workflows/ci.yml")

    assert "python-version:" in workflow
    for version in ["3.11", "3.12", "3.13", "3.14"]:
        assert version in workflow
    assert "python -m coverage run -m pytest" in workflow
    assert "python -m build" in workflow
    assert "python -m twine check dist/*" in workflow
