import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_pyproject():
    with (ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)


def test_project_metadata_defines_package_and_cli_entrypoint():
    pyproject = load_pyproject()

    assert pyproject["project"]["name"] == "acp"
    assert pyproject["project"]["requires-python"] == ">=3.11"
    assert pyproject["project"]["scripts"]["acp"] == "acp.cli:main"


def test_setuptools_package_discovery_includes_subpackages():
    pyproject = load_pyproject()

    assert pyproject["tool"]["setuptools"]["packages"]["find"]["include"] == ["acp", "acp.*"]
