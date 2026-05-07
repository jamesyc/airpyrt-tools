from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def load_pyproject():
    with (ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)


def test_project_metadata_defines_package_and_cli_entrypoint():
    pyproject = load_pyproject()

    assert pyproject["project"]["name"] == "acp"
    assert pyproject["project"]["requires-python"] == ">=3.9"
    assert pyproject["project"]["scripts"]["acp"] == "acp.cli:main"
    assert "pycryptodomex>=3.20" in pyproject["project"]["dependencies"]
    classifiers = pyproject["project"]["classifiers"]
    assert "Programming Language :: Python :: 3.9" in classifiers
    assert "Programming Language :: Python :: 3.10" in classifiers
    dev_dependencies = pyproject["project"]["optional-dependencies"]["dev"]
    assert "tomli>=2; python_version < '3.11'" in dev_dependencies
    assert "twine>=5.1" in dev_dependencies


def test_setuptools_package_discovery_includes_subpackages():
    pyproject = load_pyproject()

    assert pyproject["tool"]["setuptools"]["packages"]["find"]["include"] == ["acp", "acp.*"]
