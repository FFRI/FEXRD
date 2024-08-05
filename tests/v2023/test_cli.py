#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#
from typer.testing import CliRunner
from fexrd.cli import app
import pytest

json_files = [
    "tests/v2023/json/8b287257a36750867bdb3ed23723818588f303d72ebaeb37579f39dddd04edb3.json",
    "tests/v2023/json/8bb088d63d4d529b757a0846b31fab9e82ac7b7835a71dd68a95324fea467c44.json",
    "tests/v2023/json/cf38bcb2e6289b8a56f857fb494fccfb07163a53f0b5d77d722d35380af7ebc5.json",
]

extractors = [
    "lief",
    "dos_header",
    "rich_header",
    "header",
    "optional_header",
    "data_directories",
    "sections",
    "relocations",
    "tls",
    "export",
    # "debug",
    "imports",
    "resources_tree",
    "resources_manager",
    "signatures",
    "load_configuration",
    "peid",
    "trid",
    "strings",
    "all",
    "die",
    "manalyze_plugin_packer",
]

runner = CliRunner()


@pytest.mark.parametrize("json", json_files)
@pytest.mark.parametrize("extractor", extractors)
def test_vec(json, extractor):  # type: ignore
    result = runner.invoke(app, ["show-vec", json, "v2023", extractor])
    assert result.exit_code == 0


@pytest.mark.parametrize("json", json_files)
@pytest.mark.parametrize("extractor", extractors)
def test_dict(json, extractor):  # type: ignore
    result = runner.invoke(app, ["show-raw-dict", json, "v2023", extractor])
    assert result.exit_code == 0
