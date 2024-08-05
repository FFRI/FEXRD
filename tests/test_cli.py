#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#
import glob
import json
import os
from io import StringIO
from pathlib import Path
from typing import List

import pandas as pd
import pytest
from typer.testing import CliRunner

from fexrd.cli import app

runner = CliRunner()


target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*", "*.json")
)


def get_ver_str(path: str) -> str:
    return path.split("/")[-2]


def get_ver_number(s: str) -> int:
    return int(s[1:])


def get_available_feature_names(ver: str) -> List[str]:
    feature_names = [
        "all",
        "data_directories",
        # "debug", # debug is currently not supported
        "dos_header",
        "export",
        "header",
        "imports",
        "lief",
        "load_configuration",
        "optional_header",
        "peid",
        "relocations",
        "resources_manager",
        "resources_tree",
        "rich_header",
        "sections",
        "signature" if ver == "v2020" else "signatures",
        "strings",
        "tls",
        "trid",
        "symbols",
        "dummy",
    ]
    if get_ver_number(ver) >= 2021:
        feature_names.append("die")
        feature_names.append("manalyze_plugin_packer")

    return feature_names


@pytest.mark.parametrize("test_json", target_test_json)
def test_show_dict(test_json: str, datadir: Path) -> None:
    ver_str = get_ver_str(test_json)

    for feature_name in get_available_feature_names(ver_str):
        ref_data: Path = (
            datadir / f"{os.path.splitext(test_json)[0]}_{feature_name}_ref_raw.txt"
        )
        result = runner.invoke(app, ["show-raw-dict", test_json, ver_str, feature_name])
        if feature_name == "dummy":
            assert f"feature name: {feature_name} is not found" in result.stdout
            return

        if not ref_data.exists():
            assert (
                f"key ({feature_name}) does not exist" in result.stdout
                or f"feature name: {feature_name} is not found" in result.stdout
            )
        else:
            with open(ref_data, "r") as fin:
                reference = json.loads(fin.read())
            assert json.loads(result.stdout) == reference


@pytest.mark.parametrize("test_json", target_test_json)
def test_show_vec(test_json: str, datadir: Path) -> None:
    ver_str = get_ver_str(test_json)

    for feature_name in get_available_feature_names(ver_str):
        ref_data_path: Path = (
            datadir / f"{os.path.splitext(test_json)[0]}_{feature_name}_ref_feature.csv"
        )
        result = runner.invoke(app, ["show-vec", test_json, ver_str, feature_name])
        if feature_name == "dummy":
            assert f"feature name: {feature_name} is not found" in result.stdout
            return

        if not ref_data_path.exists():
            assert (
                f"key ({feature_name}) does not exist" in result.stdout
                or f"feature name: {feature_name} is not found" in result.stdout
            )
        else:
            assert pd.read_csv(ref_data_path).equals(
                pd.read_csv(StringIO(result.stdout))
            )
