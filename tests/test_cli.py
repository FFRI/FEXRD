#
# (c) FFRI Security, Inc., 2020 / Author: FFRI Security, Inc.
#
import glob
import json
import os
from io import StringIO
from pathlib import Path
from typing import List

import pandas as pd
import pytest
from fexrd.cli import app
from typer.testing import CliRunner

runner = CliRunner()


target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.json")
)


features: List[str] = [
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
    "signature",
    "strings",
    "tls",
    "trid",
    "dummy",
]


@pytest.mark.parametrize("test_json", target_test_json)
@pytest.mark.parametrize("feature", features)
def test_show_dict(feature: str, test_json: str, datadir: Path) -> None:
    ref_data: Path = (
        datadir / f"{os.path.splitext(test_json)[0]}_{feature}_ref_raw.txt"
    )
    result = runner.invoke(app, ["show-raw-dict", test_json, feature])

    if feature == "dummy":
        assert f"feature name: {feature} is not found" in result.stdout
        return

    if not ref_data.exists():
        assert f"key ({feature}) does not exist" in result.stdout
    else:
        with open(ref_data, "r") as fin:
            reference = json.loads(fin.read())
        print(json.loads(result.stdout))
        print(reference)
        assert json.loads(result.stdout) == reference


@pytest.mark.parametrize("test_json", target_test_json)
@pytest.mark.parametrize("feature", features)
def test_show_vec(feature: str, test_json: str, datadir: Path) -> None:
    ref_data: Path = (
        datadir / f"{os.path.splitext(test_json)[0]}_{feature}_ref_feature.csv"
    )
    result = runner.invoke(app, ["show-vec", test_json, feature])

    if feature == "dummy":
        assert f"feature name: {feature} is not found" in result.stdout
        return

    if not ref_data.exists():
        assert f"key ({feature}) does not exist" in result.stdout
    else:
        assert pd.read_csv(ref_data).equals(
            pd.read_csv(StringIO(result.stdout))
        )
