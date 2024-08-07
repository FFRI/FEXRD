#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#

import csv
import glob
import json
import os
from pathlib import Path
from typing import List, Optional

import pytest

from fexrd import RelocationsFeatureExtractor

target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*", "*.json")
)


def get_ver_str(path: str) -> str:
    return path.split("/")[-2]


def make_feature_extractor(
    ver_str: str,
) -> Optional[RelocationsFeatureExtractor]:
    return RelocationsFeatureExtractor(ver_str)


@pytest.mark.parametrize("test_json", target_test_json)
def test_get_features(test_json: str, datadir: Path) -> None:
    ver_str = get_ver_str(test_json)
    feature_extractor = make_feature_extractor(ver_str)
    if feature_extractor is None:
        return

    ref_data: str = str(datadir / f"{os.path.splitext(test_json)[0]}_ref_feature.csv")
    with open(ref_data, "r") as fin:
        reader = csv.reader(fin)
        columns_ref: List[str] = next(reader)
        feature_vector_ref: List[float] = [float(i) for i in next(reader)]

    with open(str(datadir / test_json), "r") as fin:
        obj = json.loads(fin.read())
    columns, feature_vector = feature_extractor.get_features(obj["lief"])

    assert columns == columns_ref
    assert list(feature_vector) == pytest.approx(feature_vector_ref)


@pytest.mark.parametrize("test_json", target_test_json)
def test_extract_raw_features(test_json: str, datadir: Path) -> None:
    ver_str = get_ver_str(test_json)
    feature_extractor = make_feature_extractor(ver_str)
    if feature_extractor is None:
        return

    ref_data: str = str(datadir / f"{os.path.splitext(test_json)[0]}_ref_raw.txt")
    with open(ref_data, "r") as fin:
        obj_ref = json.loads(fin.read())
    obj_ref["flattened_entries"] = dict(obj_ref["flattened_entries"])

    with open(str(datadir / test_json), "r") as fin:
        obj = json.loads(fin.read())
    raw_features = feature_extractor.extract_raw_features(obj["lief"])
    raw_features["flattened_entries"] = dict(raw_features["flattened_entries"])

    assert raw_features == obj_ref
