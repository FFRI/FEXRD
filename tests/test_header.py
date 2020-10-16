"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2020
"""

import csv
import glob
import json
import os
from pathlib import Path
from typing import List

import pytest

from fexrd import HeaderFeatureExtractor

target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.json")
)


@pytest.fixture
def feature_extractor() -> HeaderFeatureExtractor:
    return HeaderFeatureExtractor()


@pytest.mark.parametrize("test_json", target_test_json)
def test_get_features(
    feature_extractor: HeaderFeatureExtractor, test_json: str, datadir: Path
) -> None:
    ref_data: str = str(
        datadir / f"{os.path.splitext(test_json)[0]}_ref_features.csv"
    )
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
def test_extract_raw_features(
    feature_extractor: HeaderFeatureExtractor, test_json: str, datadir: Path
) -> None:
    ref_data: str = str(
        datadir / f"{os.path.splitext(test_json)[0]}_ref_raw.txt"
    )
    with open(ref_data, "r") as fin:
        obj_ref = json.loads(fin.read())

    with open(str(datadir / test_json), "r") as fin:
        obj = json.loads(fin.read())
    raw_features = feature_extractor.extract_raw_features(obj["lief"])

    assert raw_features == obj_ref
