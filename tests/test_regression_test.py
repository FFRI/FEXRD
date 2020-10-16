"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2020
"""

import glob
import json
import os
from typing import List

import pytest

from fexrd import LiefFeatureExtractor

target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*.json")
)


@pytest.fixture
def feature_extractor() -> LiefFeatureExtractor:
    return LiefFeatureExtractor()


@pytest.mark.parametrize("test_json", target_test_json)
def test_get_features(
    feature_extractor: LiefFeatureExtractor, test_json: str
) -> None:
    try:
        with open(test_json, "r") as fin:
            obj = json.loads(fin.read())
            feature_extractor.get_features(obj["lief"])
    except Exception as e:
        assert False, str(e)


@pytest.mark.parametrize("test_json", target_test_json)
def test_extract_raw_features(
    feature_extractor: LiefFeatureExtractor, test_json: str
) -> None:
    try:
        with open(test_json, "r") as fin:
            obj = json.loads(fin.read())
            feature_extractor.extract_raw_features(obj["lief"])
    except Exception as e:
        assert False, str(e)
