#
# (c) FFRI Security, Inc., 2020-2023 / Author: FFRI Security, Inc.
#
import glob
import json
import os
from typing import List

import pytest

from fexrd import AllFeaturesExtractor

target_test_json: List[str] = glob.glob(
    os.path.join(os.path.abspath(os.path.splitext(__file__)[0]), "*", "*.json")
)


def get_ver_str(path: str) -> str:
    return path.split("/")[-2]


def make_feature_extractor(ver_str: str) -> AllFeaturesExtractor:
    return AllFeaturesExtractor(ver_str)


@pytest.mark.parametrize("test_json", target_test_json)
def test_get_features(test_json: str) -> None:
    ver_str = get_ver_str(test_json)
    feature_extractor = make_feature_extractor(ver_str)

    try:
        with open(test_json, "r") as fin:
            obj = json.loads(fin.read())
            feature_extractor.get_features(obj)
    except Exception as e:
        assert False, str(e)


@pytest.mark.parametrize("test_json", target_test_json)
def test_extract_raw_features(test_json: str) -> None:
    ver_str = get_ver_str(test_json)
    feature_extractor = make_feature_extractor(ver_str)

    try:
        with open(test_json, "r") as fin:
            obj = json.loads(fin.read())
            feature_extractor.extract_raw_features(obj)
    except Exception as e:
        assert False, str(e)
