#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#
from typing import Dict, List, Tuple

import numpy as np

from .feature_extractor import FeatureExtractor
from .utils import (
    make_onehot_from_str_keys,
    vectorize_selected_features,
    vectorize_with_feature_hasher,
    ver_str_to_int,
)


class PeidFeatureExtractor(FeatureExtractor):
    feature_name = "peid"

    def __init__(self, ver: str) -> None:
        self.ver = ver_str_to_int(ver)
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def ternary_to_onehot(ternary: str) -> Dict[str, int]:
        return make_onehot_from_str_keys(["yes", "no", "no (yes)"], ternary)

    def extract_raw_features(self, raw_json: dict) -> dict:
        return {
            "PE": int(raw_json["PE"] == "32 bit"),
            "DLL": int(raw_json["DLL"] == "yes"),
            "Packed": int(raw_json["Packed"] == "yes"),
            "Anti-Debug": self.ternary_to_onehot(raw_json["Anti-Debug"]),
            "GUI Program": self.ternary_to_onehot(raw_json["GUI Program"]),
            "Console Program": self.ternary_to_onehot(
                raw_json["Console Program"]
            ),
            "contains base64": int(raw_json["contains base64"] == "yes"),
            "AntiDebug": raw_json["AntiDebug"],
            "mutex": int(raw_json["mutex"] == "yes"),
            "PEiD": raw_json["PEiD"],
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "PE",
            "DLL",
            "Packed",
            "Anti-Debug",
            "GUI Program",
            "Console Program",
            "mutex",
            "contains base64",
            "PEiD",
            "AntiDebug",
        ]
        post_process_funcs = {
            "Anti-Debug": lambda x: list(x.values()),
            "GUI Program": lambda x: list(x.values()),
            "Console Program": lambda x: list(x.values()),
            "PEiD": lambda x: vectorize_with_feature_hasher(x, 50),
            "AntiDebug": lambda x: vectorize_with_feature_hasher(x, 50),
        }
        return vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )
