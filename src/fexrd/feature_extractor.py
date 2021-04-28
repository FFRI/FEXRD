#
# (c) FFRI Security, Inc., 2020-2021 / Author: FFRI Security, Inc.
#

from typing import List, Tuple

import numpy as np

from .utils import vectorize_selected_features


class FeatureExtractor:
    feature_name: str = ""

    def __init__(self) -> None:
        pass

    def extract_raw_features(self, raw_json: dict) -> dict:
        return raw_json[self.feature_name]

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [k for k in raw_features.keys()]
        return vectorize_selected_features(
            raw_features, features_selected, {}, self.feature_name
        )

    def get_features(self, raw_json: dict) -> Tuple[List[str], np.ndarray]:
        return self.vectorize_features(self.extract_raw_features(raw_json))
