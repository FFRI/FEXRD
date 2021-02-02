#
# (c) FFRI Security, Inc., 2020 / Author: FFRI Security, Inc.
#
from typing import List, Tuple

import numpy as np

from .feature_extractor import FeatureExtractor
from .utils import vectorize_selected_features, vectorize_with_feature_hasher


class TridFeatureExtractor(FeatureExtractor):
    feature_name = "trid"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    def extract_raw_features(self, raw_json: dict) -> dict:
        return {
            "trid_entries": [
                (key, float(value[:-1]) / 100.0)
                for key, value in raw_json.items()
            ]
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["trid_entries"]
        post_process_funcs = {
            "trid_entries": lambda x: vectorize_with_feature_hasher(x, 20),
        }
        return vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )
