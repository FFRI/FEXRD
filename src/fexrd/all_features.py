#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#

from typing import List, Tuple

import numpy as np

from .die import DieFeatureExtractor
from .exceptions import InvalidVersion
from .feature_extractor import FeatureExtractor
from .lief import LiefFeatureExtractor
from .manalyze import ManalyzeFeatureExtractor
from .peid import PeidFeatureExtractor
from .strings import StringsFeatureExtractor
from .trid import TridFeatureExtractor
from .utils import ver_str_to_int


class AllFeaturesExtractor(FeatureExtractor):
    feature_name = "all"

    def __init__(self, ver: str) -> None:
        super(FeatureExtractor, self).__init__()
        self.ver = ver_str_to_int(ver)
        if not (2020 <= self.ver <= 2024):
            raise InvalidVersion(self.ver)

        extractors_dict = {
            2020: [
                LiefFeatureExtractor,
                PeidFeatureExtractor,
                StringsFeatureExtractor,
                TridFeatureExtractor,
            ],
            2021: [
                DieFeatureExtractor,
                ManalyzeFeatureExtractor,
            ],
        }
        self.extractors = [
            ext(ver)
            for v, exts in extractors_dict.items()
            if v <= self.ver
            for ext in exts
        ]

    def extract_raw_features(self, raw_json: dict) -> dict:
        raw_features = {
            extractor.feature_name: extractor.extract_raw_features(
                raw_json[extractor.feature_name]
            )
            for extractor in self.extractors
        }
        raw_features["file_size"] = raw_json["file_size"]
        return raw_features

    def vectorize_features(self, raw_features: dict) -> Tuple[List[str], np.ndarray]:
        columns: List[str] = ["file_size"]
        vectors: List[np.ndarray] = [
            raw_features["file_size"],
        ]
        for extractor in self.extractors:
            column, vector = extractor.vectorize_features(
                raw_features[extractor.feature_name]
            )
            columns += column
            vectors.append(vector)
        return columns, np.hstack(vectors)
