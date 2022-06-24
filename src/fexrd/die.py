#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#

from typing import Dict, List, Tuple

import numpy as np

from .exceptions import NotSupported
from .feature_extractor import FeatureExtractor
from .utils import (
    vectorize_selected_features,
    vectorize_with_feature_hasher,
    ver_str_to_int,
)


class DieFeatureExtractor(FeatureExtractor):
    feature_name = "die"

    def __init__(self, ver: str) -> None:
        super(FeatureExtractor, self).__init__()
        self.ver = ver_str_to_int(ver)
        if self.ver <= 2020:
            raise NotSupported(self.ver, self.__class__.__name__)

    def extract_raw_features(self, raw_json: dict) -> Dict[str, List[str]]:
        # NOTE: Other elements (arch, filetyp, mode, type, endianess) are not used here
        # because output of lief contains the same information as these elements.
        if self.ver == 2021:
            return {"detects": [i["string"] for i in raw_json["detects"]]}
        elif self.ver == 2022:
            if "values" in raw_json["detects"][0].keys():
                return {
                    "detects": [
                        i["string"] for i in raw_json["detects"][0]["values"]
                    ]
                }
            else:
                return {"detects": []}
        else:
            raise NotImplementedError

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["detects"]
        post_process_funcs = {
            "detects": lambda x: vectorize_with_feature_hasher(x, 50)
        }
        return vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )
