#
# (c) FFRI Security, Inc., 2020-2023 / Author: FFRI Security, Inc.
#

import sys
from enum import Enum
from typing import Dict, List, Optional, Tuple

import numpy as np

from .exceptions import NotSupported
from .feature_extractor import FeatureExtractor
from .utils import vectorize_selected_features, ver_str_to_int


class ManalyzeDetectionReason(Enum):
    UNUSUAL_SECTION_NAME = 0
    W_AND_X = 1
    FEW_IMPORTS = 2
    KNOWN_PACKER_SECTION_NAME = 3
    BROKEN_RITCH_HEADER = 4
    BROKEN_RESOURCE = 5
    HIGH_ENTROPY = 6
    POSSIBLY_PACKED = 7

    @staticmethod
    def has_high_entropy_section(msg: str) -> bool:
        return "has an unusually high entropy" in msg

    @staticmethod
    def determined_possibly_packed(msg: str) -> bool:
        return "The PE is possibly packed" in msg

    @staticmethod
    def has_unusual_section_name(msg: str) -> bool:
        return "Unusual section name found:" in msg

    @staticmethod
    def has_w_and_x_section(msg: str) -> bool:
        return "is both writable and executable." in msg

    @staticmethod
    def has_few_imports(msg: str) -> bool:
        return "The PE only has" in msg

    @staticmethod
    def has_known_packer_section_name(msg: str) -> bool:
        return (
            ("The PE is packed with" in msg)
            or ("This PE is packed with" in msg)
            or ("This PE is a" in msg)
        )

    @staticmethod
    def has_broken_rich_header(msg: str) -> bool:
        return ("The RICH header checksum is invalid." in msg) or (
            "The number of imports reported in the RICH header is inconsistent."
            in msg
        )

    @staticmethod
    def has_broken_resource(msg: str) -> bool:
        return "The PE's resources are bigger than it is." in msg

    @staticmethod
    def msg_to_enum(msg: str) -> Optional["ManalyzeDetectionReason"]:
        if ManalyzeDetectionReason.has_unusual_section_name(msg):
            return ManalyzeDetectionReason.UNUSUAL_SECTION_NAME
        elif ManalyzeDetectionReason.has_w_and_x_section(msg):
            return ManalyzeDetectionReason.W_AND_X
        elif ManalyzeDetectionReason.has_few_imports(msg):
            return ManalyzeDetectionReason.FEW_IMPORTS
        elif ManalyzeDetectionReason.has_known_packer_section_name(msg):
            return ManalyzeDetectionReason.KNOWN_PACKER_SECTION_NAME
        elif ManalyzeDetectionReason.has_broken_resource(msg):
            return ManalyzeDetectionReason.BROKEN_RESOURCE
        elif ManalyzeDetectionReason.has_broken_rich_header(msg):
            return ManalyzeDetectionReason.BROKEN_RITCH_HEADER
        elif ManalyzeDetectionReason.has_high_entropy_section(msg):
            return ManalyzeDetectionReason.HIGH_ENTROPY
        elif ManalyzeDetectionReason.determined_possibly_packed(msg):
            return ManalyzeDetectionReason.POSSIBLY_PACKED
        else:
            return None


class ManalyzeFeatureExtractor(FeatureExtractor):
    feature_name = "manalyze_plugin_packer"

    def __init__(self, ver: str) -> None:
        super(FeatureExtractor, self).__init__()
        self.ver = ver_str_to_int(ver)
        if self.ver == 2020:
            raise NotSupported(self.ver, self.__class__.__name__)

    def extract_raw_features(self, raw_json: dict) -> Dict[str, Dict[str, int]]:
        plugin_output_categories = {
            str(i): 0 for i in list(ManalyzeDetectionReason)
        }
        if raw_json is not None:
            for v in raw_json["plugin_output"].values():
                category = ManalyzeDetectionReason.msg_to_enum(v)
                if category is not None:
                    plugin_output_categories[str(category)] = 1
                else:
                    print(
                        f"Unknown Manalyze output {raw_json['summary']}",
                        file=sys.stderr,
                    )
            if "summary" in raw_json.keys():
                category = ManalyzeDetectionReason.msg_to_enum(
                    raw_json["summary"]
                )
                if category is not None:
                    plugin_output_categories[str(category)] = 1
                else:
                    print(
                        (
                            "Unknown Manalyze summary output"
                            f" ({raw_json['summary']})"
                        ),
                        file=sys.stderr,
                    )
        return {"manalyze_output": plugin_output_categories}

    def vectorize_features(
        self, raw_features: Dict[str, Dict[str, int]]
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["manalyze_output"]
        post_process_funcs = {"manalyze_output": lambda x: list(x.values())}
        return vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )
