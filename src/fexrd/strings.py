#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#
from statistics import mean
from typing import List, Tuple

import numpy as np

from .feature_extractor import FeatureExtractor
from .utils import vectorize_selected_features, ver_str_to_int


class StringsFeatureExtractor(FeatureExtractor):
    feature_name = "strings"

    def __init__(self, ver: str) -> None:
        self.ver = ver_str_to_int(ver)
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def make_char_histogram(strings: List[str]) -> np.ndarray:
        if strings:
            # calculate the frequency of occurrence of each character
            # counted only for the ASCII character set whose code is in [0x20, 0x7e]
            # each code is subtracted by 0x20 to fit the range of bins in [0x0, 0x7e - 0x20]
            char_counts = np.bincount(
                [
                    ord(c) - 0x20
                    for c in "".join(strings)
                    if 0x20 <= ord(c) < 0x7F
                ],
                minlength=95,
            )
        else:
            char_counts = np.zeros((95,), dtype=np.float32)
        return char_counts

    @staticmethod
    def calc_entropy(hist: np.ndarray) -> float:
        csum = hist.sum()
        if csum == 0:
            return 0
        p = hist.astype(np.float32) / csum
        wh = np.where(hist)[0]
        return float(np.sum(-p[wh] * np.log2(p[wh])))

    @staticmethod
    def calc_avg_length(strings: List[str]) -> float:
        if strings:
            return mean(len(s) for s in strings)
        else:
            return 0.0

    @staticmethod
    def count_number_of_regs(strings: List[str]) -> int:
        return sum("HKEY_" in s for s in strings)

    @staticmethod
    def count_number_of_urls(strings: List[str]) -> int:
        return sum("https" in s or "http" in s for s in strings)

    @staticmethod
    def count_number_of_paths(strings: List[str]) -> int:
        return sum("C:\\" in s for s in strings)

    def extract_raw_features(self, raw_str_list: List[str]) -> List[str]:  # type: ignore
        return raw_str_list

    def vectorize_features(self, strings: List[str]) -> Tuple[List[str], np.ndarray]:  # type: ignore
        char_hist = self.make_char_histogram(strings)
        processed_features = {
            "char_hist": char_hist,
            "entropy": self.calc_entropy(char_hist),
            "average_length": self.calc_avg_length(strings),
            "number_of_regs": self.count_number_of_regs(strings),
            "number_of_urls": self.count_number_of_urls(strings),
            "number_of_paths": self.count_number_of_paths(strings),
        }
        features_selected = [
            "char_hist",
            "entropy",
            "average_length",
            "number_of_regs",
            "number_of_urls",
            "number_of_paths",
        ]
        return vectorize_selected_features(
            processed_features, features_selected, {}, self.feature_name
        )
