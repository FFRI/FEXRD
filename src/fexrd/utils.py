#
# (c) FFRI Security, Inc., 2020-2022 / Author: FFRI Security, Inc.
#

from collections import defaultdict
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Sized,
    Tuple,
    Union,
)

import numpy as np
from sklearn.feature_extraction import FeatureHasher


def make_defaultdict_from_dict_elem(
    dict_: Union[dict, defaultdict], key: str
) -> DefaultDict[str, Any]:
    ddict: DefaultDict[str, Any] = defaultdict(lambda: None)
    if key in dict_.keys() and dict_[key] is not None:
        for k, v in dict_[key].items():
            ddict[k] = v
    return ddict


def make_onehot_from_str_keys(
    keys: List[str], target_key: Optional[str]
) -> Dict[str, int]:
    encoded_data = {key: 0 for key in keys}
    if target_key:
        encoded_data[target_key] = 1
    return encoded_data


def make_onehot_dict_from_bitflag(
    keys: List[str], bitflag: Optional[int], flag_enum_class: Any
) -> Dict[str, int]:
    encoded_data = {key: 0 for key in keys}
    if bitflag:
        for k in encoded_data.keys():
            if bitflag & int(getattr(flag_enum_class, k)) != 0:
                encoded_data[k] = 1
    return encoded_data


def vectorize_with_feature_hasher(
    list_: Optional[List[Union[str, Tuple[str, Union[float, int]]]]], dim: int
) -> np.ndarray:
    if list_ is None or not list_:
        return np.array([None for _ in range(dim)])

    if isinstance(list_[0], str):
        input_type = "string"
    else:
        input_type = "pair"
    return (
        FeatureHasher(dim, input_type=input_type)
        .transform([list_])
        .toarray()[0]
    )


def make_vector_column_for_array(name: str, dim: int) -> List[str]:
    return [f"{name}[{i}]" for i in range(dim)]


def make_vector_column_for_dict(name: str, dict_: dict) -> List[str]:
    return [f"{name}.{k}" for k in dict_.keys()]


def stack_columns(
    prefix: str, columns: List[Union[str, List[str]]]
) -> List[str]:
    result = list()
    for c in columns:
        if isinstance(c, str):
            result.append(f"{prefix}_{c}")
        else:
            result += [f"{prefix}_{i}" for i in c]
    return result


def vectorize_selected_features(
    raw_features: dict,
    features_selected: List[str],
    post_process_funcs: Dict[str, Callable],
    column_prefix: str,
) -> Tuple[List[str], np.ndarray]:
    vectors = [
        raw_features[f]
        if f not in post_process_funcs.keys()
        else post_process_funcs[f](raw_features[f])
        for f in features_selected
    ]

    def make_column(
        f: str, v: Union[Sized, Dict, float, int]
    ) -> Union[str, List[str]]:
        if not isinstance(v, Sized):
            return f
        if isinstance(raw_features[f], Dict):
            return make_vector_column_for_dict(f, raw_features[f])
        return make_vector_column_for_array(f, len(v))

    columns = stack_columns(
        column_prefix,
        [make_column(f, v) for f, v in zip(features_selected, vectors)],
    )
    return columns, np.hstack(vectors).astype(np.float32)


def ver_str_to_int(s: str) -> int:
    return int(s[1:])
