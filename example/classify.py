#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#

import glob
import json
import os
import pickle

import lightgbm as lgb
import pandas as pd
from sklearn.metrics import auc, roc_curve
from sklearn.model_selection import train_test_split

from fexrd import AllFeaturesExtractor


def classify(df: pd.DataFrame) -> None:
    X = df.drop("labels", axis=1).to_numpy()
    y = df["labels"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.25
    )

    lgb_train = lgb.Dataset(X_train, y_train)
    lgb_test = lgb.Dataset(X_val, y_val, reference=lgb_train)

    lgbm_param = {"objective": "binary", "verbose": -1}

    model = lgb.train(lgbm_param, lgb_train, valid_sets=lgb_test)
    y_pred = model.predict(X_test, num_iteration=model.best_iteration)
    fpr, tpr, thresholds = roc_curve(y_test, y_pred)
    print(f"AUC: {auc(fpr, tpr)}")


def save_as_pickle(df: pd.DataFrame, out_name: str) -> None:
    with open(out_name, "wb") as fout:
        pickle.dump(df, fout)


def _main() -> None:
    data_dir_in = "./data"

    # NOTE: Choose one of the following feature extractor class.
    # If you want to use strings feature only,
    # please comment out the "fe = AllFeaturesExtractor()" line and
    # uncomment the "fe = StringsFeatureExtractor()" line.
    # Don't forget to import a new feature extractor class when uncommenting.

    fe = AllFeaturesExtractor("v2020")
    # fe = StringsFeatureExtractor("v2020")
    # fe = LiefFeatureExtractor("v2020")

    cache_fname = f"{fe.feature_name}_cache.pickle"

    vecs = list()
    row_names = list()
    column_names = None
    labels = list()

    print(
        f"Now load file from {data_dir_in}/non_packed.jsonl and "
        f"{data_dir_in}/packed/*.jsonl"
    )
    print("It takes 3 or 5 minutes.")

    # non-packed binaries
    with open(os.path.join(data_dir_in, "non_packed.jsonl"), "r") as fin:
        for line in fin:
            obj = json.loads(line)
            column_names, vec = fe.get_features(
                obj[fe.feature_name] if fe.feature_name != "all" else obj
            )
            vecs.append(vec)
            row_names.append(obj["hashes"]["sha256"])
            labels.append(0)

    # packed binaries
    for json_in in glob.glob(os.path.join(data_dir_in, "packed", "*.jsonl")):
        with open(json_in, "r") as fin:
            for line in fin:
                obj = json.loads(line)
                _, vec = fe.get_features(
                    obj[fe.feature_name] if fe.feature_name != "all" else obj
                )
                vecs.append(vec)
                row_names.append(obj["hashes"]["sha256"])
                labels.append(1)

    df = pd.DataFrame(data=vecs, columns=column_names)
    df.index = row_names
    df["labels"] = labels
    save_as_pickle(df, cache_fname)

    print("data summary")
    print(df.describe())

    classify(df)


if __name__ == "__main__":
    _main()
