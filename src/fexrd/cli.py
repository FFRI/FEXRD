#
# (c) FFRI Security, Inc., 2020 / Author: FFRI Security, Inc.
#
import json
import sys
from typing import Dict, Optional

import pandas as pd
import typer

from . import (
    AllFeaturesExtractor,
    DataDirectoriesFeatureExtractor,
    DebugFeatureExtractor,
    DosHeaderFeatureExtractor,
    ExportFeatureExtractor,
    FeatureExtractor,
    HeaderFeatureExtractor,
    ImportsFeatureExtractor,
    LiefFeatureExtractor,
    LoadConfigurationFeatureExtractor,
    OptionalHeaderFeatureExtractor,
    PeidFeatureExtractor,
    RelocationsFeatureExtractor,
    ResourcesManagerFeatureExtractor,
    ResourcesTreeFeatureExtractor,
    RichHeaderFeatureExtractor,
    SectionsFeatureExtractor,
    SignatureFeatureExtractor,
    StringsFeatureExtractor,
    TlsFeatureExtractor,
    TridFeatureExtractor,
)

app = typer.Typer()


def feature_name_to_extractor() -> Dict[str, FeatureExtractor]:
    return {
        f.feature_name: f()
        for f in (
            LiefFeatureExtractor,
            DosHeaderFeatureExtractor,
            RichHeaderFeatureExtractor,
            HeaderFeatureExtractor,
            OptionalHeaderFeatureExtractor,
            DataDirectoriesFeatureExtractor,
            SectionsFeatureExtractor,
            RelocationsFeatureExtractor,
            TlsFeatureExtractor,
            ExportFeatureExtractor,
            DebugFeatureExtractor,
            ImportsFeatureExtractor,
            ResourcesTreeFeatureExtractor,
            ResourcesManagerFeatureExtractor,
            SignatureFeatureExtractor,
            LoadConfigurationFeatureExtractor,
            PeidFeatureExtractor,
            TridFeatureExtractor,
            StringsFeatureExtractor,
            AllFeaturesExtractor,
        )
    }


def feature_name_to_obj(obj: dict) -> Dict[str, dict]:
    f_to_obj = {
        name: obj[name]
        for name in (
            StringsFeatureExtractor.feature_name,
            PeidFeatureExtractor.feature_name,
            TridFeatureExtractor.feature_name,
            LiefFeatureExtractor.feature_name,
        )
    }

    def get_if_key_exits(obj: Dict[str, dict], key: str) -> Optional[dict]:
        return obj if key in obj.keys() else None

    f_to_obj.update(
        {
            name: get_if_key_exits(obj["lief"], name)
            for name in (
                DosHeaderFeatureExtractor.feature_name,
                RichHeaderFeatureExtractor.feature_name,
                HeaderFeatureExtractor.feature_name,
                OptionalHeaderFeatureExtractor.feature_name,
                DataDirectoriesFeatureExtractor.feature_name,
                SectionsFeatureExtractor.feature_name,
                RelocationsFeatureExtractor.feature_name,
                TlsFeatureExtractor.feature_name,
                ExportFeatureExtractor.feature_name,
                DebugFeatureExtractor.feature_name,
                ImportsFeatureExtractor.feature_name,
                ResourcesTreeFeatureExtractor.feature_name,
                ResourcesManagerFeatureExtractor.feature_name,
                SignatureFeatureExtractor.feature_name,
                LoadConfigurationFeatureExtractor.feature_name,
            )
        }
    )
    f_to_obj["all"] = obj
    return f_to_obj


@app.command()
def show_raw_dict(
    input_json: str,
    extractor_name: str = typer.Argument(
        ...,
        help=f'Available feature names are:\n {", ".join(feature_name_to_extractor().keys())} ',
    ),
) -> None:
    f_to_e = feature_name_to_extractor()
    if extractor_name not in f_to_e.keys():
        typer.echo(f"feature name: {extractor_name} is not found", err=True)
        typer.echo("Available features are:", err=True)
        typer.echo(", ".join(f_to_e.keys()), err=True)
        return
    fe = f_to_e[extractor_name]

    with open(input_json, "r") as fin:
        obj = json.loads(fin.read())

    obj_to_be_processed = feature_name_to_obj(obj)[fe.feature_name]
    if obj_to_be_processed:
        typer.echo(
            json.dumps(
                fe.extract_raw_features(
                    feature_name_to_obj(obj)[fe.feature_name]
                ),
                indent=2,
            )
        )
    else:
        typer.echo(f"key ({fe.feature_name}) does not exist")


@app.command()
def show_vec(
    input_json: str,
    extractor_name: str = typer.Argument(
        ...,
        help=f'Available feature names are:\n {", ".join(feature_name_to_extractor().keys())} ',
    ),
) -> None:
    f_to_e = feature_name_to_extractor()
    if extractor_name not in f_to_e.keys():
        typer.echo(f"feature name: {extractor_name} is not found", err=True)
        typer.echo("Available features are:", err=True)
        typer.echo(", ".join(f_to_e.keys()), err=True)
        return
    fe = f_to_e[extractor_name]

    with open(input_json, "r") as fin:
        obj = json.loads(fin.read())

    obj_to_be_processed = feature_name_to_obj(obj)[fe.feature_name]
    if obj_to_be_processed:
        columns, vec = fe.get_features(
            feature_name_to_obj(obj)[fe.feature_name]
        )
        df = pd.DataFrame(vec.reshape(1, vec.shape[0]), columns=columns)
        typer.echo(df.to_csv(sys.stdout, index=False))
    else:
        typer.echo(f"key ({fe.feature_name}) does not exist")
