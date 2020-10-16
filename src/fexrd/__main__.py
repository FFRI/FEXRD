"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2020
"""

import json
import sys

import lief


def _main(pe: str) -> None:
    from .core import LiefFeatureExtractor

    lief_json = json.loads(lief.to_json(lief.PE.parse(pe)))
    fe = LiefFeatureExtractor()
    rv = fe.extract_raw_features(lief_json)
    l, v = fe.get_features(lief_json)
    print("original data")
    print(lief_json["rich_header"])
    print("")
    print("raw vector")
    print(rv)
    print("")
    print("feature vector label name")
    print(l)
    print("")
    print("feature vector")
    print(v)
    print("")
    print("# of dimension")
    print(len(v), len(l))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path/to/PE>", file=sys.stderr)
        sys.exit(1)
    _main(sys.argv[1])
