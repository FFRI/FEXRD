"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2020
"""

import sys


def _main() -> None:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <output file name> <feature extractor name>",
            file=sys.stderr,
        )
        return

    output_fname: str = sys.argv[1]
    feature_extractor_name: str = sys.argv[2]

    with open("template.in", "r") as fin:
        script_template = fin.read()

    test_script = script_template.replace(
        "FeatureExtractor", feature_extractor_name
    )

    with open(output_fname, "w") as fout:
        fout.write(test_script)


if __name__ == "__main__":
    _main()
