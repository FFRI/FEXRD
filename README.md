Feature EXtractor for FFRI Dataset (FEXRD)
=======================================
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
![python ci](https://github.com/FFRI/FEXRD/workflows/python%20ci/badge.svg)

Make feature vectors from FFRI Dataset

Requirements
---------------------------------------
- Python (3.8, 3.9, 3.10, 3.11)
- Poetry (for building from scratch)

Install
---------------------------------------

You can install FEXRD as follows. We recommend that you create a virtual environment before the following instructions.

```
$ pip install https://github.com/FFRI/FEXRD/releases/download/v2023.1/fexrd-2023.1-py3-none-any.whl
```

Alternatively, you can build from source code as follows.

```
$ git clone https://github.com/FFRI/FEXRD.git
$ cd FEXRD
$ poetry shell
$ poetry update
$ poetry install
$ python
>>> import json
>>> from fexrd import LiefFeatureExtractor
>>> lfe = LiefFeatureExtractor()
>>> fin = open("ffridataset_sample.json", "r")
>>> obj = json.loads(fin.read())
>>> lfe.get_features(obj["lief"])
```

How to use?
---------------------------------------
See the [documentation](https://ffri.github.io/FEXRD/) for more details.

Author
---------------------------------------
Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020--2023
