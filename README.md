Feature EXtractor for FFRI Dataset (FEXRD)
=======================================
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
![python ci](https://github.com/FFRI/FEXRD/workflows/python%20ci/badge.svg)

Make feature vectors from FFRI Dataset

Requirements
---------------------------------------
- Python (3.6, 3.7, 3.8)
- poetry (for building from scratch)

Install
---------------------------------------

You can install FEXRD as follows. We recommend you to create a virtual environment before the following instructions.

```
$ git clone https://github.com/FFRI/FEXRD.git
$ cd FEXRD
# Install patched version of LIEF for Python 3.6 (We also provide whl files for Python 3.7 and 3.8 in the same directory)
$ pip install packages/lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl
$ pip install https://github.com/FFRI/FEXRD/releases/download/v2021.1/fexrd-2021.1-py3-none-any.whl
```

Alternatively, you can build from source code as follows.

```
$ poetry shell
$ poetry update # will take a few hours because it builds LIEF from scratch. Take a break and grab a cofee :)
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
Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020
