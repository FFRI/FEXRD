Feature EXtractor for FFRI Dataset (FEXRD)
=======================================
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

Extract features from FFRI Dataset

Requirements
---------------------------------------
- Python 3.6 or higher
- poetry (for building from scratch)

Install
---------------------------------------

You can install FEXRD as follows. We recommend you to create a virtual environment before the following instructions.

```
$ git clone https://github.com/FFRI/FEXRD.git
$ cd FEXRD
# Install patched version of LIEF for Python 3.6 (We also provide whl files for Python 3.7 and 3.8 in the same directory)
$ pip install packages/lief-0.11.0.ffridataset2020-cp36-none-linux_x86_64.whl
$ pip install https://github.com/FFRI/FEXRD/archive/fexrd-0.1.0-py3-none-any.whl
```

Alternatively, you can build from source code as follows.

```
$ poetry shell
$ poetry install # will take a few hours because it builds LIEF from scratch. Take a break and grab a cofee :)
$ python
>>> import json
>>> from fexrd import LiefFeatureExtractor
>>> lfe = LiefFeatureExtractor()
>>> fin = open("ffridataset_sample.json", "r")
>>> obj = json.loads(fin.read())
>>> lfe.get_features(obj["lief"])
```

Author
---------------------------------------
Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020
