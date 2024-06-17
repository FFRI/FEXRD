# Why FEXRD?

The FFRI Dataset contains a wide variety of tools' raw outputs (e.g., lief, TrID, peHash), making it versatile for different research applications. Below is an example from the FFRI Dataset 2020, formatted as JSON. In this format, keys represent tool names, and values represent the tools' raw outputs:

```json
{
  "label": 0,
  "date": null,
  "version": "2020",
  "file_size": 12288,
  "hashes": {
    "md5": "c5560c9b347ac6355dd7020b9a841ffc",
    "sha1": "437f5ccdf1fefc4f42442ddc22f46e4c34f1ae9f",
    "sha256": "e215fbbdf2a9fec8161808a41d371228882202d63924a99d0efbdae54c4d8f23",
    "ssdeep": "192:k8xZxfjo/vNxzp/yChtHmNn9sAzdN+j7RIY+Oifwhy681sy3Q5tfqXU/YEm:fxro/HzpyagNntajN/+p31TEm",
    "imphash": "7d3ef9faa2be833b9d39423cd3ed8b07",
    "impfuzzy": "48:8/Tbnw/LnNV06EAjIj1fB+xBMLSQMftMS1o:8nnw/LNVxEAkjZsXvtMS1o",
    "tlsh": "C4422B47BF564CFBC66943748463074AE1B17E418733A3CF13A9912D1FA6781312AA9C",
    "totalhash": null,
    "anymaster": "69631d85bdfc28870624870bb6dfd9c3defe4612",
    "anymaster_v1_0_1": "c1b9817d0a3e3eec7b1c53ba03460e4abc3d8f8c",
    "endgame": "d97267dd40d12b532b38daa246886bf0",
    "crits": "ce4c40d39ef962b9681c2ffe3984ad7ef7311bcd",
    "pehashng": "05c0ba3fd00cbd6615ebd83c5d57b85840f12673934b761fafb9893f786a6419"
  },
  "lief": {
    "data_directories": [
      {
        "RVA": 0,
        "size": 0,
        "type": "EXPORT_TABLE"
      },
      {
        "RVA": 10580,
        "section": ".rdata",
      }
  ...
  }
  ...
}
```

For machine learning research, it is necessary to transform this data into fixed-dimensional vectors. Given that the JSON structure is heavily nested, simply flattening the data could lead to excessively high-dimensional vectors, which might be cumbersome.

FEXRD provides a straightforward solution for deriving fixed-dimensional vectors from the FFRI Dataset, tailored for machine learning research.
