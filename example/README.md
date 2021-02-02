# Example

We have provided a simple example of binary classification using FEXRD.

## About data

The "data" directory contains JSON files in FFRI Dataset format.

Both "data/packed" and "data/non\_packed" contain JSON files that are created by processing [PackingData](https://github.com/chesvectain/PackingData/), where "data/packed" contains the result for packed binaries and "data/non\_packed" contains the result for non-packed (normal) binaries.

[classify.py](classify.py) script demonstrates the binary classification task in which files are packed or not.
