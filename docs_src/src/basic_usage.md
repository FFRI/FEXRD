# Basic Usage

## Feature Extractor Class

FEXRD provides feature extraction classes to convert the elements in the FFRI Dataset into `numpy.ndarray` vectors (hereinafter referred to simply as vectors). These classes are prepared for the values corresponding to the following keys in the FFRI Dataset.

- lief
    - dos\_header
    - rich\_header
    - header
    - optional\_header
    - data\_directories
    - sections
    - relocations
    - tls
    - export
    - debug (work in progress)
    - imports
    - resources\_tree (work in progress)
    - resources\_manager
    - signature
    - load\_configuration
- peid
- trid
- strings

The feature extraction classes corresponding to each of the above keys are as follows.

- LiefFeatureExtractor: lief
    - DosHeaderFeatureExtractor: dos\_header
    - RichHeaderFeatureExtractor: rich\_header
    - HeaderFeatureExtractor: header
    - OptionalHeaderFeatureExtractor: optional\_header
    - DataDirectoriesFeatureExtractor: data\_directories
    - SectionsFeatureExtractor: sections
    - RelocationsFeatureExtractor: relocations
    - TlsFeatureExtractor: tls
    - ExportFeatureExtractor: export
    - DebugFeatureExtractor: debug
    - ImportsFeatureExtractor: imports
    - ResourcesTreeFeatureExtractor: resources\_tree
    - ResourcesManagerFeatureExtractor: resources\_manager
    - SignatureFeatureExtractor: signature
    - LoadConfigurationFeatureExtractor: load\_configuration
- PeidFeatureExtractor: peid
- TridFeatureExtractor: trid
- StringsFeatureExtractor: strings

In addition to the above feature extraction classes, we also provide AllFeaturesExtractor. This can be used to create a vector that combines all the above feature extraction classes' outputs.

## Usage Example

Let's see how to use it in practice.

In FEXRD, depending on the feature you want to use, you can instantiate the corresponding feature extraction class and call the `get_features` method to retrieve the output vector. An example of creating a vector of the "strings" element is as follows.

```python
import json
from fexrd import StringsFeatureExtractor

sfe = StringsFeatureExtractor() # instantiae feature extractor class for the "string" element
fin = open("ffridataset_sample.jsonl", "r")
for l in fin.readlines():
    obj = json.loads(l)
    column_names, vector = sfe.get_features(obj["strings"]) # convert to the vector
```

In the above example, `StringsFeatureExtractor` is instantiated, and the "string" element is passed as an argument to the `get_features` method to get the vector.

The return value of the `get_features` method is a tuple, where the 0th element is the column name of the vector and the 1st element is the vector.

The same is true for converting the element corresponding to the key other than "strings" into a vector.

## More Practical Usage Examples

The [example](https://github.com/FFRI/FEXRD/tree/master/example) directory contains more practical usage examples.
