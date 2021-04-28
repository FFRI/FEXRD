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
    - signatures (signature for FFRI Dataset 2020)
    - load\_configuration
- peid
- trid
- strings
- die
- Manalyze

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
    - SignatureFeatureExtractor: signatures (signature for FFRI Dataset 2020)
    - LoadConfigurationFeatureExtractor: load\_configuration
- PeidFeatureExtractor: peid
- TridFeatureExtractor: trid
- StringsFeatureExtractor: strings
- DieFeatureExtractor: die
- Manalyze: manalyze_plugin_packer

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

## Command Line Interface

FEXRD also provides a command-line interface for debugging purposes. Two commands are currently supported.

The command `show-raw-dict` shows a raw output of a specified JSON element before vectorization.

The command `show-vec` shows a feature vector of a specified JSON element.

```
$ python -m fexrd show-raw-dict --help
Usage: __main__.py show-raw-dict [OPTIONS] INPUT_JSON VER_STR EXTRACTOR_NAME

Arguments:
  INPUT_JSON      [required]
  VER_STR         [required]
  EXTRACTOR_NAME  Show an output of extract_raw_feature method. Available
                  feature names are:  lief, dos_header, rich_header, header,
                  optional_header, data_directories, sections, relocations,
                  tls, export, debug, imports, resources_tree,
                  resources_manager, signatures, load_configuration, peid,
                  trid, strings, all, die, manalyze_plugin_packer  [required]

$ python -m fexrd show-vec --help
Usage: __main__.py show-vec [OPTIONS] INPUT_JSON VER_STR EXTRACTOR_NAME

Arguments:
  INPUT_JSON      [required]
  VER_STR         [required]
  EXTRACTOR_NAME  Show an output of vectorize_features. Available feature
                  names are: lief, dos_header, rich_header, header,
                  optional_header, data_directories, sections, relocations,
                  tls, export, debug, imports, resources_tree,
                  resources_manager, signatures, load_configuration, peid,
                  trid, strings, all, die, manalyze_plugin_packer  [required]


Options:
  --help  Show this message and exit.
```

Here, we show some usage examples.

```
$ python -m fexrd show-vec ./tests/test_regression_test/v2021/01340ff69f0c627a5f1cba2b82a59ef90b1a61ecb8078e183dc3e5d4abc847e9.json v2021 dos_header
dos_header_addressof_new_exeheader,dos_header_addressof_relocation_table,dos_header_checksum,dos_header_file_size_in_pages,dos_header_header_size_in_paragraphs,dos_header_initial_ip,dos_header_initial_relative_cs,dos_header_initial_relative_ss,dos_header_initial_sp,dos_header_magic,dos_header_maximum_extra_paragraphs,dos_header_minimum_extra_paragraphs,dos_header_numberof_relocation,dos_header_oem_id,dos_header_oem_info,dos_header_overlay_number,dos_header_reserved[0],dos_header_reserved[1],dos_header_reserved[2],dos_header_reserved[3],dos_header_reserved2[0],dos_header_reserved2[1],dos_header_reserved2[2],dos_header_reserved2[3],dos_header_reserved2[4],dos_header_reserved2[5],dos_header_reserved2[6],dos_header_reserved2[7],dos_header_reserved2[8],dos_header_reserved2[9],dos_header_used_bytes_in_the_last_page
16843152.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,23117.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0,37008.0
$ python -m fexrd show-raw-dict ./tests/test_regression_test/v2021/01340ff69f0c627a5f1cba2b82a59ef90b1a61ecb8078e183dc3e5d4abc
847e9.json v2021 dos_header
{
  "addressof_new_exeheader": 16843152,
  "addressof_relocation_table": 37008,
  "checksum": 37008,
  "file_size_in_pages": 37008,
  "header_size_in_paragraphs": 37008,
  "initial_ip": 37008,
  "initial_relative_cs": 37008,
  "initial_relative_ss": 37008,
  "initial_sp": 37008,
  "magic": 23117,
  "maximum_extra_paragraphs": 37008,
  "minimum_extra_paragraphs": 37008,
  "numberof_relocation": 37008,
  "oem_id": 37008,
  "oem_info": 37008,
  "overlay_number": 37008,
  "reserved": [
    37008,
    37008,
    37008,
    37008
  ],
  "reserved2": [
    37008,
    37008,
    37008,
    37008,
    37008,
    37008,
    37008,
    37008,
    37008,
    37008
  ],
  "used_bytes_in_the_last_page": 37008
}
```

Additionally, you can use Docker for the CLI.
```
docker-compose -f .\docker-compose.production.yml run app python -m fexrd show-raw-dict --help
```

## More Practical Usage Examples

The [example](https://github.com/FFRI/FEXRD/tree/master/example) directory contains more practical usage examples.
