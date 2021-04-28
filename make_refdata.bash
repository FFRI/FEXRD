#!/bin/bash

for v in "v2021"
do
    for p in "test_input1" "test_input2"
    do
        for f in "data_directories" "dos_header" "export" "header" "imports" "load_configuration" "optional_header" "relocations" "resources_manager" "resources_tree" "rich_header" "sections" "tls" "all" "lief" "peid" "strings" "trid" "signature" "signatures" "debug" "die" "manalyze_plugin_packer"
        do
            echo ${v}, ${p}, ${f}
            python -m src.fexrd show-vec tests/test_cli/${v}/${p}.json ${v} "${f}" > tests/test_cli/${v}/${p}_${f}_ref_feature.csv
        done
    done
done

for v in "v2021"
do
    for p in "test_input1" "test_input2"
    do
        for f in "data_directories" "dos_header" "export" "header" "imports" "load_configuration" "optional_header" "relocations" "resources_manager" "resources_tree" "rich_header" "sections" "tls" "all" "lief" "peid" "strings" "trid" "signature" "signatures" "debug" "die" "manalyze_plugin_packer"
        do
            echo ${p}, ${f}
            python -m src.fexrd show-raw-dict ./tests/test_cli/${v}/${p}.json ${v} "${f}" > tests/test_cli/${v}/${p}_${f}_ref_raw.txt
        done
    done
done
