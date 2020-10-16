"""
Author of this code work, Koh M. Nakagawa. c FFRI Security, Inc. 2020
"""

from collections import defaultdict
from enum import Enum
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Sized,
    Tuple,
    Union,
)

import lief
import numpy as np
from sklearn.feature_extraction import FeatureHasher

assert lief.__version__.startswith("0.11.0"), "Supported LIEF version is 0.11.0"


def _make_defaultdict_from_dict_elem(
    dict_: Union[dict, defaultdict], key: str
) -> DefaultDict[str, Any]:
    return (
        defaultdict(lambda: None, dict_[key])
        if key in dict_.keys() and dict_[key] is not None
        else defaultdict(lambda: None)
    )


def _make_onehot_dict_from_str_keys(
    keys: List[str], target_key: Optional[str]
) -> Dict[str, int]:
    encoded_data = {key: 0 for key in keys}
    if target_key:
        encoded_data[target_key] = 1
    return encoded_data


def _make_onehot_dict_from_bitflag(
    keys: List[str], bitflag: Optional[int], flag_enum_class: Any
) -> Dict[str, int]:
    encoded_data = {key: 0 for key in keys}
    if bitflag:
        for k in encoded_data.keys():
            if bitflag & int(getattr(flag_enum_class, k)) != 0:
                encoded_data[k] = 1
    return encoded_data


def _vectorize_with_feature_hasher(
    list_: Optional[List[Union[str, Tuple[str, int]]]], dim: int
) -> np.ndarray:
    if list_ is None or not list_:
        return np.array([None for _ in range(dim)])

    if isinstance(list_[0], str):
        input_type = "string"
    else:
        input_type = "pair"
    return (
        FeatureHasher(dim, input_type=input_type)
        .transform([list_])
        .toarray()[0]
    )


def _make_vector_column_for_array(name: str, dim: int) -> List[str]:
    return [f"{name}[{i}]" for i in range(dim)]


def _make_vector_column_for_dict(name: str, dict_: dict) -> List[str]:
    return [f"{name}.{k}" for k in dict_.keys()]


def _stack_columns(
    prefix: str, columns: List[Union[str, List[str]]]
) -> List[str]:
    result = list()
    for c in columns:
        if isinstance(c, str):
            result.append(f"{prefix}_{c}")
        else:
            result += [f"{prefix}_{i}" for i in c]
    return result


def _vectorize_selected_features(
    raw_features: dict,
    features_selected: List[str],
    post_process_funcs: Dict[str, Callable],
    column_prefix: str,
) -> Tuple[List[str], np.ndarray]:
    vectors = [
        raw_features[f]
        if f not in post_process_funcs.keys()
        else post_process_funcs[f](raw_features[f])
        for f in features_selected
    ]
    columns = _stack_columns(
        column_prefix,
        [
            f
            if not isinstance(v, Sized)
            else _make_vector_column_for_dict(f, raw_features[f])
            if isinstance(raw_features[f], Dict)
            else _make_vector_column_for_array(f, len(v))
            for f, v in zip(features_selected, vectors)
        ],
    )
    return columns, np.hstack(vectors).astype(np.float32)


class FeatureExtractor:
    feature_name: str = ""

    def __init__(self) -> None:
        pass

    def extract_raw_features(self, raw_json: dict) -> dict:
        return raw_json[self.feature_name]

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [k for k in raw_features.keys()]
        return _vectorize_selected_features(
            raw_features, features_selected, {}, self.feature_name
        )

    def get_features(self, raw_json: dict) -> Tuple[List[str], np.ndarray]:
        return self.vectorize_features(self.extract_raw_features(raw_json))


class DosHeaderFeatureExtractor(FeatureExtractor):
    feature_name = "dos_header"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()


class RichHeaderFeatureExtractor(FeatureExtractor):
    feature_name = "rich_header"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    def extract_raw_features(self, raw_json: dict) -> dict:
        rich_header = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )

        if rich_header["entries"]:
            # list of (comp.id, count)
            entries: Optional[List[Tuple[str, int]]] = [
                (f'{entry["id"]:04x}{entry["build_id"]:04x}', entry["count"],)
                for entry in rich_header["entries"]
            ]
        else:
            entries = None

        return {
            "key": rich_header["key"],
            "entries": entries,
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["key", "entries"]
        post_process_funcs = {
            "entries": lambda x: _vectorize_with_feature_hasher(x, 50),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class HeaderFeatureExtractor(FeatureExtractor):
    feature_name = "header"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def machine_to_onehot(machine: str) -> Dict[str, int]:
        encoded_data = {
            "INVALID": 0,
            "UNKNOWN": 0,
            "AMD64": 0,
            "ARM": 0,
            "ARM64": 0,
            "I386": 0,
            "OTHER": 0,
        }
        if machine in encoded_data.keys():
            encoded_data[machine] = 1
        else:
            encoded_data["OTHER"] = 1
        return encoded_data

    @staticmethod
    def characteristics_to_onehot(chracteristics: int) -> Dict[str, int]:
        return _make_onehot_dict_from_bitflag(
            [
                "RELOCS_STRIPPED",
                "EXECUTABLE_IMAGE",
                "LINE_NUMS_STRIPPED",
                "LOCAL_SYMS_STRIPPED",
                "AGGRESSIVE_WS_TRIM",
                "LARGE_ADDRESS_AWARE",
                "BYTES_REVERSED_LO",
                "CHARA_32BIT_MACHINE",
                "DEBUG_STRIPPED",
                "REMOVABLE_RUN_FROM_SWAP",
                "NET_RUN_FROM_SWAP",
                "SYSTEM",
                "DLL",
                "UP_SYSTEM_ONLY",
                "BYTES_REVERSED_HI",
            ],
            chracteristics,
            lief.PE.HEADER_CHARACTERISTICS,
        )

    def extract_raw_features(
        self, raw_json: dict
    ) -> Dict[str, Union[int, Dict[str, int]]]:
        header = raw_json[self.feature_name]
        return {
            "signature": header["signature"],
            "machine": self.machine_to_onehot(header["machine"]),
            "numberof_sections": header["numberof_sections"],
            "time_date_stamp": header["time_date_stamp"],
            "numberof_symbols": header["numberof_symbols"],
            "pointerto_symbol_table": header["pointerto_symbol_table"],
            "sizeof_optional_header": header["sizeof_optional_header"],
            "characteristics": self.characteristics_to_onehot(
                header["characteristics"]
            ),
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "signature",
            "machine",
            "numberof_sections",
            "time_date_stamp",
            "numberof_symbols",
            "time_date_stamp",
            "numberof_symbols",
            "pointerto_symbol_table",
            "sizeof_optional_header",
            "characteristics",
        ]
        post_process_funcs = {
            "machine": lambda x: list(x.values()),
            "characteristics": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


# NOTE: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
class DllCharacteristics(Enum):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


class OptionalHeaderFeatureExtractor(FeatureExtractor):
    feature_name = "optional_header"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def subsystem_to_onehot(subsystem: str) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "UNKNOWN",
                "NATIVE",
                "WINDOWS_GUI",
                "WINDOWS_CUI",
                "OS2_CUI",
                "POSIX_CUI",
                "NATIVE_WINDOWS",
                "WINDOWS_CE_GUI",
                "EFI_APPLICATION",
                "EFI_BOOT_SERVICE_DRIVER",
                "EFI_RUNTIME_DRIVER",
                "EFI_ROM",
                "XBOX",
                "WINDOWS_BOOT_APPLICATION",
                "Out of range",
            ],
            subsystem,
        )

    @staticmethod
    def dll_characteristics_to_onehot(
        dll_characteristics: int,
    ) -> Dict[str, int]:
        encoded_data = {
            str(k): int((dll_characteristics & k.value) != 0)
            for k in DllCharacteristics
        }
        return encoded_data

    def extract_raw_features(self, raw_json: dict) -> dict:
        optional_header = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )
        return {
            "magic": int(optional_header["magic"] == "PE32"),
            "major_linker_version": optional_header["major_linker_version"],
            "minor_linker_version": optional_header["minor_linker_version"],
            "sizeof_code": optional_header["sizeof_code"],
            "sizeof_initialized_data": optional_header[
                "sizeof_initialized_data"
            ],
            "sizeof_uninitialized_data": optional_header[
                "sizeof_uninitialized_data"
            ],
            "addressof_entrypoint": optional_header["addressof_entrypoint"],
            "baseof_code": optional_header["baseof_code"],
            "baseof_data": optional_header["baseof_data"],
            "imagebase": optional_header["imagebase"],
            "section_alignment": optional_header["section_alignment"],
            "file_alignment": optional_header["file_alignment"],
            "major_operating_system_version": optional_header[
                "major_operating_system_version"
            ],
            "minor_operating_system_version": optional_header[
                "minor_operating_system_version"
            ],
            "major_image_version": optional_header["major_image_version"],
            "minor_image_version": optional_header["minor_image_version"],
            "major_subsystem_version": optional_header[
                "major_subsystem_version"
            ],
            "minor_subsystem_version": optional_header[
                "minor_subsystem_version"
            ],
            "win32_version_value": optional_header["win32_version_value"],
            "sizeof_image": optional_header["sizeof_image"],
            "sizeof_headers": optional_header["sizeof_headers"],
            "checksum": optional_header["checksum"],
            "sizeof_stack_reserve": optional_header["sizeof_stack_reserve"],
            "sizeof_stack_commit": optional_header["sizeof_stack_commit"],
            "sizeof_heap_reserve": optional_header["sizeof_heap_reserve"],
            "sizeof_heap_commit": optional_header["sizeof_heap_commit"],
            "loader_flags": optional_header["loader_flags"],
            "numberof_rva_and_size": optional_header["numberof_rva_and_size"],
            "subsystem": self.subsystem_to_onehot(optional_header["subsystem"]),
            "dll_characteristics": self.dll_characteristics_to_onehot(
                optional_header["dll_characteristics"]
            ),
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "major_linker_version",
            "minor_linker_version",
            "sizeof_code",
            "sizeof_initialized_data",
            "sizeof_uninitialized_data",
            "addressof_entrypoint",
            "baseof_code",
            "baseof_data",
            "imagebase",
            "section_alignment",
            "file_alignment",
            "major_operating_system_version",
            "minor_operating_system_version",
            "major_image_version",
            "minor_image_version",
            "major_subsystem_version",
            "minor_subsystem_version",
            "win32_version_value",
            "sizeof_image",
            "sizeof_headers",
            "checksum",
            "sizeof_stack_reserve",
            "sizeof_stack_commit",
            "sizeof_heap_reserve",
            "sizeof_heap_commit",
            "loader_flags",
            "numberof_rva_and_size",
            "subsystem",
            "dll_characteristics",
        ]
        post_process_funcs = {
            "subsystem": lambda x: list(x.values()),
            "dll_characteristics": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class DataDirectoriesFeatureExtractor(FeatureExtractor):
    feature_name = "data_directories"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def pair_with_section_type(
        data_directories: Optional[List[dict]], record_name: str
    ) -> Optional[List[Tuple[str, int]]]:
        if data_directories:
            return [
                (data_directory["type"], data_directory[record_name])
                for data_directory in data_directories
            ]
        else:
            return None

    def extract_raw_features(self, raw_json: dict) -> dict:
        data_directories = (
            raw_json[self.feature_name]
            if self.feature_name in raw_json.keys()
            else None
        )
        if data_directories:
            section: Optional[List[str]] = [
                data_directory["section"]
                if "section" in data_directory.keys()
                else None
                for data_directory in data_directories
            ]
        else:
            section = None

        return {
            "RVA": self.pair_with_section_type(data_directories, "RVA"),
            "size": self.pair_with_section_type(data_directories, "size"),
            "section": section,
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["RVA", "size", "section"]
        post_process_funcs = {
            "RVA": lambda x: _vectorize_with_feature_hasher(x, 50),
            "size": lambda x: _vectorize_with_feature_hasher(x, 50),
            "section": lambda x: _vectorize_with_feature_hasher(
                list(filter(lambda y: y is not None, x)) if x else None, 20
            ),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class SectionsFeatureExtractor(FeatureExtractor):
    feature_name = "sections"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def pair_with_section_name(
        sections: Optional[List[dict]], record_name: str
    ) -> Optional[List[Tuple[str, int]]]:
        if sections:
            return [
                (section["name"], section[record_name]) for section in sections
            ]
        else:
            return None

    # TODO: Reconsider the way to vectorize section characteristics
    @staticmethod
    def vectorize_characteristics(
        sections: Optional[List[dict]],
    ) -> Dict[str, int]:
        encoded_data = {
            "TYPE_NO_PAD": 0,
            "CNT_CODE": 0,
            "CNT_INITIALIZED_DATA": 0,
            "CNT_UNINITIALIZED_DATA": 0,
            "LNK_OTHER": 0,
            "LNK_INFO": 0,
            "LNK_REMOVE": 0,
            "LNK_COMDAT": 0,
            "GPREL": 0,
            "MEM_PURGEABLE": 0,
            "MEM_16BIT": 0,
            "MEM_LOCKED": 0,
            "MEM_PRELOAD": 0,
            "ALIGN_1BYTES": 0,
            "ALIGN_2BYTES": 0,
            "ALIGN_4BYTES": 0,
            "ALIGN_8BYTES": 0,
            "ALIGN_16BYTES": 0,
            "ALIGN_32BYTES": 0,
            "ALIGN_64BYTES": 0,
            "ALIGN_128BYTES": 0,
            "ALIGN_256BYTES": 0,
            "ALIGN_512BYTES": 0,
            "ALIGN_1024BYTES": 0,
            "ALIGN_2048BYTES": 0,
            "ALIGN_4096BYTES": 0,
            "ALIGN_8192BYTES": 0,
            "LNK_NRELOC_OVFL": 0,
            "MEM_DISCARDABLE": 0,
            "MEM_NOT_CACHED": 0,
            "MEM_NOT_PAGED": 0,
            "MEM_SHARED": 0,
            "MEM_EXECUTE": 0,
            "MEM_READ": 0,
            "MEM_WRITE": 0,
        }
        if sections:
            for section in sections:
                for characteristic in section["characteristics"]:
                    encoded_data[characteristic] += 1
        return encoded_data

    # TODO: Reconsider the way to vectorize section types
    @staticmethod
    def vectorize_types(sections: Optional[List[dict]]) -> Dict[str, int]:
        encoded_data = {
            "TEXT": 0,
            "TLS_": 0,
            "IDATA": 0,
            "DATA": 0,
            "BSS": 0,
            "RESOURCE": 0,
            "RELOCATION": 0,
            "EXPORT": 0,
            "DEBUG": 0,
            "UNKNOWN": 0,
            "Out of range": 0,
        }
        if sections:
            for section in sections:
                for type_ in section["types"]:
                    encoded_data[type_] += 1
        return encoded_data

    def extract_raw_features(self, raw_json: dict) -> dict:
        sections = (
            raw_json[self.feature_name]
            if self.feature_name in raw_json.keys()
            else None
        )
        return {
            "pointerto_relocation": self.pair_with_section_name(
                sections, "pointerto_relocation"
            ),
            "pointerto_line_numbers": self.pair_with_section_name(
                sections, "pointerto_line_numbers"
            ),
            "numberof_relocations": self.pair_with_section_name(
                sections, "numberof_relocations"
            ),
            "numberof_line_numbers": self.pair_with_section_name(
                sections, "numberof_line_numbers"
            ),
            "entropy": self.pair_with_section_name(sections, "entropy"),
            "characteristics": self.vectorize_characteristics(sections),
            "types": self.vectorize_types(sections),
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "pointerto_relocation",
            "pointerto_line_numbers",
            "numberof_relocations",
            "numberof_line_numbers",
            "characteristics",
            "entropy",
            "types",
        ]
        post_process_funcs = {
            "pointerto_relocation": lambda x: _vectorize_with_feature_hasher(
                x, 50
            ),
            "pointerto_line_numbers": lambda x: _vectorize_with_feature_hasher(
                x, 50
            ),
            "numberof_relocations": lambda x: _vectorize_with_feature_hasher(
                x, 50
            ),
            "numberof_line_numbers": lambda x: _vectorize_with_feature_hasher(
                x, 50
            ),
            "entropy": lambda x: _vectorize_with_feature_hasher(x, 50),
            "characteristics": lambda x: list(x.values()),
            "types": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class RelocationsFeatureExtractor(FeatureExtractor):
    feature_name = "relocations"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def flatten_relocation_entries(
        relocations: Optional[List[dict]],
    ) -> List[Tuple[int, str]]:
        flattened_entries = list()
        if relocations:
            for relocation in relocations:
                virtual_address = relocation["virtual_address"]
                for entry in relocation["entries"]:
                    flattened_entries.append(
                        ((virtual_address + entry["position"], entry["type"]))
                    )
        return flattened_entries

    # NOTE: This method is only valid for LIEF v0.10.1
    # TODO: support LIEF v0.11 or later
    @staticmethod
    def count_relocation_types(
        flattend_entries: Optional[List[Tuple[int, str]]]
    ) -> List[int]:
        buckets = {
            "ABSOLUTE": 0,
            "HIGH": 0,
            "LOW": 0,
            "HIGHLOW": 0,
            "HIGHADJ": 0,
            "MIPS_JMPADDR | ARM_MOV32A | ARM_MOV32 | RISCV_HI20": 0,
            "SECTION": 0,
            "REL | ARM_MOV32T | THUMB_MOV32 | RISCV_LOW12I": 0,
            "RISCV_LOW12S": 0,
            "MIPS_JMPADDR16 | IA64_DIR64": 0,
            "DIR64": 0,
            "HIGH3ADJ": 0,
            "Out of range": 0,
        }
        if flattend_entries:
            for _, type_ in flattend_entries:
                buckets[type_] += 1
        return list(buckets.values())

    def extract_raw_features(self, raw_json: dict) -> dict:
        relocations = (
            raw_json[self.feature_name]
            if self.feature_name in raw_json.keys()
            else None
        )
        return {
            "flattened_entries": self.flatten_relocation_entries(relocations)
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["flattened_entries"]
        post_process_funcs = {
            "flattened_entries": lambda x: self.count_relocation_types(x),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class TlsFeatureExtractor(FeatureExtractor):
    feature_name = "tls"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def characteristics_to_onehot(
        characteristics: Optional[int],
    ) -> Dict[str, int]:
        if characteristics:
            characteristics_str: Optional[str] = str(
                lief.PE.SECTION_CHARACTERISTICS(characteristics & 0xF00000)
            )
            has_extra_bits = int((characteristics & 0xFF0FFFFF) != 0)
        else:
            characteristics_str = None
            has_extra_bits = 0
        encoded_data = _make_onehot_dict_from_str_keys(
            [
                "SECTION_CHARACTERISTICS.ALIGN_1BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_2BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_4BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_8BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_16BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_32BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_64BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_128BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_256BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_512BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_1024BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_2048BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_4096BYTES",
                "SECTION_CHARACTERISTICS.ALIGN_8192BYTES",
                "SECTION_CHARACTERISTICS.???",
            ],
            characteristics_str,
        )
        encoded_data["has_extra_bits"] = has_extra_bits
        return encoded_data

    @staticmethod
    def data_directory_to_onehot(
        data_directory: Optional[str],
    ) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "EXPORT_TABLE",
                "IMPORT_TABLE",
                "RESOURCE_TABLE",
                "EXCEPTION_TABLE",
                "CERTIFICATE_TABLE",
                "BASE_RELOCATION_TABLE",
                "DEBUG",
                "ARCHITECTURE",
                "GLOBAL_PTR",
                "TLS_TABLE",
                "LOAD_CONFIG_TABLE",
                "BOUND_IMPORT",
                "IAT",
                "DELAY_IMPORT_DESCRIPTOR",
                "CLR_RUNTIME_HEADER",
            ],
            data_directory,
        )

    def extract_raw_features(self, raw_json: dict) -> dict:
        tls = _make_defaultdict_from_dict_elem(raw_json, self.feature_name)
        return {
            "callbacks": int(
                bool(tls["callbacks"])
            ),  # NOTE: Tls callback functions exists or not
            "addressof_raw_data": int(bool(tls["addressof_raw_data"])),
            "addressof_index": tls["addressof_index"],
            "addressof_callbacks": tls["addressof_callbacks"],
            "sizoeof_zero_fill": tls["sizeof_zero_fill"],
            "characteristics": self.characteristics_to_onehot(
                tls["characteristics"]
            ),
            "data_directory": self.data_directory_to_onehot(
                tls["data_directory"]
            ),
            "section": tls["section"],
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "callbacks",
            "addressof_raw_data",
            "addressof_index",
            "addressof_callbacks",
            "sizoeof_zero_fill",
            "characteristics",
            "data_directory",
        ]
        post_process_funcs = {
            "characteristics": lambda x: list(x.values()),
            "data_directory": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class ExportFeatureExtractor(FeatureExtractor):
    feature_name = "export"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def make_export_apis(
        entries: Optional[List[dict]], name: Optional[str]
    ) -> Optional[List[str]]:
        if entries is None or name is None:
            return None
        export_apis: List[str] = list()
        for entry in entries:
            if "forward_information" in entry.keys():
                api_name = f'{entry["forward_information"]["library"]}:{entry["forward_information"]["function"]}'
            else:
                api_name = f'{name}:{entry["name"]}'
            export_apis.append(api_name)
        return export_apis

    @staticmethod
    def pair_with_export_api(
        entries: Optional[List[dict]],
        export_apis: Optional[List[str]],
        record_name: str,
    ) -> Optional[List[Tuple[str, int]]]:
        if export_apis is not None and entries is not None:
            return [
                (export_api, entry[record_name])
                for export_api, entry in zip(export_apis, entries)
            ]
        else:
            return None

    def extract_raw_features_from_entries(
        self, entries: Optional[List[dict]], export_apis: Optional[List[str]]
    ) -> dict:
        prefix = "entries"
        return {
            f"{prefix}_ordinal": self.pair_with_export_api(
                entries, export_apis, "ordinal"
            ),
            f"{prefix}_address": self.pair_with_export_api(
                entries, export_apis, "address"
            ),
            f"{prefix}_is_extern": self.pair_with_export_api(
                entries, export_apis, "is_extern"
            ),
        }

    def extract_raw_features(self, raw_json: dict) -> dict:
        export = _make_defaultdict_from_dict_elem(raw_json, self.feature_name)
        entries = export["entries"]
        export_apis = self.make_export_apis(entries, export["name"])
        return {
            "export_flags": export["export_flags"],
            "timestamp": export["timestamp"],
            "major_version": export["major_version"],
            "minor_version": export["minor_version"],
            "ordinal_base": export["ordinal_base"],
            "name": export["name"],
            **self.extract_raw_features_from_entries(entries, export_apis),
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        selected_features = [
            "export_flags",
            "timestamp",
            "major_version",
            "minor_version",
            "ordinal_base",
            "entries_ordinal",
            "entries_address",
            "entries_is_extern",
        ]
        post_process_funcs = {
            "entries_ordinal": lambda x: _vectorize_with_feature_hasher(x, 50),
            "entries_address": lambda x: _vectorize_with_feature_hasher(x, 50),
            "entries_is_extern": lambda x: _vectorize_with_feature_hasher(
                x, 50
            ),
        }
        return _vectorize_selected_features(
            raw_features,
            selected_features,
            post_process_funcs,
            self.feature_name,
        )


class DebugFeatureExtractor(FeatureExtractor):
    feature_name = "debug"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    # TODO: vectorize debug feature
    # def extract_raw_features(self, raw_json: dict) -> dict:
    #     debug = _make_defaultdict_from_dict(raw_json, self.feature_name)
    #     return {...}


class ImportsFeatureExtractor(FeatureExtractor):
    feature_name = "imports"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def pair_with_import_dlls(
        imports: Optional[List[dict]], record_name: str
    ) -> Optional[List[Tuple[str, int]]]:
        if imports:
            return [
                (import_["name"], import_[record_name]) for import_ in imports
            ]
        else:
            return None

    @staticmethod
    def pair_with_import_apis(
        imports: Optional[List[dict]], record_name: str
    ) -> Optional[List[Tuple[str, int]]]:
        if imports is None:
            return None
        result: List[Tuple[str, int]] = list()
        for import_ in imports:
            dll_name = import_["name"]
            for entry in import_["entries"]:
                result.append(
                    (
                        f"{dll_name}:{ImportsFeatureExtractor.get_api_name(entry)}",
                        entry[record_name],
                    )
                )
        return result

    @staticmethod
    def get_api_name(entry: dict) -> str:
        if "name" in entry.keys():
            return entry["name"]
        else:
            return f'ord{entry["ordinal"]}'

    @staticmethod
    def flatten_api_entries(
        imports: Optional[List[dict]],
    ) -> Optional[List[str]]:
        if imports is None:
            return None
        return [
            f'{import_["name"]}:{ImportsFeatureExtractor.get_api_name(entry)}'
            for import_ in imports
            for entry in import_["entries"]
        ]

    @staticmethod
    def flatten_dll_entries(
        imports: Optional[List[dict]],
    ) -> Optional[List[str]]:
        if imports is None:
            return None
        return [import_["name"] for import_ in imports]

    def extract_raw_features(self, raw_json: dict) -> dict:
        imports = (
            raw_json[self.feature_name]
            if self.feature_name in raw_json.keys()
            else None
        )
        return {
            "dll_names": self.flatten_dll_entries(imports),
            "api_names": self.flatten_api_entries(imports),
            "forwarder_chain": self.pair_with_import_dlls(
                imports, "forwarder_chain"
            ),
            "timedatestamp": self.pair_with_import_dlls(
                imports, "timedatestamp"
            ),
            "import_address_table_rva": self.pair_with_import_dlls(
                imports, "import_address_table_rva"
            ),
            "iat_address": self.pair_with_import_apis(imports, "iat_address"),
            "data": self.pair_with_import_apis(imports, "data"),
            "hint": self.pair_with_import_apis(imports, "hint"),
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "dll_names",
            "api_names",
            "forwarder_chain",
            "timedatestamp",
            "import_address_table_rva",
            "iat_address",
            "data",
            "hint",
        ]
        post_process_funcs = {
            "dll_names": lambda x: _vectorize_with_feature_hasher(x, 100),
            "api_names": lambda x: _vectorize_with_feature_hasher(x, 500),
            "forwarder_chain": lambda x: _vectorize_with_feature_hasher(x, 100),
            "timedatestamp": lambda x: _vectorize_with_feature_hasher(x, 100),
            "import_address_table_rva": lambda x: _vectorize_with_feature_hasher(
                x, 100
            ),
            "iat_address": lambda x: _vectorize_with_feature_hasher(x, 100),
            "data": lambda x: _vectorize_with_feature_hasher(x, 100),
            "hint": lambda x: _vectorize_with_feature_hasher(x, 100),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


# NOTE: In LIEF 0.11 or later, dict structure of resources_tree is different from 0.10.1 one.
# TODO: When updating LIEF version 0.10.1 to 0.11, the extract_raw_features should be modified.
class ResourcesTreeFeatureExtractor(FeatureExtractor):
    feature_name = "resources_tree"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    def extract_raw_features(self, raw_json: dict) -> dict:
        resources_tree = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )
        return {
            "characteristics": resources_tree["characteristics"],
            "major_version": resources_tree["major_version"],
            "minor_version": resources_tree["minor_version"],
            "numberof_id_entries": resources_tree["numberof_id_entries"],
            "numberof_name_entries": resources_tree["numberof_name_entries"],
            "time_date_stamp": resources_tree["time_date_stamp"],
        }


class ResourcesManagerFeatureExtractor(FeatureExtractor):
    feature_name = "resources_manager"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    # TODO: should parse manifest XML using xmltodict
    # @staticmethod
    # def parse_manifest_content():
    #     pass

    @staticmethod
    def fixed_version_file_flags_to_onehot(
        file_flags: Optional[int],
    ) -> Dict[str, int]:
        return _make_onehot_dict_from_bitflag(
            [
                "DEBUG",
                "INFOINFERRED",
                "PATCHED",
                "PRERELEASE",
                "PRIVATEBUILD",
                "SPECIALBUILD",
            ],
            file_flags,
            lief.PE.FIXED_VERSION_FILE_FLAGS,
        )

    @staticmethod
    def fixed_version_os_to_onehot(version_os: Optional[str]) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "DOS",
                "DOS_WINDOWS16",
                "DOS_WINDOWS32",
                "NT",
                "NT_WINDOWS32",
                "OS216",
                "OS216_PM16",
                "OS232",
                "OS232_PM32",
                "PM16",
                "PM32",
                "UNKNOWN",
                "WINDOWS16",
                "WINDOWS32",
                "Out of range",
            ],
            version_os,
        )

    @staticmethod
    def fixed_version_file_type_to_onehot(
        file_type: Optional[str],
    ) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "APP",
                "DLL",
                "DRV",
                "FONT",
                "STATIC_LIB",
                "VXD",
                "UNKNOWN",
                "Out of range",
            ],
            file_type,
        )

    @staticmethod
    def fixed_version_file_subtype_to_onehot(
        file_subtype: Optional[str],
    ) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "DRV_COMM",
                "DRV_DISPLAY",
                "DRV_INSTALLABLE",
                "DRV_KEYBOARD",
                "DRV_LANGUAGE",
                "DRV_MOUSE",
                "DRV_NETWORK",
                "DRV_PRINTER",
                "DRV_SOUND",
                "DRV_SYSTEM",
                "DRV_VERSIONED_PRINTER",
                "UNKNOWN",
                "Out of range",
            ],
            file_subtype,
        )

    # @staticmethod
    # def langcode_items_to_featurevector(langcode_items):
    #     pass

    # @staticmethod
    # def translations_to_featurevector(translations):
    #     pass

    def extract_raw_features_from_version(
        self, version: DefaultDict[str, Any]
    ) -> dict:
        prefix = "version"
        return {
            f"{prefix}_type": version["type"],
            # NOTE: should be VS_VERSION_INFO, but other strings might come
            f"{prefix}_key": int(version["key"] == "VS_VERSION_INFO"),
        }

    def extract_raw_features_from_fixed_file_info(
        self, fixed_file_info: DefaultDict[str, Any]
    ) -> dict:
        prefix = "version"
        cprefix = "fixed_file_info"
        return {
            f"{prefix}_{cprefix}_signature": fixed_file_info["signature"],
            f"{prefix}_{cprefix}_struct_version": fixed_file_info[
                "struct_version"
            ],
            f"{prefix}_{cprefix}_file_version_MS": fixed_file_info[
                "file_version_MS"
            ],
            f"{prefix}_{cprefix}_file_version_LS": fixed_file_info[
                "file_version_LS"
            ],
            f"{prefix}_{cprefix}_file_flags_mask": self.fixed_version_file_flags_to_onehot(
                fixed_file_info["file_flags_mask"]
            ),
            f"{prefix}_{cprefix}_file_flags": self.fixed_version_file_flags_to_onehot(
                fixed_file_info["file_flags"]
            ),
            f"{prefix}_{cprefix}_file_os": self.fixed_version_os_to_onehot(
                fixed_file_info["file_os"]
            ),
            f"{prefix}_{cprefix}_file_type": self.fixed_version_file_type_to_onehot(
                fixed_file_info["file_type"]
            ),
            f"{prefix}_{cprefix}_file_subtype": self.fixed_version_file_subtype_to_onehot(
                fixed_file_info["file_subtype"]
            ),
            f"{prefix}_{cprefix}_file_date_MS": fixed_file_info["file_date_MS"],
            f"{prefix}_{cprefix}_file_date_LS": fixed_file_info["file_date_LS"],
        }

    def extract_raw_features_from_string_file_info(
        self, string_file_info: DefaultDict[str, Any]
    ) -> dict:
        prefix = "version"
        cprefix = "string_file_info"
        # TODO: convert langcode_items array to feature vector
        # langcode_items = _make_defaultdict_from_dict(string_file_info, "lang_code_item")

        return {
            f"{prefix}_{cprefix}_type": string_file_info["type"],
            f"{prefix}_{cprefix}_key": int(
                string_file_info["key"] == "StringFileInfo"
            ),
        }

    def extract_raw_features_from_var_file_info(
        self, var_file_info: DefaultDict[str, Any]
    ) -> dict:
        prefix = "version"
        cprefix = "var_file_info"

        return {
            f"{prefix}_{cprefix}_type": var_file_info["type"],
            f"{prefix}_{cprefix}_key": int(
                var_file_info["key"] == "VarFileInfo"
            ),
            # f"{prefix}_{cprefix}_translations": self.translations_to_featurevector(var_file_info["translations"])
        }

    def extract_raw_features_from_icons(
        self, icons: DefaultDict[str, Any]
    ) -> dict:
        # TODO: should be implemented for icons
        pass

    def extract_raw_features(self, raw_json: dict) -> dict:
        resources_manager = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )
        version = _make_defaultdict_from_dict_elem(resources_manager, "version")
        return {
            # NOTE: extracted but not converted to feature vector
            # TODO: should parse manifest XML file
            "manifest": resources_manager["manifest"],
            **self.extract_raw_features_from_version(version),
            **self.extract_raw_features_from_fixed_file_info(
                _make_defaultdict_from_dict_elem(version, "fixed_file_info")
            ),
            **self.extract_raw_features_from_string_file_info(
                _make_defaultdict_from_dict_elem(version, "string_file_info")
            ),
            **self.extract_raw_features_from_var_file_info(
                _make_defaultdict_from_dict_elem(version, "var_file_info")
            ),
            # **self.extract_raw_features_from_icons(
            #     _make_defaultdict_from_dict_elem(
            #         resources_manager, "icons"
            #     )
            # )
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "version_type",
            "version_key",
            "version_fixed_file_info_signature",
            "version_fixed_file_info_struct_version",
            "version_fixed_file_info_file_version_MS",
            "version_fixed_file_info_file_version_LS",
            "version_fixed_file_info_file_flags_mask",
            "version_fixed_file_info_file_flags",
            "version_fixed_file_info_file_os",
            "version_fixed_file_info_file_type",
            "version_fixed_file_info_file_subtype",
            "version_fixed_file_info_file_date_MS",
            "version_fixed_file_info_file_date_LS",
            "version_string_file_info_type",
            "version_string_file_info_key",
            "version_var_file_info_type",
            "version_var_file_info_key",
        ]
        post_process_funcs = {
            "version_fixed_file_info_file_flags_mask": lambda x: list(
                x.values()
            ),
            "version_fixed_file_info_file_flags": lambda x: list(x.values()),
            "version_fixed_file_info_file_os": lambda x: list(x.values()),
            "version_fixed_file_info_file_type": lambda x: list(x.values()),
            "version_fixed_file_info_file_subtype": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class SignatureFeatureExtractor(FeatureExtractor):
    feature_name = "signature"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    # TODO: should be implemented
    # @staticmethod
    # def crts_to_feature_vector(crts):
    #     pass

    def extract_raw_features_from_content_info(
        self, content_info: DefaultDict[str, Any]
    ) -> dict:
        prefix = "content_info"
        return {
            f"{prefix}_content_type": content_info["content_type"],
            f"{prefix}_digest_algorithm": content_info["digest_algorithm"],
            f"{prefix}_type": content_info["type"],
        }

    def extract_raw_features_from_signer_info(
        self, signer_info: DefaultDict[str, Any]
    ) -> dict:
        prefix = "signer_info"
        return {
            f"{prefix}_version": signer_info["version"],
            f"{prefix}_digest_algorithm": signer_info["digest_algorithm"],
            f"{prefix}_signature_algorithm": signer_info["signature_algorithm"],
        }

    def extract_raw_features_from_authenticated_attributres(
        self, authenticated_attributes: DefaultDict[str, Any]
    ) -> dict:
        prefix = "signer_info"
        cprefix = "authenticated_attributes"
        return {
            f"{prefix}_{cprefix}_content_type": authenticated_attributes[
                "content_type"
            ],
            f"{prefix}_{cprefix}_program_name": authenticated_attributes[
                "program_name"
            ],
            f"{prefix}_{cprefix}_url": authenticated_attributes["url"],
            f"{prefix}_{cprefix}_message_digest": authenticated_attributes[
                "message_digest"
            ],
        }

    def extract_raw_features(self, raw_json: dict) -> dict:
        signature = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )
        signer_info = _make_defaultdict_from_dict_elem(signature, "signer_info")
        return {
            "version": signature["version"],
            # NOTE: extracted but not converted to feature vector
            **self.extract_raw_features_from_content_info(
                _make_defaultdict_from_dict_elem(signature, "content_info")
            ),
            # NOTE: extracted but not converted to feature vector
            **self.extract_raw_features_from_signer_info(signer_info),
            # NOTE: extracted but not converted to feature vector
            **self.extract_raw_features_from_authenticated_attributres(
                _make_defaultdict_from_dict_elem(
                    signer_info, "authenticated_attributes"
                )
            ),
            # NOTE: extracted but not converted to feature vector
            "signer_info_issuer": signer_info["issuer"],
            # TODO: make feature vector from certificates array
            "certificates": signature["certificates"],
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = ["version"]
        return _vectorize_selected_features(
            raw_features, features_selected, {}, self.feature_name
        )


# NOTE: https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate#parameters
class ProcessHeapFlags(Enum):
    HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
    HEAP_GENERATE_EXCEPTIONS = 0x00000004
    HEAP_NO_SERIALIZE = 0x00000001


class LoadConfigurationFeatureExtractor(FeatureExtractor):
    feature_name: str = "load_configuration"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()

    @staticmethod
    def version_to_onehot(ver: Optional[str]) -> Dict[str, int]:
        return _make_onehot_dict_from_str_keys(
            [
                "UNKNOWN",
                "SEH",
                "WIN_8_1",
                "WIN10_0_9879",
                "WIN10_0_14286",
                "WIN10_0_14383",
                "WIN10_0_14901",
                "WIN10_0_15002",
                "WIN10_0_16237",
            ],
            ver,
        )

    @staticmethod
    def process_heap_flags_to_onehot(phf: Optional[int]) -> Dict[str, int]:
        encoded_data = {str(k): 0 for k in ProcessHeapFlags}
        if phf:
            for k in ProcessHeapFlags:
                if (phf & k.value) != 0:
                    encoded_data[str(k)] = 1
        return encoded_data

    def extract_raw_features_from_code_integrity(
        self, code_integrity: DefaultDict[str, Any]
    ) -> dict:
        prefix = "code_integrity"
        return {
            f"{prefix}_flags": code_integrity["flags"],
            f"{prefix}_catalog": code_integrity["catalog"],
            f"{prefix}_catalog_offset": code_integrity["catalog_offset"],
            f"{prefix}_reserved": code_integrity["reserved"],
        }

    def extract_raw_features(self, raw_json: dict) -> dict:
        load_configuration = _make_defaultdict_from_dict_elem(
            raw_json, self.feature_name
        )

        return {
            "version": self.version_to_onehot(load_configuration["version"]),
            "characteristics": load_configuration["characteristics"],
            "timedatestamp": load_configuration["timedatestamp"],
            "major_version": load_configuration["major_version"],
            "minor_version": load_configuration["minor_version"],
            "global_flags_clear": load_configuration["global_flags_clear"],
            "global_flags_set": load_configuration["global_flags_set"],
            "critical_section_default_timeout": load_configuration[
                "critical_section_default_timeout"
            ],
            "decommit_free_block_threshold": load_configuration[
                "decommit_free_block_threshold"
            ],
            "decommit_total_free_threshold": load_configuration[
                "decommit_total_free_threshold"
            ],
            "lock_prefix_table": load_configuration["lock_prefix_table"],
            "maximum_allocation_size": load_configuration[
                "maximum_allocation_size"
            ],
            "virtual_memory_threshold": load_configuration[
                "virtual_memory_threshold"
            ],
            "process_affinity_mask": load_configuration[
                "process_affinity_mask"
            ],
            "process_heap_flags": self.process_heap_flags_to_onehot(
                load_configuration["process_heap_flags"]
            ),
            "csd_version": load_configuration["csd_version"],
            "reserved1": load_configuration["reserved1"],
            "security_cookie": load_configuration["security_cookie"],
            "se_handler_table": load_configuration["se_handler_table"],
            "se_handler_count": load_configuration["se_handler_count"],
            "guard_cf_check_function_pointer": load_configuration[
                "guard_cf_check_function_pointer"
            ],
            "guard_cf_dispatch_function_pointer": load_configuration[
                "guard_cf_dispatch_function_pointer"
            ],
            "guard_cf_function_table": load_configuration[
                "guard_cf_function_table"
            ],
            "guard_cf_function_count": load_configuration[
                "guard_cf_function_count"
            ],
            "guard_flags": load_configuration["guard_flags"],
            **self.extract_raw_features_from_code_integrity(
                _make_defaultdict_from_dict_elem(
                    load_configuration, "code_integrity"
                )
            ),
            "guard_address_taken_iat_entry_table": load_configuration[
                "guard_address_taken_iat_entry_table"
            ],
            "guard_address_taken_iat_entry_count": load_configuration[
                "guard_address_taken_iat_entry_count"
            ],
            "guard_long_jump_target_table": load_configuration[
                "guard_long_jump_target_table"
            ],
            "guard_long_jump_target_count": load_configuration[
                "guard_long_jump_target_count"
            ],
            "dynamic_value_reloc_table": load_configuration[
                "dynamic_value_reloc_table"
            ],
            "hybrid_metadata_pointer": load_configuration[
                "hybrid_metadata_pointer"
            ],
            "guard_rf_failure_routine": load_configuration[
                "guard_rf_failure_routine"
            ],
            "guard_rf_failure_routine_function_pointer": load_configuration[
                "guard_rf_failure_routine_function_pointer"
            ],
            "dynamic_value_reloctable_offset": load_configuration[
                "dynamic_value_reloctable_offset"
            ],
            "dynamic_value_reloctable_section": load_configuration[
                "dynamic_value_reloctable_section"
            ],
            "reserved2": load_configuration["reserved2"],
            "guard_rf_verify_stackpointer_function_pointer": load_configuration[
                "guard_rf_verify_stackpointer_function_pointer"
            ],
            "hotpatch_table_offset": load_configuration[
                "hotpatch_table_offset"
            ],
            "reserved3": load_configuration["reserved3"],
            "addressof_unicode_string": load_configuration[
                "addressof_unicode_string"
            ],
        }

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        features_selected = [
            "version",
            "characteristics",
            "timedatestamp",
            "major_version",
            "minor_version",
            "minor_version",
            "global_flags_clear",
            "global_flags_set",
            "critical_section_default_timeout",
            "decommit_free_block_threshold",
            "decommit_total_free_threshold",
            "lock_prefix_table",
            "maximum_allocation_size",
            "virtual_memory_threshold",
            "process_affinity_mask",
            "process_heap_flags",
            "csd_version",
            "reserved1",
            "security_cookie",
            "se_handler_table",
            "se_handler_count",
            "guard_cf_check_function_pointer",
            "guard_cf_dispatch_function_pointer",
            "guard_cf_function_table",
            "guard_cf_function_count",
            "guard_flags",
            "code_integrity_flags",
            "code_integrity_catalog",
            "code_integrity_catalog_offset",
            "code_integrity_reserved",
            "guard_address_taken_iat_entry_table",
            "guard_address_taken_iat_entry_count",
            "guard_long_jump_target_table",
            "guard_long_jump_target_count",
            "dynamic_value_reloc_table",
            "hybrid_metadata_pointer",
            "guard_rf_failure_routine",
            "guard_rf_failure_routine_function_pointer",
            "dynamic_value_reloctable_offset",
            "dynamic_value_reloctable_section",
            "reserved2",
            "guard_rf_verify_stackpointer_function_pointer",
            "hotpatch_table_offset",
            "reserved3",
            "addressof_unicode_string",
        ]
        post_process_funcs = {
            "version": lambda x: list(x.values()),
            "process_heap_flags": lambda x: list(x.values()),
        }
        return _vectorize_selected_features(
            raw_features,
            features_selected,
            post_process_funcs,
            self.feature_name,
        )


class LiefFeatureExtractor(FeatureExtractor):
    feature_name = "lief"

    def __init__(self) -> None:
        super(FeatureExtractor, self).__init__()
        self.extractors = (
            DosHeaderFeatureExtractor(),
            RichHeaderFeatureExtractor(),
            HeaderFeatureExtractor(),
            OptionalHeaderFeatureExtractor(),
            DataDirectoriesFeatureExtractor(),
            SectionsFeatureExtractor(),
            RelocationsFeatureExtractor(),
            TlsFeatureExtractor(),
            ExportFeatureExtractor(),
            # DebugFeatureExtractor(),
            ImportsFeatureExtractor(),
            ResourcesTreeFeatureExtractor(),
            ResourcesManagerFeatureExtractor(),
            SignatureFeatureExtractor(),
            LoadConfigurationFeatureExtractor(),
        )

    def extract_raw_features(self, raw_json: dict) -> dict:
        raw_features = {
            extractor.feature_name: extractor.extract_raw_features(raw_json)
            for extractor in self.extractors
        }
        # top-level defined features
        raw_features["entrypoint"] = raw_json["entrypoint"]
        raw_features["virtual_size"] = raw_json["virtual_size"]
        return raw_features

    def vectorize_features(
        self, raw_features: dict
    ) -> Tuple[List[str], np.ndarray]:
        columns: List[str] = ["entrypoint", "virtual_size"]
        vectors: List[np.ndarray] = [
            raw_features["entrypoint"],
            raw_features["virtual_size"],
        ]
        for extractor in self.extractors:
            column, vector = extractor.vectorize_features(
                raw_features[extractor.feature_name]
            )
            columns += column
            vectors.append(vector)
        return columns, np.hstack(vectors)
