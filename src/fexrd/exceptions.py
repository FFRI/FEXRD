#
# (c) FFRI Security, Inc., 2020-2023 / Author: FFRI Security, Inc.
#


class FexrdBaseException(Exception):
    pass


class InvalidVersion(FexrdBaseException):
    def __init__(self, ver: int) -> None:
        self.ver = ver

    def __str__(self) -> str:
        return f"{self.ver} is not valid version"


class NotImplementedYet(FexrdBaseException):
    def __init__(self, ver: int, cls_name: str) -> None:
        self.ver = ver
        self.cls_name = cls_name

    def __str__(self) -> str:
        return (
            f"{self.cls_name} is not implemented for FFRI Dataset version"
            f" v{self.ver}"
        )


class NotSupported(FexrdBaseException):
    def __init__(self, ver: int, cls_name: str) -> None:
        self.ver = ver
        self.cls_name = cls_name

    def __str__(self) -> str:
        return (
            f"{self.cls_name} is not supported for FFRI Dataset version"
            f" v{self.ver}"
        )
