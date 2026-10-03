"""异常类型定义。"""


class FileProtectError(Exception):
    """库所有异常的基类。"""


class UnknownFileError(FileProtectError):
    """请求的文件标识不存在。"""


class DuplicateFileError(FileProtectError):
    """同一文件标识被重复导入。"""


class CorruptCiphertextError(FileProtectError):
    """密文损坏或认证失败。"""


class RotationConflictError(FileProtectError):
    """当前状态不允许发起新轮换。"""
