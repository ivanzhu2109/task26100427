"""Local file protection library: AES-256 encryption with crash-safe key rotation."""

from .store import FileProtector, RotationResult, Status

__all__ = ["FileProtector", "RotationResult", "Status"]
__version__ = "0.1.0"
