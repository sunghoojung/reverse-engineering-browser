"""Durable, user-only replacement of local workspace documents."""

import os
import tempfile
from pathlib import Path


def atomic_write_private(path: Path, encoded: bytes) -> None:
    """Replace a file only after its complete contents have reached storage.

    Callers own serialization, size limits, validation, and concurrency control.
    The temporary file stays beside the destination so replacement is atomic.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
