from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from debugger.limits import (
    MAX_HEAP_SNAPSHOT_BYTES,
    MAX_HEAP_SNAPSHOT_CHUNK_BYTES,
)


@dataclass
class HeapSnapshotCollector:
    path: Path
    stream: Any
    byte_count: int = 0
    chunk_count: int = 0
    error: Optional[str] = None

    def append(self, chunk: Any) -> None:
        if self.error is not None:
            return
        if not isinstance(chunk, str):
            self.error = "Debugger returned a malformed heap snapshot chunk"
            return
        encoded = chunk.encode("utf-8")
        if len(encoded) > MAX_HEAP_SNAPSHOT_CHUNK_BYTES:
            self.error = "Debugger returned an oversized heap snapshot chunk"
            return
        if self.byte_count + len(encoded) > MAX_HEAP_SNAPSHOT_BYTES:
            self.error = "Heap snapshot exceeds the 256 MiB capture limit"
            return
        try:
            self.stream.write(encoded)
        except OSError:
            self.error = "Heap snapshot could not be written to local temporary storage"
            return
        self.byte_count += len(encoded)
        self.chunk_count += 1

    def close(self) -> None:
        try:
            self.stream.close()
        except OSError:
            if self.error is None:
                self.error = "Heap snapshot temporary storage could not be closed"


@dataclass(frozen=True)
class HeapSnapshotCapture:
    path: Path
    target_id: str
    byte_count: int
    captured_at_ms: int
