"""Shared Rust derivation for the browser development server.

A missing binary leaves the explicitly labelled lexical engine available. Once
selected, worker failures are surfaced rather than silently changing engines.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from deobfuscation import DeobfuscationError

_LOCK = threading.Lock()
_MAX_OUTPUT = 32 * 1024 * 1024


class WorkerError(DeobfuscationError):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def worker_path():
    configured = os.environ.get('REB_DEOBFUSCATOR_WORKER')
    if configured:
        path = Path(configured)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise WorkerError('Configured deobfuscation worker is unavailable', 503)
        return path
    root = Path(__file__).resolve().parent.parent / 'deobfuscator-worker/target'
    for profile in ('debug', 'release'):
        path = root / profile / 'reb-deobfuscator-worker'
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def derive_with_worker(source):
    path = worker_path()
    if path is None:
        return None
    if not _LOCK.acquire(blocking=False):
        raise WorkerError('Deobfuscation worker is busy; retry when analysis finishes', 409)
    try:
        with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as output:
            input_file.write(json.dumps({'source': source}).encode() + b'\n')
            input_file.seek(0)
            try:
                result = subprocess.run([str(path)], stdin=input_file, stdout=output, stderr=subprocess.DEVNULL, timeout=5, env={'LANG': 'C', 'LC_ALL': 'C'}, check=False)
            except subprocess.TimeoutExpired as error:
                raise WorkerError('Deobfuscation exceeded five seconds', 408) from error
            except OSError as error:
                raise WorkerError('Deobfuscation worker could not start', 503) from error
            output.seek(0)
            data = output.read(_MAX_OUTPUT + 1)
            if result.returncode:
                raise WorkerError('JavaScript analysis worker terminated unexpectedly; original source is preserved', 502)
            if len(data) > _MAX_OUTPUT:
                raise WorkerError('Deobfuscation worker returned an invalid response', 502)
        try:
            document = json.loads(data)
            if document['schema'] != 'reb-deobfuscator-worker-v1':
                raise ValueError('schema')
            if document['ok'] is not True:
                raise WorkerError('JavaScript could not be parsed', 422)
            rewrites = document['transformations']
            derived = document['derived_source']
            if not isinstance(rewrites, list) or len(rewrites) > 4096 or not isinstance(derived, str):
                raise ValueError('shape')
            original = source.encode()
            segments = []
            rebuilt = bytearray()
            offset = 0
            counts = {}

            def append(kind, start, end, replacement):
                begin = len(rebuilt)
                rebuilt.extend(replacement)
                segments.append({'kind': kind, 'original_start': start, 'original_end': end, 'derived_start': begin, 'derived_end': len(rebuilt)})

            for rewrite in rewrites:
                start, end = rewrite['original_start'], rewrite['original_end']
                if type(start) is not int or type(end) is not int or not offset <= start < end <= len(original):
                    raise ValueError('ranges')
                if start > offset:
                    append('verbatim', offset, start, original[offset:start])
                append('replacement', start, end, rewrite['replacement'].encode())
                offset = end
                kind = rewrite['kind']
                counts[kind] = counts.get(kind, 0) + 1
            if offset < len(original):
                append('verbatim', offset, len(original), original[offset:])
            if rebuilt.decode() != derived:
                raise ValueError('source map')
            return {'text': derived, 'offset_unit': 'utf-8-byte', 'segments': segments,
                    'truncated': bool(document['transformations_truncated']),
                    'transformations': [{'id': kind, 'kind': 'rewrite', 'count': count,
                                         'detail': 'Static AST rewrite with original-source mapping; no JavaScript execution.'}
                                        for kind, count in sorted(counts.items())]}
        except WorkerError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise WorkerError('Deobfuscation worker returned an invalid response', 502) from error
    finally:
        _LOCK.release()
