"""State directory: offsets per log file, cached ingest config, retry deadline, run lock."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from typing import Any, Dict, Optional

STATE_FILE = "state.json"
LOCK_FILE = "collector.lock"
STATE_VERSION = 1


def ensure_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)


def atomic_write_json(path: str, data: Any) -> None:
    directory = os.path.dirname(path) or "."
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"), sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class State:
    """JSON state; ``readonly`` (dry run) never writes."""

    def __init__(self, directory: Optional[str], readonly: bool = False):
        self.dir = directory
        self.readonly = readonly or not directory
        self.data: Dict[str, Any] = {"version": STATE_VERSION, "files": {}, "config": None, "retryNotBefore": 0}
        if directory:
            try:
                with open(os.path.join(directory, STATE_FILE), encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict) and loaded.get("version") == STATE_VERSION:
                    self.data.update(loaded)
            except (OSError, ValueError):
                pass
        self.data.setdefault("files", {})

    @property
    def files(self) -> Dict[str, Any]:
        return self.data["files"]

    def save(self) -> None:
        if self.readonly:
            return
        assert self.dir is not None
        atomic_write_json(os.path.join(self.dir, STATE_FILE), self.data)


class RunLock:
    """Exclusive ``flock`` so that two runs (cron + manual) never overlap."""

    def __init__(self, directory: str):
        self.path = os.path.join(directory, LOCK_FILE)
        self.fd: Optional[int] = None

    def acquire(self) -> bool:
        ensure_dir(os.path.dirname(self.path))
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            return False
        return True

    def release(self) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None
