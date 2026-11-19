"""Incremental reading of log files with rotation handling.

State per configured file path (``files[path]``)::

    {"log": "access", "seenAt": <unix>, "cur": Slot, "old": Slot | null}
    Slot = {"dev", "ino", "offset", "fp", "fpLen"}

* ``cur`` is the file currently at ``path``; ``offset`` is the byte position after the
  last line the gateway confirmed.
* When the inode at ``path`` changes, the previous ``cur`` becomes ``old``. It is found
  again by inode (``path.1``, dateext names like ``path-20261111``) and read to the end,
  then dropped. Compressed rotations (``.gz`` …) are never read.
* A file that became smaller than the offset, or whose first bytes changed
  (fingerprint), is read again from the start (copytruncate, recreated file).
* On first sight of a path, an uncompressed ``path.1`` is read as well (backfill; the
  30 day limit applies to lines).
* Paths matched by several globs or symlinks are read once (same device and inode).
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

FP_BYTES = 1024
READ_CHUNK = 1024 * 1024
MAX_LINE = 64 * 1024
PRUNE_AFTER_SECONDS = 7 * 86400
COMPRESSED = (".gz", ".bz2", ".xz", ".zst", ".zip", ".lz4", ".z")
NUMBERED_ROTATION = re.compile(r"\.\d{1,2}$")


@dataclass
class Unit:
    key: str  # configured path (state key)
    slot: str  # "cur" or "old"
    log: str  # "access" or "error"
    path: str  # file to open
    dev: int
    ino: int
    start: int

    @property
    def batch_prefix(self) -> str:
        name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(self.key))[:48] or "log"
        return f"{self.log}.{self.ino}.{name}"


def _fingerprint(path: str, length: int) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read(length)).hexdigest()


def _slot(st: os.stat_result, offset: int = 0) -> dict:
    return {"dev": st.st_dev, "ino": st.st_ino, "offset": offset, "fp": "", "fpLen": 0}


def _same(slot: dict, st: os.stat_result) -> bool:
    return slot.get("dev") == st.st_dev and slot.get("ino") == st.st_ino


def is_candidate(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(COMPRESSED):
        return False
    return not NUMBERED_ROTATION.search(path)


def discover(patterns: List[str]) -> List[str]:
    found: List[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern)) if glob.has_magic(pattern) else ([pattern] if os.path.exists(pattern) else [])
        for path in matches:
            if os.path.isfile(path) and is_candidate(path) and path not in found:
                found.append(path)
    return found


def _locate(base: str, slot: dict) -> Optional[str]:
    """Find the rotated copy of ``slot`` by device and inode."""
    candidates = [base + ".1"]
    directory = os.path.dirname(base) or "."
    prefix = os.path.basename(base)
    try:
        for name in sorted(os.listdir(directory)):
            if name.startswith(prefix) and name != prefix and not name.lower().endswith(COMPRESSED):
                candidates.append(os.path.join(directory, name))
    except OSError:
        pass
    for path in candidates:
        try:
            st = os.stat(path)
        except OSError:
            continue
        if _same(slot, st):
            return path
    return None


def plan_units(
    files: Dict[str, dict],
    paths: List[Tuple[str, str]],
    now: float,
    warn: Callable[[str], None],
) -> List[Unit]:
    """Update ``files`` (state) for this run and return the files to read, in order."""
    units: List[Unit] = []
    claimed: Set[Tuple[int, int]] = set()
    for base, log in paths:
        try:
            st = os.stat(base)
        except OSError as exc:
            warn(f"logs: cannot read {base}: {exc.strerror}")
            continue
        if (st.st_dev, st.st_ino) in claimed:
            continue  # symlink or second glob for the same file
        entry = files.get(base)
        if entry is None:
            entry = {"log": log, "cur": _slot(st), "old": None}
            rotated = base + ".1"
            try:
                rst = os.stat(rotated)
                if os.path.isfile(rotated) and not _same(entry["cur"], rst):
                    entry["old"] = _slot(rst)
            except OSError:
                pass
        elif not _same(entry["cur"], st):
            if entry.get("old"):
                warn(f"logs: {base} was rotated twice since the last run; the rest of the older file is skipped")
            entry["old"] = entry["cur"]
            entry["cur"] = _slot(st)
        entry["log"] = log
        entry["seenAt"] = now

        old = entry.get("old")
        if old:
            path = _locate(base, old)
            if path is None:
                warn(f"logs: rotated copy of {base} not found (compressed or removed); continuing with the new file")
                entry["old"] = None
            else:
                ost = os.stat(path)
                if old["offset"] > ost.st_size:
                    old["offset"] = 0
                units.append(Unit(base, "old", log, path, ost.st_dev, ost.st_ino, old["offset"]))
                claimed.add((ost.st_dev, ost.st_ino))

        cur = entry["cur"]
        try:
            if st.st_size < cur["offset"] or (cur.get("fpLen") and (
                st.st_size < cur["fpLen"] or _fingerprint(base, cur["fpLen"]) != cur["fp"]
            )):
                if cur["offset"]:
                    warn(f"logs: {base} was truncated or replaced; reading it from the start")
                cur["offset"] = 0
            length = min(st.st_size, FP_BYTES)
            if length > cur.get("fpLen", 0):
                cur["fp"], cur["fpLen"] = _fingerprint(base, length), length
        except OSError as exc:
            warn(f"logs: cannot read {base}: {exc.strerror}")
            continue
        units.append(Unit(base, "cur", log, base, st.st_dev, st.st_ino, cur["offset"]))
        claimed.add((st.st_dev, st.st_ino))
        files[base] = entry

    # forget files that disappeared a week ago
    for key in [k for k, v in files.items() if now - float(v.get("seenAt", 0)) > PRUNE_AFTER_SECONDS]:
        del files[key]
    return units


def commit(files: Dict[str, dict], unit: Unit, offset: int) -> None:
    entry = files.get(unit.key)
    if entry is None:
        return
    slot = entry.get(unit.slot)
    if slot and slot.get("ino") == unit.ino:
        slot["offset"] = offset


def finish_old(files: Dict[str, dict], unit: Unit) -> None:
    """The rotated copy is read completely: forget it."""
    entry = files.get(unit.key)
    if entry and unit.slot == "old" and entry.get("old") and entry["old"].get("ino") == unit.ino:
        entry["old"] = None


def read_lines(path: str, start: int) -> Iterator[Tuple[Optional[str], int, int]]:
    """Yield ``(text, line_start, line_end)`` for complete lines from ``start``.

    ``text`` is ``None`` for lines longer than ``MAX_LINE`` (skipped, offset still advances).
    An incomplete last line (no newline yet) is left for the next run.
    """
    with open(path, "rb") as fh:
        fh.seek(start)
        pos = start
        buf = b""
        oversized = False
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                return
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    if len(buf) > MAX_LINE:
                        pos += len(buf)
                        buf = b""
                        oversized = True
                    break
                raw, buf = buf[:nl], buf[nl + 1:]
                begin, pos = pos, pos + nl + 1
                if oversized or len(raw) > MAX_LINE:
                    oversized = False
                    yield None, begin, pos
                    continue
                yield raw.rstrip(b"\r").decode("utf-8", errors="replace"), begin, pos
