"""Shared contracts. Veritas intra fines."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AssuranceError(ValueError):
    """An operator-safe error with a stable code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Resource:
    id: str
    url: str


@dataclass(frozen=True)
class RuntimeConfig:
    subject_id: str
    control_id: str
    subject_token: str = field(repr=False)
    control_token: str = field(repr=False)
    resources: tuple[Resource, ...]
    timeout_seconds: float = 3.0
    max_response_bytes: int = 16384
    freshness_seconds: int = 30
    allow_http_loopback: bool = False

    def scope(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "control_id": self.control_id,
            "resources": [{"id": r.id, "url": r.url} for r in self.resources],
            "freshness_seconds": self.freshness_seconds,
        }


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise AssuranceError("invalid_json_value") from None


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise AssuranceError("invalid_timestamp") from None


def read_json(path: str | Path, limit: int = 4 * 1024 * 1024) -> Any:
    if type(limit) is not int or not 1 <= limit <= 16 * 1024 * 1024:
        raise AssuranceError("invalid_document_limit")

    def finite(number):
        value = float(number)
        if not math.isfinite(value):
            raise AssuranceError("invalid_json_number")
        return value

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise AssuranceError("duplicate_json_key")
            value[key] = item
        return value

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise AssuranceError("document_not_regular")
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise AssuranceError("document_too_large")
        return json.loads(raw, object_pairs_hook=unique, parse_float=finite,
                          parse_constant=lambda _: (_ for _ in ()).throw(AssuranceError("invalid_json_number")))
    except AssuranceError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise AssuranceError("document_unreadable") from None


def write_private(path: str | Path, value: Any) -> None:
    data = canonical(value) + b"\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError):
        raise AssuranceError("output_exists_or_unwritable") from None


def read_secret(path: str | Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise AssuranceError("credential_file_not_private")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise AssuranceError("credential_file_wrong_owner")
            value = handle.read(8193)
        if len(value) > 8192:
            raise AssuranceError("credential_too_long")
        token = value.decode("ascii").rstrip("\r\n")
        if not 16 <= len(token) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise AssuranceError("credential_invalid")
        return token
    except AssuranceError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise AssuranceError("credential_unreadable") from None
