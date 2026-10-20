"""Strict local configuration. Fines ante actionem."""

from __future__ import annotations

import hmac
import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from .common import AssuranceError, Resource, RuntimeConfig, read_json, read_secret

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")
_SCHEMA = "access-assurance-lite/config-v1"


def valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def validate_resource_url(value: object, *, allow_http_loopback: bool = False):
    """Return parsed URL or a stable error; URL data never enters errors."""
    try:
        if (not isinstance(value, str) or not 1 <= len(value) <= 2048
                or any(ord(c) < 33 or ord(c) > 126 for c in value)
                or any(c in value for c in "\\?#")):
            raise ValueError
        parts = urlsplit(value)
        host = parts.hostname
        if (parts.scheme not in {"https", "http"} or not host
                or parts.username is not None or parts.password is not None
                or parts.fragment or parts.query or "%" in host
                or parts.port == 0):
            raise ValueError
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
            labels = host.rstrip(".").split(".")
            if (len(host) > 253 or any(not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in labels)):
                raise ValueError
        if parts.scheme == "http" and not (
                allow_http_loopback is True and address is not None and address.is_loopback
                and getattr(address, "ipv4_mapped", None) is None):
            raise AssuranceError("https_required")
        return parts
    except AssuranceError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise AssuranceError("invalid_resource_url") from None


def _object(value, required, optional=()):
    if (not isinstance(value, dict) or not set(required) <= set(value)
            or set(value) - set(required) - set(optional)):
        raise AssuranceError("invalid_config_structure")
    return value


def _identity(value, base):
    value = _object(value, ("id", "token_file"))
    path = value["token_file"]
    if (not valid_identifier(value["id"]) or not isinstance(path, str)
            or not 1 <= len(path) <= 4096 or "\x00" in path or path != path.strip()):
        raise AssuranceError("invalid_identity_config")
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    return value["id"], read_secret(candidate)


def load_config(path, *, allow_http_loopback=False) -> RuntimeConfig:
    if type(allow_http_loopback) is not bool:
        raise AssuranceError("invalid_config_option")
    data = _object(read_json(path, 65536),
                   ("schema", "subject", "control", "resources"),
                   ("timeout_seconds", "max_response_bytes", "freshness_seconds"))
    if data["schema"] != _SCHEMA:
        raise AssuranceError("unsupported_config_schema")
    timeout = data.get("timeout_seconds", 3.0)
    maximum = data.get("max_response_bytes", 16384)
    freshness = data.get("freshness_seconds", 30)
    if (type(timeout) not in (int, float) or not 0.1 <= timeout <= 30
            or not math.isfinite(timeout)):
        raise AssuranceError("invalid_timeout")
    if type(maximum) is not int or not 1024 <= maximum <= 65536:
        raise AssuranceError("invalid_response_limit")
    if type(freshness) is not int or not 1 <= freshness <= 300:
        raise AssuranceError("invalid_freshness")
    entries = data["resources"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise AssuranceError("invalid_resources")
    resources, ids, urls = [], set(), set()
    for entry in entries:
        _object(entry, ("id", "url"))
        if not valid_identifier(entry["id"]):
            raise AssuranceError("invalid_resource_id")
        parts = validate_resource_url(entry["url"], allow_http_loopback=allow_http_loopback)
        canonical_url = (parts.scheme, parts.hostname.lower(),
                         parts.port or (443 if parts.scheme == "https" else 80),
                         parts.path or "/")
        if entry["id"] in ids or canonical_url in urls:
            raise AssuranceError("duplicate_resource")
        ids.add(entry["id"])
        urls.add(canonical_url)
        resources.append(Resource(entry["id"], entry["url"]))
    base = Path(path).absolute().parent
    subject_id, subject_token = _identity(data["subject"], base)
    control_id, control_token = _identity(data["control"], base)
    if subject_id == control_id or hmac.compare_digest(subject_token, control_token):
        raise AssuranceError("identities_must_differ")
    return RuntimeConfig(subject_id, control_id, subject_token, control_token,
                         tuple(resources), float(timeout), maximum, freshness,
                         allow_http_loopback)
