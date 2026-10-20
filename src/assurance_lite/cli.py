"""Terminal operations. Testimonium non est praesentia."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .common import AssuranceError, canonical, parse_time, read_json, write_private


EXIT = {"VERIFIED": 0, "READY": 0, "RESIDUAL": 2, "UNKNOWN": 3}


def _emit(value, machine=False):
    if machine:
        print(canonical(value).decode("ascii"))
        return
    print("ACCESS ASSURANCE / LITE")
    print("Veritas intra fines.\n")
    if isinstance(value, dict) and "state" in value:
        label = "Recorded result: " if value.get("currentness") == "HISTORICAL_ONLY" else "Result: "
        print(label + json.dumps(value["state"], ensure_ascii=True))
        for item in value.get("resources", []):
            print("  " + json.dumps(item["resource_id"], ensure_ascii=True) + "  recorded=" + item["state"])
        if "currentness" in value:
            print("Evidence: " + value["currentness"])
        if "expires_at" in value:
            print("Observation deadline: " + value["expires_at"])
        if "artifact_sha256" in value:
            print("Artifact integrity: " + value["artifact_sha256"])
    else:
        print(json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False))


def _summary(envelope, *, saved=False):
    from .evidence import verify
    payload = verify(envelope)
    now = datetime.now(timezone.utc)
    expires = parse_time(payload["expires_at"])
    currentness = "HISTORICAL_ONLY" if saved else ("FRESH_AT_COMPLETION" if now < expires else "STALE")
    state = payload["state"]
    if not saved and now >= expires:
        state = "UNKNOWN"
    return {
        "kind": payload["kind"], "state": state,
        "recorded_state": payload["state"], "currentness": currentness,
        "expires_at": payload["expires_at"], "artifact_sha256": envelope["sha256"],
        "resources": [{"resource_id": r["resource_id"], "state": r["state"]}
                      for r in payload["results"]],
        "resource_states": "RECORDED_AT_COMPLETION; inspect original observations for individual deadlines",
        "boundary": "Only configured credentials, resources and observation times; trusted resource protocol.",
    }


def _config(args):
    from .config import load_config
    return load_config(args.config, allow_http_loopback=args.allow_http_loopback)


def _new_directory(path):
    try:
        Path(path).mkdir(mode=0o700)
    except OSError:
        raise AssuranceError("directory_exists_or_unwritable") from None


def _init(args):
    _new_directory(args.directory)
    document = {
        "schema": "access-assurance-lite/config-v1",
        "subject": {"id": "subject-example", "token_file": "subject.token"},
        "control": {"id": "control-example", "token_file": "control.token"},
        "resources": [{"id": "resource-example", "url": "https://app.example.invalid/assurance/probe"}],
        "timeout_seconds": 3, "max_response_bytes": 16384, "freshness_seconds": 30,
    }
    write_private(Path(args.directory) / "config.json", document)
    return {"created": "config.json", "credentials_created": False,
            "next": "Configure your trusted probe endpoint and distinct private token files (mode 0600), then baseline."}


def _csv_cell(value):
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        text = "'" + text
    return text


def _csv_export(envelope, path):
    from .evidence import verify
    p = verify(envelope)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["resource", "recorded_state", "observed_at", "expires_at", "evidence_scope"])
    for row in p["results"]:
        writer.writerow([_csv_cell(row["resource_id"]), row["state"],
                         p["created_at"], p["expires_at"], "HISTORICAL_ONLY"])
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(output.getvalue())
    except OSError:
        raise AssuranceError("output_exists_or_unwritable") from None


def _compare(args):
    from .evidence import verify
    before = verify(read_json(args.before))
    after = verify(read_json(args.after))
    if before["kind"] != "check" or after["kind"] != "check":
        raise AssuranceError("comparison_requires_checks")
    if before["scope"] != after["scope"] or before["baseline"]["sha256"] != after["baseline"]["sha256"]:
        raise AssuranceError("comparison_scope_mismatch")
    if parse_time(before["created_at"]) > parse_time(after["created_at"]):
        raise AssuranceError("comparison_order_invalid")
    old = {r["resource_id"]: r["state"] for r in before["results"]}
    changes = [{"resource_id": r["resource_id"], "before": old[r["resource_id"]], "after": r["state"]}
               for r in after["results"] if old[r["resource_id"]] != r["state"]]
    return {"currentness": "HISTORICAL_ONLY", "changes": changes, "changed": bool(changes)}


def _watch(args):
    from .engine import check
    if not 1 <= args.count <= 720 or not 0.1 <= args.interval <= 60 or args.count * args.interval > 3600:
        raise AssuranceError("watch_limits_exceeded")
    cfg = _config(args)
    baseline = read_json(args.baseline)
    _new_directory(args.directory)
    last = None
    count = 0
    started = time.monotonic()
    for index in range(args.count):
        if time.monotonic() - started >= 3600:
            break
        envelope = check(cfg, baseline)
        write_private(Path(args.directory) / f"check-{index + 1:04d}.json", envelope)
        last = _summary(envelope)
        last["sequence"] = index + 1
        _emit(last, args.json)
        count += 1
        if index + 1 < args.count:
            time.sleep(args.interval)
    if last is None:
        raise AssuranceError("watch_no_observation")
    write_private(Path(args.directory) / "summary.json", {
        "samples": count, "last_recorded_state": last["state"],
        "currentness": "HISTORICAL_ONLY", "elapsed_seconds": round(time.monotonic() - started, 3),
    })
    return EXIT.get(last["state"], 4)


def parser():
    p = argparse.ArgumentParser(prog="assurance-lite", description="Bounded application access verification. No administrative mutations.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("doctor", "benchmark"):
        c = sub.add_parser(command)
        c.add_argument("--json", action="store_true")
    c = sub.add_parser("init")
    c.add_argument("--directory", required=True)
    c.add_argument("--json", action="store_true")
    c = sub.add_parser("demo")
    c.add_argument("--directory", required=True)
    c.add_argument("--json", action="store_true")
    for command in ("baseline", "check", "watch"):
        c = sub.add_parser(command)
        c.add_argument("--config", required=True)
        c.add_argument("--allow-http-loopback", action="store_true")
        c.add_argument("--json", action="store_true")
        if command != "baseline":
            c.add_argument("--baseline", required=True)
        if command == "watch":
            c.add_argument("--directory", required=True)
            c.add_argument("--count", type=int, default=10)
            c.add_argument("--interval", type=float, default=2)
        else:
            c.add_argument("--out", required=True)
    c = sub.add_parser("inspect")
    c.add_argument("artifact")
    c.add_argument("--json", action="store_true")
    c.add_argument("--csv")
    c = sub.add_parser("compare")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--json", action="store_true")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "watch":
            return _watch(args)
        if args.command == "doctor":
            result = {"version": __version__, "python": platform.python_version(),
                      "platform": platform.system(), "runtime_dependencies": 0,
                      "network_used": False, "telemetry": False,
                      "supported_platform": sys.platform.startswith("linux"),
                      "edition": "Lite public alpha"}
        elif args.command == "init":
            result = _init(args)
        elif args.command == "demo":
            from .lab import run_demo
            result = run_demo(args.directory)
        elif args.command == "benchmark":
            from .benchmark import run_benchmark
            result = run_benchmark()
        elif args.command == "compare":
            result = _compare(args)
        elif args.command == "inspect":
            doc = read_json(args.artifact)
            result = _summary(doc, saved=True)
            if args.csv:
                _csv_export(doc, args.csv)
        else:
            from .engine import baseline, check
            cfg = _config(args)
            doc = baseline(cfg) if args.command == "baseline" else check(cfg, read_json(args.baseline))
            write_private(args.out, doc)
            result = _summary(doc)
        _emit(result, args.json)
        if args.command in ("baseline", "check"):
            return EXIT.get(result["state"], 4)
        if args.command == "benchmark" and result.get("mismatch_count", 0):
            return 4
        return 0
    except AssuranceError as exc:
        print(canonical({"error": exc.code}).decode("ascii"), file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print('{"error":"interrupted"}', file=sys.stderr)
        return 130
    except Exception:
        print('{"error":"operation_failed"}', file=sys.stderr)
        return 4
