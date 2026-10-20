"""Build a deterministic, runtime-dependency-free Python executable archive."""

from pathlib import Path
import hashlib
import zipfile


def build(destination):
    root = Path(__file__).resolve().parents[1]
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            files = {str(p.relative_to(root / "src")): p.read_bytes()
                     for p in sorted((root / "src").rglob("*.py"))}
            files["__main__.py"] = b"from assurance_lite.cli import main\nraise SystemExit(main())\n"
            files["LICENSE"] = (root / "LICENSE").read_bytes()
            files["DISTRIBUTION.md"] = (root / "DISTRIBUTION.md").read_bytes()
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                bundle.writestr(info, content)
    return hashlib.sha256(target.read_bytes()).hexdigest()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    args = parser.parse_args()
    print(build(args.output))
