#!/usr/bin/env python3
"""Verify the clean-room SAF-T1602 source archives against their manifest fragment."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research/techniques/SAF-T1602/source-manifest-fragment.yml"
CORPUS = ROOT / "research/sources/SAF-T1602"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    errors: list[str] = []
    referenced: set[Path] = set()
    archived = 0
    remote = 0

    for source in manifest["sources"]:
        source_id = source["id"]
        archive = source["archive"]
        if archive["status"] != "archived":
            remote += 1
            continue
        archived += 1
        for record_name, record in (
            ("archive", archive),
            ("extracted_text", source["extracted_text"]),
        ):
            path = ROOT / record["path"]
            referenced.add(path.resolve())
            if not path.is_file():
                errors.append(f"{source_id} {record_name}: missing {record['path']}")
                continue
            actual_bytes = path.stat().st_size
            actual_hash = digest(path)
            if actual_bytes != record["bytes"]:
                errors.append(
                    f"{source_id} {record_name}: bytes {actual_bytes} != {record['bytes']}"
                )
            if actual_hash != record["sha256"]:
                errors.append(
                    f"{source_id} {record_name}: sha256 {actual_hash} != {record['sha256']}"
                )

    corpus_files = {path.resolve() for path in CORPUS.iterdir() if path.is_file()}
    for extra in sorted(corpus_files - referenced):
        errors.append(f"unreferenced corpus file: {extra.relative_to(ROOT)}")
    for absent in sorted(referenced - corpus_files):
        errors.append(f"referenced file outside corpus or absent: {absent}")

    if errors:
        for error in errors:
            print(f"FAIL {error}")
        return 1
    print(
        f"PASS sources={len(manifest['sources'])} archived={archived} "
        f"remote_reviewed={remote} files={len(corpus_files)} hashes_and_sizes=verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
