#!/usr/bin/env python3
"""Verify that the JVM PerfData corpus matches the sanitized fixtures."""

import hashlib
import json
from pathlib import Path
import sys


FUZZ_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FUZZ_ROOT.parent
MANIFEST_PATH = (
    REPOSITORY_ROOT / "aic-common/tests/fixtures/jvm_perfdata/manifest.json"
)
CORPUS_PATH = FUZZ_ROOT / "corpus/jvm_perfdata"


def fail(message: str) -> None:
    print(f"corpus parity check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    with MANIFEST_PATH.open(encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        fail("fixture manifest has no fixtures list")

    expected = {}
    for fixture in fixtures:
        if fixture.get("kind") != "sanitized_capture":
            continue
        filename = fixture.get("filename")
        sha256 = fixture.get("sha256")
        if not isinstance(filename, str) or not isinstance(sha256, str):
            fail("sanitized fixture entry has invalid filename or sha256")
        if filename in expected:
            fail(f"duplicate fixture entry: {filename}")
        expected[filename] = sha256.lower()

    if len(expected) != 6:
        fail(f"expected 6 sanitized fixtures, found {len(expected)}")

    if not CORPUS_PATH.is_dir():
        fail(f"missing corpus directory: {CORPUS_PATH}")
    actual = {entry.name for entry in CORPUS_PATH.iterdir()}
    expected_names = set(expected)
    missing = sorted(expected_names - actual)
    extra = sorted(actual - expected_names)
    if missing:
        fail(f"missing corpus entries: {', '.join(missing)}")
    if extra:
        fail(f"extra corpus entries: {', '.join(extra)}")

    for filename, expected_sha256 in sorted(expected.items()):
        corpus_file = CORPUS_PATH / filename
        if not corpus_file.is_file():
            fail(f"corpus entry is not a file: {filename}")
        actual_sha256 = hashlib.sha256(corpus_file.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            fail(
                f"sha256 mismatch for {filename}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )

    print(f"verified {len(expected)} JVM PerfData corpus entries")


if __name__ == "__main__":
    main()
