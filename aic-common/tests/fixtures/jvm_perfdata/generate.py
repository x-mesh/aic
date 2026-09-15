#!/usr/bin/env python3
"""Capture pinned Temurin PerfData and retain only required numeric counters."""

import argparse
import base64
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

IMAGES = {
    "17.0.20": "eclipse-temurin@sha256:36d9a76dc231587873b103c68a789b85d91b41d314dda69730d6bc43a777f2a9",
    "21.0.12": "eclipse-temurin@sha256:1f79c73404fb0cccf9a3459eda22892f368d994b1028d6fb1ae871c1f49749a6",
    "25.0.4": "eclipse-temurin@sha256:dcf835e52330939b6c9f90ecab8aafcbcaa8fbf48423db44de884cf978c10144",
}
COLLECTORS = {"G1": "-XX:+UseG1GC", "ZGC": "-XX:+UseZGC"}
REQUIRED = (
    "java.threads.started",
    "java.threads.live",
    "java.threads.livePeak",
    "java.threads.daemon",
    "java.cls.loadedClasses",
    "java.cls.sharedLoadedClasses",
    "java.cls.unloadedClasses",
    "java.cls.sharedUnloadedClasses",
)
EXPECTED_METADATA = {
    REQUIRED[0]: (b"J", 4, 2),
    REQUIRED[1]: (b"J", 1, 3),
    REQUIRED[2]: (b"J", 1, 3),
    REQUIRED[3]: (b"J", 1, 3),
    REQUIRED[4]: (b"J", 4, 2),
    REQUIRED[5]: (b"J", 4, 2),
    REQUIRED[6]: (b"J", 4, 2),
    REQUIRED[7]: (b"J", 4, 2),
}
IMAGE_RE = re.compile(r"^eclipse-temurin@sha256:[0-9a-f]{64}$")
CAPTURE_SCRIPT = r"""
cat >/tmp/Sleep.java <<'EOF'
public final class Sleep {
    public static void main(String[] args) throws Exception { Thread.sleep(30000L); }
}
EOF
javac -d /tmp /tmp/Sleep.java
java "$1" -cp /tmp Sleep &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
file="/tmp/hsperfdata_$(id -un)/$pid"
attempt=0
while [ ! -s "$file" ] || [ "$(od -An -tu1 -j7 -N1 "$file" | tr -d ' ')" != 1 ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || exit 70
    sleep 0.05
done
base64 "$file" | tr -d '\n'
"""


def unpack_i32(data, offset, order):
    return struct.unpack_from(order + "i", data, offset)[0]


def parse_required(data):
    if len(data) < 32 or data[:4] != bytes.fromhex("cafec0c0"):
        raise ValueError("invalid PerfData magic or prologue")
    order = {1: "<"}.get(data[4])
    if order is None or data[5:8] != bytes((2, 0, 1)):
        raise ValueError("capture is not accessible PerfData v2.0")
    used = unpack_i32(data, 8, order)
    cursor = unpack_i32(data, 24, order)
    count = unpack_i32(data, 28, order)
    if not 32 <= cursor <= used <= len(data) or not 0 <= count <= 4096:
        raise ValueError("invalid PerfData bounds")
    found = {}
    for _ in range(count):
        if cursor % 8:
            raise ValueError("misaligned PerfData entry")
        length, name_offset, vector_length = struct.unpack_from(order + "iii", data, cursor)
        data_type, flags, units, variability = struct.unpack_from("BBBB", data, cursor + 12)
        data_offset = unpack_i32(data, cursor + 16, order)
        end = cursor + length
        if length < 20 or length % 8 or end > used:
            raise ValueError("invalid PerfData entry length")
        name_start = cursor + name_offset
        name_end = data.find(b"\0", name_start, min(end, name_start + 256))
        if name_end < 0:
            raise ValueError("unterminated PerfData entry name")
        name = data[name_start:name_end].decode("ascii")
        if name in EXPECTED_METADATA:
            actual = (bytes((data_type,)), units, variability)
            if actual != EXPECTED_METADATA[name] or flags != 1 or vector_length != 0:
                raise ValueError(f"unexpected metadata for {name}")
            if name in found:
                raise ValueError(f"duplicate required counter {name}")
            value = struct.unpack_from(order + "q", data, cursor + data_offset)[0]
            if value < 0:
                raise ValueError(f"negative required counter {name}")
            found[name] = (value, data_type, flags, units, variability)
        cursor = end
    if cursor != used or set(found) != set(REQUIRED):
        raise ValueError("required counter set is incomplete")
    return found


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def sanitize(found):
    output = bytearray(32)
    output[:8] = bytes.fromhex("cafec0c0") + bytes((1, 2, 0, 1))
    struct.pack_into("<iiqii", output, 8, 0, 0, 0, 32, len(REQUIRED))
    for name in REQUIRED:
        value, data_type, flags, units, variability = found[name]
        encoded_name = name.encode("ascii")
        data_offset = align_up(20 + len(encoded_name) + 1, 8)
        entry_length = align_up(data_offset + 8, 8)
        entry = bytearray(entry_length)
        struct.pack_into("<iiiBBBBi", entry, 0, entry_length, 20, 0, data_type, flags, units, variability, data_offset)
        entry[20:20 + len(encoded_name)] = encoded_name
        struct.pack_into("<q", entry, data_offset, value)
        output.extend(entry)
    struct.pack_into("<i", output, 8, len(output))
    return bytes(output)


def capture(docker, image, collector):
    if not IMAGE_RE.fullmatch(image):
        raise ValueError(f"image must use a full eclipse-temurin digest: {image}")
    command = [
        docker, "run", "--rm", "--network", "none",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--entrypoint", "/bin/sh", image, "-eu", "-c", CAPTURE_SCRIPT, "sh", collector,
    ]
    encoded = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    return base64.b64decode(encoded, validate=True)


def expected(values):
    raw = {name: values[name][0] for name in REQUIRED}
    unloaded = raw[REQUIRED[6]] + raw[REQUIRED[7]]
    if raw[REQUIRED[3]] > raw[REQUIRED[1]] or raw[REQUIRED[1]] > raw[REQUIRED[2]]:
        raise ValueError("captured thread counters violate required invariants")
    if raw[REQUIRED[4]] + raw[REQUIRED[5]] < unloaded:
        raise ValueError("captured class counters violate required invariants")
    return {
        "threads_started_total": raw[REQUIRED[0]],
        "threads_live": raw[REQUIRED[1]],
        "threads_peak": raw[REQUIRED[2]],
        "threads_daemon": raw[REQUIRED[3]],
        "classes_loaded": raw[REQUIRED[4]] + raw[REQUIRED[5]] - unloaded,
        "classes_unloaded_total": unloaded,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    for build, image in IMAGES.items():
        parser.add_argument(f"--image-{build.split('.')[0]}", default=image)
    args = parser.parse_args()
    images = {build: getattr(args, f"image_{build.split('.')[0]}") for build in IMAGES}
    args.output.mkdir(parents=True, exist_ok=True)
    generator_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    fixtures = []
    for build, image in images.items():
        digest = image.split("@", 1)[1]
        for gc, flag in COLLECTORS.items():
            values = parse_required(capture(args.docker, image, flag))
            sanitized = sanitize(values)
            filename = f"temurin-{build}-{gc.lower()}.bin"
            (args.output / filename).write_bytes(sanitized)
            fixtures.append({
                "filename": filename,
                "sha256": hashlib.sha256(sanitized).hexdigest(),
                "kind": "sanitized_capture",
                "vendor": "Eclipse Temurin",
                "build": build,
                "gc": gc,
                "byte_order": "little-endian",
                "format": "2.0",
                "source_image_digest": digest,
                "expected": expected(values),
            })
    manifest = {"schema_version": 1, "generator_sha256": generator_sha256, "fixtures": fixtures}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
