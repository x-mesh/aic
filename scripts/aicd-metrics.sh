#!/usr/bin/env bash
#
# aicd-metrics.sh
# -----------------------------------------------------------------------------
# aicd control socket 에 GetMetrics IPC 를 직접 보내 snapshot 을 출력한다.
# 실제로 몇 개의 세션이 attach 했는지, central_store_push_total 이 증가하는지
# 의 "진실" 은 aicd 쪽 카운터에만 있다.
# -----------------------------------------------------------------------------

set -u
set -o pipefail

SOCK="/tmp/aic-$(id -u)/aicd.sock"
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/aic/aicd.sock" ]; then
    SOCK="$XDG_RUNTIME_DIR/aic/aicd.sock"
fi

if [ ! -S "$SOCK" ]; then
    echo "error: aicd control socket 이 없습니다: $SOCK" >&2
    exit 1
fi

python3 - "$SOCK" <<'PY'
import json, socket, struct, sys

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
req = json.dumps("GetMetrics").encode("utf-8")
s.sendall(struct.pack(">I", len(req)) + req)

# response: 4-byte BE length + JSON
hdr = b""
while len(hdr) < 4:
    chunk = s.recv(4 - len(hdr))
    if not chunk:
        raise RuntimeError("unexpected eof on header")
    hdr += chunk
plen = struct.unpack(">I", hdr)[0]

body = b""
while len(body) < plen:
    chunk = s.recv(plen - len(body))
    if not chunk:
        raise RuntimeError("unexpected eof on body")
    body += chunk

resp = json.loads(body)
# IpcResponse::Metrics(MetricsSnapshot) -> {"Metrics": {...}}
snap = resp.get("Metrics") if isinstance(resp, dict) else None
if snap is None:
    print("unexpected response:", json.dumps(resp, indent=2))
    sys.exit(2)

fields = [
    "pid",
    "uptime_secs",
    "ipc_request_count",
    "central_store_push_total",
    "attach_connections",
    "attach_open_total",
    "dropped_bytes",
    "attach_reconnect_total",
]
for k in fields:
    print(f"  {k:26s} {snap.get(k, 'n/a')}")
PY
