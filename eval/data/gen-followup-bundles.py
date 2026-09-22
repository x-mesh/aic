#!/usr/bin/env python3
"""probe-judgments.json의 fixture를 묶어 follow-up 번들을 만든다.

정답은 구성상 정해진다: 신호 섹션 하나가 문제 대상을 드러내고, 그 대상을 더 깊이 보는 템플릿이
정답이다. 잡음 섹션은 판정이 none인 fixture에서 가져온다. 실제 호스트 출력은 섞이지 않는다.

docker·k8s 신호 섹션은 기존 fixture에 없어 여기서 직접 쓴다. 형식은 probes.rs의 명령이 내는
출력 형태(docker ps --format 표, kubectl get pods 표)를 따른다.
"""
import json, random, pathlib

SRC = pathlib.Path(__file__).with_name("probe-judgments.json")
OUT = pathlib.Path(__file__).with_name("followup-bundles.json")
cases = json.loads(SRC.read_text())["cases"]
rng = random.Random(20260922)

def sec(probe, cmd, stdout):
    return f"## {probe}\ncommand: {cmd}\nexit_code=0 duration_ms=1 truncated=false cwd=.\n--- stdout ---\n{stdout}\n\n--- stderr ---\n"

def stdout_of(section):
    body = section.split("--- stdout ---", 1)[1] if "--- stdout ---" in section else section
    return body.split("--- stderr ---", 1)[0].strip()

# 잡음은 clean-negative만 쓴다. boundary-negative(임계 바로 아래)를 섞으면 "신호 없음" 번들에 49.98%
# 같은 값이 들어가고, 그것을 follow-up 대상으로 고른 것을 오답으로 세게 된다 — 판정 실험에서 이미
# 확인한 fixture 설계 문제다.
none_pool = [c for c in cases if c["expected"] == "none"
             and "clean-negative" in c["traits"] and "excluded-mount" not in c["traits"]]
def noise(k, exclude_probe):
    pool = [c for c in none_pool if c["probe_id"] != exclude_probe]
    return [c["section"] for c in rng.sample(pool, k)]

bundles = []
def add(bid, split, symptom, signal_sections, accepted, traits, source):
    k = rng.choice([2, 3])
    secs = list(signal_sections) + noise(k, signal_sections and "" or "")
    rng.shuffle(secs)
    bundles.append({
        "id": bid, "split": split, "symptom": symptom,
        "evidence": "".join(secs), "accepted": accepted,
        "source": source, "traits": traits,
    })

# ── failed_units → journal_unit <unit> ──
fu = [c for c in cases if c["probe_id"] == "failed_units" and c["expected"] != "none"]
for i, c in enumerate(fu):
    units = []
    for line in stdout_of(c["section"]).splitlines():
        for tok in line.split():
            if tok.endswith((".service", ".timer", ".socket", ".mount")):
                units.append(tok); break
    if not units: continue
    split = "dev" if i < 3 else "final"
    add(f"fu-{i+1:02d}", split, "서비스가 죽었습니다", [c["section"]],
        [f"journal_unit {u}" for u in units],
        ["signal:failed_units", "multi-target" if len(units) > 1 else "single-target"],
        f"fixture:{c['id']}")

# ── proc_fd_top → proc_fd <pid> (fd 열이 가장 큰 PID) ──
pf = [c for c in cases if c["probe_id"] == "proc_fd_top" and c["expected"] != "none"]
for i, c in enumerate(pf):
    rows = []
    for line in stdout_of(c["section"]).splitlines():
        t = line.split()
        if len(t) >= 3 and t[0].isdigit() and t[1].isdigit():
            rows.append((int(t[0]), t[1]))
    if not rows: continue
    top_pid = max(rows)[1]
    split = "dev" if i < 3 else "final"
    add(f"pf-{i+1:02d}", split, "파일 디스크립터 누수가 의심됩니다", [c["section"]],
        [f"proc_fd {top_pid}"], ["signal:proc_fd_top"], f"fixture:{c['id']}")

# ── docker_ps → docker_logs|docker_inspect_container|docker_health <name> ──
docker_rows = [
    ("web-1",   "nginx:1.25",   "Up 7 days",                         "Up"),
    ("api-2",   "myapp:2.1",    "Restarting (1) 12 seconds ago",     "bad"),
    ("cache-1", "redis:7",      "Up 3 days (healthy)",               "Up"),
    ("worker-3","myapp:2.1",    "Up 2 hours (unhealthy)",            "bad"),
    ("db-1",    "postgres:16",  "Exited (137) 5 minutes ago",        "bad"),
]
def docker_ps(bad_name):
    hdr = "CONTAINER ID   IMAGE          STATUS                          NAMES"
    lines = [hdr]
    for name, img, status, kind in docker_rows:
        st = status if (name == bad_name or kind == "Up") else "Up 5 days"
        lines.append(f"{'a1b2c3d4e5f6':<15}{img:<15}{st:<32}{name}")
    return sec("docker_ps", "docker ps --format table", "\n".join(lines))
for i, (name, _, status, kind) in enumerate([r for r in docker_rows if r[3] == "bad"]):
    split = "dev" if i < 1 else "final"
    add(f"dk-{i+1:02d}", split, "컨테이너가 이상합니다", [docker_ps(name)],
        [f"docker_logs {name}", f"docker_inspect_container {name}", f"docker_health {name}", f"docker_logs_since {name}"],
        ["signal:docker_ps"], "synthetic:docker-ps-table")
# 두 개가 동시에 나쁜 번들 하나
add("dk-04", "final", "컨테이너가 이상합니다", [docker_ps("api-2").replace("Up 5 days", "Exited (137) 5 minutes ago", 1)],
    [f"docker_logs api-2", f"docker_inspect_container api-2", f"docker_logs db-1", f"docker_inspect_container db-1"],
    ["signal:docker_ps", "multi-target"], "synthetic:docker-ps-table")

# ── k8s_pods_notready → k8s_pod_describe|k8s_pod_logs <pod> ──
def k8s_pods(bad):
    hdr = "NAMESPACE   NAME                        READY   STATUS             RESTARTS   AGE"
    rows = [
        ("payments-7f9c-x1", "0/1", "CrashLoopBackOff", "14"),
        ("payments-7f9c-x2", "1/1", "Running", "0"),
        ("ingest-5d2a-q9",   "0/1", "ImagePullBackOff", "0"),
        ("cache-0",          "1/1", "Running", "0"),
    ]
    lines = [hdr]
    for name, ready, status, restarts in rows:
        if name != bad and status != "Running":
            ready, status, restarts = "1/1", "Running", "0"
        lines.append(f"{'prod':<12}{name:<28}{ready:<8}{status:<19}{restarts:<11}3d")
    return sec("k8s_pods_notready", "kubectl get pods -A", "\n".join(lines))
for i, bad in enumerate(["payments-7f9c-x1", "ingest-5d2a-q9"]):
    split = "dev" if i < 1 else "final"
    add(f"k8-{i+1:02d}", split, "pod이 계속 재시작합니다", [k8s_pods(bad)],
        [f"k8s_pod_describe {bad}", f"k8s_pod_logs {bad}"], ["signal:k8s_pods"], "synthetic:kubectl-get-pods")

# ── 신호 없음 → 정답은 빈 accepted ──
for i in range(6):
    k = rng.choice([3, 4])
    secs = [c["section"] for c in rng.sample(none_pool, k)]
    rng.shuffle(secs)
    bundles.append({
        "id": f"nn-{i+1:02d}", "split": "dev" if i < 2 else "final",
        "symptom": rng.choice([None, "서버가 좀 이상합니다"]),
        "evidence": "".join(secs), "accepted": [],
        "source": "fixture:none-only", "traits": ["no-signal"],
    })

OUT.write_text(json.dumps({"schema_version": 1, "generated": "2026-09-22", "bundles": bundles}, ensure_ascii=False, indent=2) + "\n")
print(f"{len(bundles)} bundles → {OUT.name}")
