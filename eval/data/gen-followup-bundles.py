#!/usr/bin/env python3
"""follow-up 번들 생성기(2라운드).

정답은 구성상 정해진다: 신호 섹션이 문제 대상을 드러내고, 그 대상을 더 깊이 보는 템플릿이 정답이다.
정답 집합은 eval의 결정적 후보 추출(`followup::candidates`)과 같아야 하며 `followup-validate`가 그
동일성을 검사한다 — 여기의 규칙 복제본(스캐너 임계, STATUS 필터)이 Rust 쪽과 어긋나면 검증이 실패한다.

섹션 형식은 probes.rs의 명령이 실제로 내는 출력 형태를 따른다: `docker ps -s`(NAMES 뒤에 SIZE 열,
`-a`가 없어 종료된 컨테이너는 없음), `kubectl get pods -A | grep -v Running`(남는 정상 행은 Completed뿐),
`kubectl get nodes`, `systemctl --failed --no-legend`, `aic proc-fd-top`. 실제 호스트 출력은 섞지 않는다.

1라운드 결함을 고쳤다: 잡음에서 신호 probe를 제외하지 못하던 인자, evidence와 어긋난 dk-04 정답,
스캐너 출력(50% 이상 표 순서 최대 3개)과 다른 pf-08 정답.
"""
import json, random, re, pathlib

SRC = pathlib.Path(__file__).with_name("probe-judgments.json")
OUT = pathlib.Path(__file__).with_name("followup-bundles.json")
cases = json.loads(SRC.read_text())["cases"]
rng = random.Random(20260922)

# ── 규칙 복제본 (Rust: diagnose.rs scan_proc_fd, followup.rs *_is_problem) ──
PROC_FD_PCT_WARN, PROC_FD_ABS_WARN, PROC_FD_FINDING_CAP = 50, 10_000, 3
ARG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount")

def arg_ok(tok): return ARG_RE.fullmatch(tok) is not None
def docker_problem(st):
    s = st.strip(); return (not s.startswith("Up")) or "(unhealthy)" in s or "(Paused)" in s
def pod_problem(st): return st not in ("Running", "Completed", "Succeeded")
def pod_has_logs(st): return st in ("CrashLoopBackOff", "Error", "OOMKilled")
def node_problem(st): return st.startswith("NotReady") or st == "Unknown"

def proc_fd_flagged(stdout):
    limit, out = None, []
    for line in stdout.splitlines():
        if line.startswith("per-proc limit:"):
            try: limit = int(line.split(":", 1)[1].strip()) or None
            except ValueError: limit = None
            continue
        t = line.split()
        if len(t) < 2 or not t[0].isdigit() or not t[1].isdigit(): continue
        fd, pid = int(t[0]), t[1]
        pct = fd * 100 // limit if limit else None
        if (pct is not None and pct >= PROC_FD_PCT_WARN) or fd >= PROC_FD_ABS_WARN:
            out.append(pid)
        if len(out) >= PROC_FD_FINDING_CAP: break
    return out

# ── 섹션 도우미 ──
def sec(probe, cmd, stdout):
    return f"## {probe}\ncommand: {cmd}\nexit_code=0 duration_ms=1 truncated=false cwd=.\n--- stdout ---\n{stdout}\n\n--- stderr ---\n"

def stdout_of(section):
    body = section.split("--- stdout ---", 1)[1] if "--- stdout ---" in section else section
    return body.split("--- stderr ---", 1)[0].strip()

def probe_of(section): return section.split("\n", 1)[0][3:].strip()

def table(header, rows):
    """docker/kubectl처럼 열 너비를 최대 길이 + 3으로 맞춘 표. 마지막 열은 채우지 않는다."""
    cols = list(zip(header, *rows)) if rows else [(h,) for h in header]
    widths = [max(len(c) for c in col) + 3 for col in cols]
    def fmt(r): return "".join(c.ljust(w) for c, w in zip(r[:-1], widths[:-1])) + r[-1]
    return "\n".join([fmt(list(header))] + [fmt(list(r)) for r in rows])

def dedup(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen: seen.add(x); out.append(x)
    return out

# ── failed_units ──
def failed_units_section(units):
    rows = "\n".join(f"● {u:<30} loaded failed failed {d}" for u, d in units)
    return sec("failed_units", "systemctl --failed --no-pager --no-legend | head -n 40", rows)

def key_failed_units(section):
    units = []
    for line in stdout_of(section).splitlines():
        for tok in line.split():
            if tok.endswith(UNIT_SUFFIXES):
                if arg_ok(tok): units.append(tok)
                break
    return [f"journal_unit {u}" for u in dedup(units)]

# ── proc_fd_top ──
def proc_fd_section(limit, rows):
    lines = ([f"per-proc limit: {limit}"] if limit else []) + ["     FD     PID COMMAND"]
    lines += [f"{fd:>7} {pid:>7} {cmd}" for fd, pid, cmd in rows]
    return sec("proc_fd_top", "aic proc-fd-top", "\n".join(lines))

def key_proc_fd(section):
    stdout = stdout_of(section)
    flagged = proc_fd_flagged(stdout)
    out = []
    for line in stdout.splitlines():
        t = line.split()
        if len(t) < 3 or not t[0].isdigit() or not t[1].isdigit(): continue
        pid, cmd = t[1], t[2]
        if pid not in flagged: continue
        out.append(f"proc_fd {pid}")
        if any(ch.isalpha() for ch in cmd) and arg_ok(cmd): out.append(f"proc_net {cmd}")
    return dedup(out)

# ── docker ps -s ──
DOCKER_HDR = ("CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES", "SIZE")
DOCKER_SETS = {
    "A": [("web-1", "nginx:1.25", '"/docker-entrypoint.…"', "7 days ago", "0.0.0.0:80->80/tcp", "1.09kB (virtual 187MB)"),
          ("api-2", "myapp:2.1", '"python -m app"', "2 hours ago", "", "0B (virtual 412MB)"),
          ("cache-1", "redis:7", '"docker-entrypoint.s…"', "3 days ago", "6379/tcp", "0B (virtual 117MB)"),
          ("worker-3", "myapp:2.1", '"python -m worker"', "2 hours ago", "", "12.3kB (virtual 412MB)"),
          ("db-1", "postgres:16", '"docker-entrypoint.s…"', "5 days ago", "5432/tcp", "63B (virtual 431MB)")],
    "B": [("nginx-proxy", "nginx:1.27-alpine", '"/docker-entrypoint.…"', "3 weeks ago", "0.0.0.0:443->443/tcp", "2.1kB (virtual 43.2MB)"),
          ("auth-svc", "registry.local/auth:4.2.0", '"/app/auth serve"', "9 hours ago", "8080/tcp", "0B (virtual 96.4MB)"),
          ("queue", "rabbitmq:3.13-management", '"docker-entrypoint.s…"', "3 weeks ago", "5672/tcp, 15672/tcp", "1.02MB (virtual 260MB)"),
          ("cron-runner", "registry.local/cron:1.9", '"/usr/bin/supercronic…"', "9 hours ago", "", "4.1kB (virtual 71MB)"),
          ("pg-primary", "postgres:15", '"docker-entrypoint.s…"', "3 weeks ago", "5432/tcp", "0B (virtual 417MB)")],
    "C": [("frontend", "ghcr.io/acme/frontend:2024.9", '"nginx -g \'daemon of…"', "26 hours ago", "0.0.0.0:3000->80/tcp", "0B (virtual 52.1MB)"),
          ("backend", "ghcr.io/acme/backend:2024.9", '"gunicorn app:app"', "26 hours ago", "8000/tcp", "18.7kB (virtual 210MB)"),
          ("redis-1", "redis:7-alpine", '"docker-entrypoint.s…"', "6 days ago", "6379/tcp", "0B (virtual 41.4MB)"),
          ("sidekiq", "ghcr.io/acme/backend:2024.9", '"bundle exec sidekiq"', "26 hours ago", "", "0B (virtual 210MB)"),
          ("mongo", "mongo:7", '"docker-entrypoint.s…"', "6 days ago", "27017/tcp", "0B (virtual 754MB)")],
}
HEALTHY = ["Up 7 days", "Up 3 days (healthy)", "Up 5 days", "Up 12 hours", "Up 2 weeks (healthy)"]
DOCKER_TEMPLATES = ["docker_logs", "docker_logs_since", "docker_inspect_container", "docker_health"]

def docker_section(set_key, status_by_name):
    rows = []
    for i, (name, img, cmd, created, ports, size) in enumerate(DOCKER_SETS[set_key]):
        st = status_by_name.get(name, HEALTHY[i % len(HEALTHY)])
        rows.append(("%012x" % rng.getrandbits(48), img, cmd, created, st, ports, name, size))
    return sec("docker_ps", "docker ps -s | head -n 30", table(DOCKER_HDR, rows)), rows

def key_docker(rows):
    return [f"{t} {r[6]}" for r in rows if docker_problem(r[4]) for t in DOCKER_TEMPLATES]

# ── kubectl get pods -A | grep -v Running ──
POD_HDR = ("NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE")
COMPLETED = [("prod", "backup-28812345-x9k2l", "0/1", "Completed", "0", "3h"),
             ("kube-system", "apiserver-check-q7s2m", "0/1", "Completed", "0", "5m")]

def pods_section(rows, all_ns=True):
    hdr = POD_HDR if all_ns else POD_HDR[1:]
    rs = [r if all_ns else r[1:] for r in rows]
    cmd = ("kubectl get pods -A" if all_ns else "kubectl get pods") + " | grep -v Running | head -n 40"
    return sec("k8s_pods_notready", cmd, table(hdr, rs))

def key_pods(rows):
    out = []
    for ns, name, ready, status, restarts, age in rows:
        if not pod_problem(status): continue
        out.append(f"k8s_pod_describe {name}")
        if pod_has_logs(status): out.append(f"k8s_pod_logs {name}")
    return out

# ── kubectl get nodes ──
NODE_HDR = ("NAME", "STATUS", "ROLES", "AGE", "VERSION")
def nodes_section(rows): return sec("k8s_nodes", "kubectl get nodes | head -n 40", table(NODE_HDR, rows))
def key_nodes(rows): return [f"k8s_node_describe {r[0]}" for r in rows if node_problem(r[1])]

# ── 잡음 풀: 판정 none인 clean-negative fixture + 정상 docker/k8s 표 ──
# boundary-negative(임계 바로 아래)는 섞지 않는다 — "신호 없음" 번들에 49.98% 같은 값이 들어가면 그것을
# 고른 것을 오답으로 세게 된다(판정 실험에서 확인한 fixture 설계 문제).
NONE_FIXTURES = [c for c in cases if c["expected"] == "none"
                 and "clean-negative" in c["traits"] and "excluded-mount" not in c["traits"]]
READY_NODES = [("node-a", "Ready", "control-plane", "300d", "v1.28.9"),
               ("node-b", "Ready,SchedulingDisabled", "<none>", "300d", "v1.28.9"),
               ("node-c", "Ready", "<none>", "300d", "v1.28.9")]
def healthy_docker():
    override = {} if rng.random() < 0.7 else {"cache-1": "Up 10 seconds (health: starting)"}
    return docker_section(rng.choice("ABC"), override)[0]
def healthy_pods(): return pods_section(rng.choice([[], COMPLETED[:1], COMPLETED]), True)
def healthy_nodes(): return nodes_section(READY_NODES)
NOISE_POOL = [(c["probe_id"], (lambda s=c["section"]: s)) for c in NONE_FIXTURES] + [
    ("docker_ps", healthy_docker), ("k8s_pods_notready", healthy_pods), ("k8s_nodes", healthy_nodes)]

def noise(k, exclude, force=()):
    """probe가 겹치지 않게 k개. `force`의 probe는 반드시 넣는다(함정 번들용)."""
    picked, used = [], set()
    for p in force:
        fs = [f for q, f in NOISE_POOL if q == p]
        picked.append(rng.choice(fs)()); used.add(p)
    pool = [(p, f) for p, f in NOISE_POOL if p not in exclude and p not in used]
    rng.shuffle(pool)
    for p, f in pool:
        if p in used: continue
        picked.append(f()); used.add(p)
        if len(picked) == k: break
    return picked

bundles = []
DEV_EVERY = 3  # 계열마다 세 번들 중 하나가 개발 분할

def add(prefix, idx, symptom, signal_sections, accepted, traits, source):
    split = "dev" if idx % DEV_EVERY == 0 else "final"
    exclude = {probe_of(s) for s in signal_sections}
    secs = list(signal_sections) + noise(rng.choice([2, 3]), exclude)
    rng.shuffle(secs)
    bundles.append({"id": f"{prefix}-{idx + 1:02d}", "split": split, "symptom": symptom,
                    "evidence": "".join(secs), "accepted": accepted, "source": source, "traits": traits})

# ── failed_units → journal_unit <unit> (fixture 8 + synthetic 4) ──
FU_SYN = [
    [("kubelet.service", "kubelet: The Kubernetes Node Agent")],
    [("var-lib-data.mount", "/var/lib/data")],
    [("logrotate.timer", "Daily rotation of log files"), ("etcd.service", "etcd key-value store")],
    [("sshd.socket", "OpenSSH Server Socket"), ("containerd.service", "containerd container runtime"),
     ("docker.service", "Docker Application Container Engine")],
]
fu_sections = [(c["section"], f"fixture:{c['id']}") for c in cases
               if c["probe_id"] == "failed_units" and c["expected"] != "none"]
fu_sections += [(failed_units_section(u), "synthetic:systemctl-failed") for u in FU_SYN]
i = 0
for section, source in fu_sections:
    key = key_failed_units(section)
    if not key: continue
    add("fu", i, ["서비스가 죽었습니다", "앱이 안 뜹니다"][i % 2], [section], key,
        ["signal:failed_units", "multi-target" if len(key) > 1 else "single-target"], source)
    i += 1

# ── proc_fd_top → proc_fd <pid> | proc_net <cmd> (fixture 8 + synthetic 5) ──
PF_SYN = [
    (None, [(12000, 3101, "java"), (300, 3102, "sshd")], ["abs-rule", "no-limit-line"]),
    (1048576, [(15000, 4210, "envoy"), (800, 4211, "node")], ["abs-rule"]),
    (4096, [(2100, 5001, "gunicorn"), (2048, 5002, "celery"), (100, 5003, "cron")], ["multi-target", "boundary-50pct"]),
    (8192, [(7000, 6001, "ingest-a"), (6500, 6002, "ingest-b"), (6000, 6003, "ingest-c"),
            (5500, 6004, "ingest-d"), (4200, 6005, "ingest-e")], ["multi-target", "cap-3"]),
    (1024, [(600, 7001, "redis-server")], []),
]
pf_sections = [(c["section"], f"fixture:{c['id']}", []) for c in cases
               if c["probe_id"] == "proc_fd_top" and c["expected"] != "none"]
pf_sections += [(proc_fd_section(lim, rows), "synthetic:proc-fd-top", tr) for lim, rows, tr in PF_SYN]
i = 0
for section, source, extra in pf_sections:
    key = key_proc_fd(section)
    if not key: continue
    add("pf", i, ["파일 디스크립터 누수가 의심됩니다", "Too many open files 오류가 납니다"][i % 2], [section], key,
        ["signal:proc_fd_top"] + extra, source)
    i += 1

# ── docker_ps → docker_* <name> ──
DK = [
    ("A", {"api-2": "Restarting (1) 12 seconds ago"}, []),
    ("B", {"auth-svc": "Up 2 hours (unhealthy)"}, []),
    ("C", {"sidekiq": "Restarting (137) 8 seconds ago"}, []),
    ("A", {"worker-3": "Up 2 hours (unhealthy)", "cache-1": "Up 10 seconds (health: starting)"}, ["distractor:health-starting"]),
    ("B", {"queue": "Up 3 days (Paused)"}, ["status:paused"]),
    ("C", {"mongo": "Restarting (1) 3 seconds ago", "redis-1": "Up 4 seconds (health: starting)"}, ["distractor:health-starting"]),
    ("A", {"api-2": "Restarting (1) 12 seconds ago", "db-1": "Up 5 days (unhealthy)"}, ["multi-target"]),
    ("B", {"nginx-proxy": "Restarting (3) 40 seconds ago", "cron-runner": "Up 9 hours (unhealthy)"}, ["multi-target"]),
    ("C", {"frontend": "Up 1 hour (unhealthy)", "backend": "Restarting (1) 5 seconds ago", "redis-1": "Up 20 minutes (Paused)"}, ["multi-target"]),
    ("B", {"pg-primary": "Up 11 minutes (unhealthy)"}, []),
]
for i, (set_key, bad, extra) in enumerate(DK):
    section, rows = docker_section(set_key, bad)
    add("dk", i, ["컨테이너가 이상합니다", "서비스 응답이 없습니다"][i % 2], [section], key_docker(rows),
        ["signal:docker_ps"] + extra, "synthetic:docker-ps-s")

# ── k8s_pods_notready → k8s_pod_describe|k8s_pod_logs <pod> ──
K8 = [
    ([("prod", "payments-7f9c-x1", "0/1", "CrashLoopBackOff", "14 (2m ago)", "3d")], True, []),
    ([("prod", "ingest-5d2a-q9", "0/1", "ImagePullBackOff", "0", "25m")] + COMPLETED[:1], True, ["distractor:completed", "no-logs"]),
    ([("staging", "api-6c8d-abcde", "0/1", "Error", "3 (10m ago)", "1h")], False, ["no-namespace-column"]),
    ([("prod", "worker-0", "0/1", "OOMKilled", "7 (1m ago)", "2d")], True, []),
    ([("prod", "cache-1", "0/1", "Pending", "0", "12m")], True, ["no-logs"]),
    ([("prod", "search-84f6-zz1", "0/1", "Evicted", "0", "4h")] + COMPLETED, True, ["distractor:completed", "no-logs"]),
    ([("staging", "migrate-job-7t2rq", "0/1", "Init:CrashLoopBackOff", "5 (30s ago)", "9m")], False, ["no-namespace-column", "no-logs"]),
    ([("prod", "auth-5b7d-k2m", "0/1", "CreateContainerConfigError", "0", "2m")], True, ["no-logs"]),
    ([("prod", "payments-7f9c-x1", "0/1", "CrashLoopBackOff", "14 (2m ago)", "3d"),
      ("prod", "ingest-5d2a-q9", "0/1", "ErrImagePull", "0", "3m")], True, ["multi-target"]),
    ([("prod", "gateway-0", "0/1", "ContainerStatusUnknown", "2", "6h"),
      ("prod", "gateway-1", "0/1", "Unknown", "0", "6h")] + COMPLETED[:1], True, ["multi-target", "distractor:completed"]),
]
for i, (rows, all_ns, extra) in enumerate(K8):
    add("k8", i, ["pod이 계속 재시작합니다", "배포가 안 뜹니다"][i % 2], [pods_section(rows, all_ns)], key_pods(rows),
        ["signal:k8s_pods"] + extra, "synthetic:kubectl-get-pods")

# ── k8s_nodes → k8s_node_describe <node> ──
KN = [
    ([("ip-10-0-1-23.ec2.internal", "Ready", "control-plane", "120d", "v1.29.4"),
      ("ip-10-0-2-45.ec2.internal", "NotReady", "<none>", "120d", "v1.29.4"),
      ("ip-10-0-3-67.ec2.internal", "Ready", "<none>", "98d", "v1.29.4")], []),
    ([("node-a", "Ready", "control-plane", "300d", "v1.28.9"),
      ("node-b", "Ready,SchedulingDisabled", "<none>", "300d", "v1.28.9"),
      ("node-c", "NotReady", "<none>", "300d", "v1.28.9")], ["distractor:cordoned"]),
    ([("gke-prod-pool-1-7f2a", "NotReady", "<none>", "40d", "v1.30.2"),
      ("gke-prod-pool-1-9c1b", "NotReady", "<none>", "40d", "v1.30.2"),
      ("gke-prod-pool-1-e4d0", "Ready", "<none>", "40d", "v1.30.2")], ["multi-target"]),
    ([("k8s-master-1", "Ready", "control-plane", "2y", "v1.27.3"),
      ("k8s-worker-1", "Unknown", "<none>", "2y", "v1.27.3"),
      ("k8s-worker-2", "Ready", "<none>", "2y", "v1.27.3")], ["status:unknown"]),
    ([(f"worker-{n:02d}", "Ready", "<none>", "77d", "v1.29.4") for n in range(1, 7)]
     + [("worker-07", "NotReady,SchedulingDisabled", "<none>", "77d", "v1.29.4")], ["many-rows"]),
]
for i, (rows, extra) in enumerate(KN):
    add("kn", i, ["노드가 이상합니다", "pod이 스케줄되지 않습니다"][i % 2], [nodes_section(rows)], key_nodes(rows),
        ["signal:k8s_nodes"] + extra, "synthetic:kubectl-get-nodes")

# ── 신호 없음 → 정답은 빈 accepted. 함정: 정상 docker/k8s 표, 정상 proc_fd_top 행 ──
NN = [((), "fixture-only")] * 4 + [(("docker_ps",), "trap:docker_ps")] * 3 \
   + [(("k8s_pods_notready",), "trap:k8s_pods")] * 3 + [(("k8s_nodes",), "trap:k8s_nodes")] * 2 \
   + [(("proc_fd_top",), "trap:proc_fd_top")] * 2
NN_SYMPTOMS = [None, "서버가 좀 이상합니다", "배포 후 느려진 것 같습니다", None, "컨테이너가 이상합니다"]
for i, (force, trap) in enumerate(NN):
    secs = noise(rng.choice([3, 4]), set(), force)
    rng.shuffle(secs)
    bundles.append({"id": f"nn-{i + 1:02d}", "split": "dev" if i % DEV_EVERY == 0 else "final",
                    "symptom": NN_SYMPTOMS[i % len(NN_SYMPTOMS)], "evidence": "".join(secs), "accepted": [],
                    "source": "fixture:none-only+synthetic:healthy-tables", "traits": ["no-signal", trap]})

OUT.write_text(json.dumps({"schema_version": 1, "generated": "2026-09-22", "bundles": bundles},
                          ensure_ascii=False, indent=2) + "\n")
dev = sum(b["split"] == "dev" for b in bundles)
print(f"{len(bundles)} bundles (dev {dev} / final {len(bundles) - dev}) → {OUT.name}")
