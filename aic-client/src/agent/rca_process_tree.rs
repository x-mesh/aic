//! rca-agent `/collectz`의 `observations.top.process_tree`(schema `process_tree.v1`) 요약.
//!
//! 트리 원문은 노드 1024개·종료 이력 256개까지 와서 수백 KB가 되고, LLM 출력 상한(64 KiB)을
//! 넘으면 통째로 생략 표식으로 바뀐다. 그러면 크래시·kill·자원 상위 프로세스를 볼 수 없으므로,
//! 판정에 쓰는 부분만 남긴 요약으로 바꾼다. 형식 정본: RCA-eBPF
//! `docs/architecture/process-tree-aic-format.md`.
//!
//! 해석 규칙(#74에서 rca-agent 쪽에 약속한 내용):
//! - 노드와 종료 이력의 식별 키는 `(pid, start_boottime_ns)`다. pid만으로는 재사용된 pid가 섞인다.
//! - 자원 필드가 없으면 "측정 안 함", 0이면 "측정값 0"이다. 없는 값을 0으로 채우지 않는다.
//! - `closed_by:"reconcile"` 종료는 시각·원인을 모르므로 개수와 age 범위만 싣는다.
//! - `kill_sender`는 원문 그대로 둔다. `pid`는 시그널을 생성한 실행 문맥이라 "죽인 주체"로
//!   해석한 필드를 만들지 않는다.
//! - 신뢰도 플래그(`loss_in_window`, `tree_basis`, 잘림 카운터 등)는 원문 그대로 통과시킨다.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

/// 요약임을 알리는 키. 값은 원래 `process_tree`의 직렬화 크기(bytes)다.
pub(crate) const SUMMARY_KEY: &str = "aic_summary_of_bytes";
/// 창 안 종료(exit_event) 레코드를 최근 순으로 남기는 수.
const MAX_EXITS: usize = 32;
/// reconcile 종료 레코드를 남기는 수. 나머지는 개수로만 센다.
const MAX_RECONCILE_EXITS: usize = 8;
/// 자원 지표마다 남기는 상위 노드 수.
const TOP_NODES_PER_METRIC: usize = 8;
/// D state(uninterruptible) 노드를 남기는 수.
const MAX_D_STATE_NODES: usize = 16;
/// 조상 사슬에 싣는 최대 단계 수. 이보다 깊으면 뿌리 쪽을 `…`로 줄인다.
const MAX_CHAIN_DEPTH: usize = 8;

/// 원문 그대로 통과시키는 최상위 필드. 모두 작은 스칼라·객체이고 해석의 전제다.
const PASSTHROUGH_FIELDS: &[&str] = &[
    "available",
    "attribution_level",
    "basis",
    "schema",
    "pid_namespace",
    "tree_basis",
    "usage_fields",
    "nodes_total",
    "nodes_truncated",
    "nodes_candidates",
    "nodes_active_total",
    "nodes_active_dropped",
    "exited_dropped_in_window",
    "loss_in_window",
    "loss_keys",
    "clock",
    "render_scope",
    "exited_summary",
    "blackbox_refs",
    FINDINGS_KEY,
];

/// 종료 레코드에서 남기는 필드. `kill_sender`·`total`처럼 객체인 값도 그대로 둔다.
const EXIT_FIELDS: &[&str] = &[
    "pid",
    "start_boottime_ns",
    "ppid",
    "fork_ppid",
    "comm",
    "exe",
    "argv_path",
    "cgroup_id",
    "cgroup_path",
    "ns_pid",
    "closed_by",
    "exit_age_seconds",
    "lifetime_ms",
    "exit_status",
    "signal",
    "core_dumped",
    "cpu_total_ns",
    "kill_sender",
    "total",
];

const RECONCILE_FIELDS: &[&str] = &[
    "pid",
    "start_boottime_ns",
    "comm",
    "exe",
    "cgroup_path",
    "last_seen_alive_age_seconds",
    "first_missing_age_seconds",
];

/// 노드 요약에서 남기는 식별 필드.
const NODE_ID_FIELDS: &[&str] = &[
    "pid",
    "start_boottime_ns",
    "comm",
    "exe",
    "argv_path",
    "cgroup_path",
    "state",
    "proc_state",
];

/// `(요약 키, 노드에서 읽을 경로)`. 경로가 둘이면 합한다(net 송수신).
const METRICS: &[(&str, &[&str])] = &[
    ("cpu_ns", &["window", "cpu_ns"]),
    ("runq_wait_us", &["window", "runq_wait_us"]),
    ("block_io_bytes", &["window", "block_io_bytes"]),
    ("rss_bytes", &["rss_bytes"]),
];
const NET_FIELDS: [&str; 2] = ["net_send_bytes", "net_recv_bytes"];

/// `process_tree` 원문을 요약으로 바꾼 값을 돌려준다. 객체가 아니면 `None`(호출부가 원문을 둔다).
pub(crate) fn summarize(tree: &Value) -> Option<Value> {
    let tree = tree.as_object()?;
    let mut out = Map::new();
    out.insert(
        SUMMARY_KEY.into(),
        json!(Value::Object(tree.clone()).to_string().len()),
    );
    for key in PASSTHROUGH_FIELDS {
        if let Some(v) = tree.get(*key) {
            out.insert((*key).into(), v.clone());
        }
    }

    let nodes: &[Value] = tree
        .get("nodes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let exited: &[Value] = tree
        .get("exited")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    out.insert("exits_in_window".into(), exits_in_window(exited));
    out.insert("reconcile_exits".into(), reconcile_exits(exited));
    let index = NodeIndex::new(nodes);
    out.insert("top_nodes".into(), top_nodes(nodes, &index));
    out.insert("d_state".into(), d_state(nodes, &index));
    out.insert(
        "counts".into(),
        json!({
            "nodes_rendered": nodes.len(),
            "nodes_exited_in_window": nodes.iter().filter(|n| exited_in_window(n)).count(),
            "exited_rendered": exited.len(),
        }),
    );
    Some(Value::Object(out))
}

fn exited_in_window(node: &Value) -> bool {
    node.pointer("/in_window/exited").and_then(Value::as_bool) == Some(true)
}

fn pick(record: &Value, fields: &[&str]) -> Value {
    let picked: Map<String, Value> = fields
        .iter()
        .filter_map(|k| record.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect();
    Value::Object(picked)
}

/// 요약에 싣는 컨테이너 id 길이. docker CLI가 보여 주는 짧은 id와 같은 길이다.
const SHORT_CONTAINER_ID: usize = 12;

/// `cgroup_path`에서 찾은 컨테이너(전체 id). rca-agent는 경로 원문만 주고 해석은 aic가 맡는다(#74).
/// 같은 컨테이너인지는 전체 id로 비교하고, 표시할 때만 [`short_id`]로 줄인다.
fn container(record: &Value) -> Option<(&'static str, String)> {
    let path = record.get("cgroup_path").and_then(Value::as_str)?;
    crate::workload::container_from_cgroup_path(path)
}

fn short_id(id: &str) -> String {
    id.chars().take(SHORT_CONTAINER_ID).collect()
}

/// `pick`한 레코드에 `container: {runtime, id}`를 붙인다. 찾지 못하면 키를 넣지 않는다.
fn with_container(mut picked: Value, record: &Value) -> Value {
    if let (Value::Object(fields), Some((runtime, id))) = (&mut picked, container(record)) {
        fields.insert(
            "container".into(),
            json!({ "runtime": runtime, "id": short_id(&id) }),
        );
    }
    picked
}

fn age(record: &Value, key: &str) -> f64 {
    record.get(key).and_then(Value::as_f64).unwrap_or(f64::MAX)
}

/// 창 안에 커널 종료 이벤트로 닫힌 종료를 최근 순으로 `MAX_EXITS`개 남긴다.
fn exits_in_window(exited: &[Value]) -> Value {
    recent_exits(
        exited
            .iter()
            .filter(|e| e.get("in_window").and_then(Value::as_bool) == Some(true))
            .collect(),
    )
}

/// reconcile을 뺀 종료를 최근 순으로 `MAX_EXITS`개 남긴다. 블랙박스 고정본의 종료 이력도 이 모양으로 싣는다.
pub(crate) fn recent_exits(candidates: Vec<&Value>) -> Value {
    let mut events: Vec<&Value> = candidates
        .into_iter()
        .filter(|e| e.get("closed_by").and_then(Value::as_str) != Some("reconcile"))
        .collect();
    let total = events.len();
    events.sort_by(|a, b| age(a, "exit_age_seconds").total_cmp(&age(b, "exit_age_seconds")));
    let kept: Vec<Value> = events
        .into_iter()
        .take(MAX_EXITS)
        .map(|e| with_container(pick(e, EXIT_FIELDS), e))
        .collect();
    json!({ "total": total, "kept": kept.len(), "records": kept })
}

/// reconcile 종료는 종료 시각·상태가 없다. 개수와, 실제 종료가 들어 있는 age 범위만 싣는다.
/// 레코드는 최근에 없어진 것부터 `MAX_RECONCILE_EXITS`개 남기고, age 범위는 모든 reconcile
/// 종료로 계산한다(남기지 못한 레코드의 범위도 잃지 않게).
fn reconcile_exits(exited: &[Value]) -> Value {
    const MISSING: &str = "first_missing_age_seconds";
    const ALIVE: &str = "last_seen_alive_age_seconds";
    let mut records: Vec<&Value> = exited
        .iter()
        .filter(|e| e.get("closed_by").and_then(Value::as_str) == Some("reconcile"))
        .collect();
    records.sort_by(|a, b| age(a, MISSING).total_cmp(&age(b, MISSING)));
    let kept: Vec<Value> = records
        .iter()
        .take(MAX_RECONCILE_EXITS)
        .map(|e| pick(e, RECONCILE_FIELDS))
        .collect();
    let ages = |key: &str| -> Vec<f64> {
        records
            .iter()
            .filter_map(|e| e.get(key).and_then(Value::as_f64))
            .collect()
    };
    let newest = ages(MISSING).into_iter().reduce(f64::min);
    let oldest = ages(ALIVE).into_iter().reduce(f64::max);
    let mut out = json!({
        "total": records.len(),
        "in_window": records
            .iter()
            .filter(|e| e.get("in_window").and_then(Value::as_bool) == Some(true))
            .count(),
        "kept": kept.len(),
        "records": kept,
        "note": "종료 시각과 원인을 모름. 각 종료는 first_missing_age_seconds 초 전과 \
                 last_seen_alive_age_seconds 초 전 사이에 일어남",
    });
    if let (Some(newest), Some(oldest)) = (newest, oldest) {
        // age 두 값이 모두 있는 reconcile 종료가 들어 있는 경과 시간 범위. 시각이 아니라 창 끝 기준 초다.
        let without = records
            .iter()
            .filter(|e| e.get(MISSING).is_none() || e.get(ALIVE).is_none())
            .count();
        out["age_range_seconds"] =
            json!({ "min": newest, "max": oldest, "records_without_age": without });
    }
    out
}

/// pid → 노드. `ppid`는 pid만 가리키므로, 같은 pid가 둘이면(live와 창 이전 종료) live를 고른다.
struct NodeIndex<'a> {
    by_pid: HashMap<u64, &'a Value>,
}

impl<'a> NodeIndex<'a> {
    fn new(nodes: &'a [Value]) -> Self {
        let mut by_pid: HashMap<u64, &'a Value> = HashMap::new();
        for node in nodes {
            let Some(pid) = node.get("pid").and_then(Value::as_u64) else {
                continue;
            };
            let is_live = node.get("state").and_then(Value::as_str) == Some("live");
            match by_pid.get(&pid) {
                Some(existing)
                    if existing.get("state").and_then(Value::as_str) == Some("live")
                        && !is_live => {}
                _ => {
                    by_pid.insert(pid, node);
                }
            }
        }
        Self { by_pid }
    }

    /// 뿌리 → 노드 순의 `comm(pid)` 사슬. 부모가 트리에 없거나 `ancestors_truncated`면 앞에 `…`를 붙인다.
    fn chain(&self, node: &Value) -> String {
        let mut parts = vec![label(node)];
        let mut current = node;
        let mut cut = false;
        loop {
            if current.get("ancestors_truncated").and_then(Value::as_bool) == Some(true) {
                cut = true;
                break;
            }
            let ppid = current.get("ppid").and_then(Value::as_u64).unwrap_or(0);
            if ppid == 0 {
                break;
            }
            let Some(parent) = self.by_pid.get(&ppid) else {
                cut = true;
                break;
            };
            if parts.len() >= MAX_CHAIN_DEPTH {
                cut = true;
                break;
            }
            parts.push(label(parent));
            current = parent;
        }
        if cut {
            parts.push("…".to_string());
        }
        parts.reverse();
        parts.join(" > ")
    }
}

fn label(node: &Value) -> String {
    let comm = node.get("comm").and_then(Value::as_str).unwrap_or("?");
    match node.get("pid").and_then(Value::as_u64) {
        Some(pid) => format!("{comm}({pid})"),
        None => comm.to_string(),
    }
}

fn node_summary(node: &Value, index: &NodeIndex) -> Value {
    let mut v = with_container(pick(node, NODE_ID_FIELDS), node);
    if let Value::Object(fields) = &mut v {
        fields.insert("chain".into(), json!(index.chain(node)));
    }
    v
}

/// 노드의 지표 값. 필드가 없으면 `None`(측정 안 함). net은 송수신 중 하나라도 있으면 합한다.
fn metric_value(node: &Value, path: &[&str]) -> Option<u64> {
    path.iter()
        .try_fold(node, |v, key| v.get(*key))
        .and_then(Value::as_u64)
}

fn net_value(node: &Value) -> Option<u64> {
    let window = node.get("window")?;
    let values: Vec<u64> = NET_FIELDS
        .iter()
        .filter_map(|k| window.get(*k).and_then(Value::as_u64))
        .collect();
    (!values.is_empty()).then(|| values.iter().sum())
}

/// 지표마다 값이 큰 노드를 `TOP_NODES_PER_METRIC`개. 값이 0인 노드는 상위 목록에서 뺀다.
/// 측정한 노드가 하나도 없으면 그 지표 키를 싣지 않는다(측정 안 함을 빈 목록으로 보이지 않게).
fn top_nodes(nodes: &[Value], index: &NodeIndex) -> Value {
    let mut out = Map::new();
    let mut add = |key: &str, values: Vec<(u64, &Value)>| {
        if values.is_empty() {
            return;
        }
        let measured = values.len();
        let mut ranked: Vec<(u64, &Value)> = values.into_iter().filter(|(v, _)| *v > 0).collect();
        ranked.sort_by_key(|(value, _)| std::cmp::Reverse(*value));
        let top: Vec<Value> = ranked
            .into_iter()
            .take(TOP_NODES_PER_METRIC)
            .map(|(value, node)| {
                let mut v = node_summary(node, index);
                if let Value::Object(fields) = &mut v {
                    fields.insert("value".into(), json!(value));
                }
                v
            })
            .collect();
        out.insert(key.to_string(), json!({ "measured": measured, "top": top }));
    };
    for (key, path) in METRICS {
        add(
            key,
            nodes
                .iter()
                .filter_map(|n| metric_value(n, path).map(|v| (v, n)))
                .collect(),
        );
    }
    add(
        "net_bytes",
        nodes
            .iter()
            .filter_map(|n| net_value(n).map(|v| (v, n)))
            .collect(),
    );
    Value::Object(out)
}

/// 렌더 시점에 D state였던 노드. 행(hang) 진단의 근거다.
fn d_state(nodes: &[Value], index: &NodeIndex) -> Value {
    let matched: Vec<&Value> = nodes
        .iter()
        .filter(|n| n.get("proc_state").and_then(Value::as_str) == Some("D"))
        .collect();
    let kept: Vec<Value> = matched
        .iter()
        .take(MAX_D_STATE_NODES)
        .map(|n| node_summary(n, index))
        .collect();
    json!({ "total": matched.len(), "kept": kept.len(), "nodes": kept })
}

// ── 판정(finding) ─────────────────────────────────────────────

/// 트리 원문에서 만든 판정을 싣는 키. 요약으로 바뀌어도 그대로 남는다.
pub(crate) const FINDINGS_KEY: &str = "aic_findings";
/// 같은 부모·실행 파일이 창 안에서 이 횟수 이상 비정상 종료하면 크래시 루프로 본다.
/// rca-agent 블랙박스의 crash_loop 느린 경로(10분 안 3회)와 같은 횟수다.
const CRASH_LOOP_MIN_EXITS: usize = 3;
/// D state 노드가 이 수 이상이면 warning으로 올린다. 그보다 적으면 참고로만 싣는다.
const D_STATE_WARN_NODES: usize = 5;
/// 종류마다 싣는 판정 수 상한.
const MAX_FINDINGS_PER_KIND: usize = 5;
/// 판정 메시지에 이름을 나열하는 최대 수.
const MAX_NAMES_IN_MESSAGE: usize = 3;

/// 프로세스 자신의 오류로 나는 시그널. 이 시그널로 끝났으면 프로그램 결함이나 메모리 오류다.
const FAULT_SIGNALS: &[(u64, &str)] = &[
    (4, "SIGILL"),
    (6, "SIGABRT"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (11, "SIGSEGV"),
];
const SIGKILL: u64 = 9;

fn signal_name(sig: u64) -> String {
    match sig {
        SIGKILL => "SIGKILL".to_string(),
        15 => "SIGTERM".to_string(),
        _ => FAULT_SIGNALS
            .iter()
            .find(|(n, _)| *n == sig)
            .map(|(_, name)| (*name).to_string())
            .unwrap_or_else(|| format!("signal {sig}")),
    }
}

fn finding(kind: &str, warning: bool, message: String) -> Value {
    json!({
        "kind": kind,
        "severity": if warning { "warning" } else { "info" },
        "message": message,
    })
}

/// 트리 원문에서 판정을 만든다. 순수 함수이며 원문(`nodes`·`exited`)이 있어야 한다.
///
/// 보수적으로 판정한다:
/// - `closed_by:"reconcile"` 종료는 시각·원인을 모르므로 근거로 쓰지 않는다.
/// - SIGKILL만으로 OOM이라고 하지 않는다(OOM은 oom 신호와 맞춰 봐야 한다). `kill_sender`가
///   있으면 `si_code_name`과 송신 문맥을 그대로 적는다.
/// - `loss_in_window`이면 손실을 먼저 알린다. 그 창에서는 "없었다"는 판단을 믿을 수 없다.
pub(crate) fn findings(tree: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    if tree.get("loss_in_window").and_then(Value::as_bool) == Some(true) {
        let keys: Vec<&str> = tree
            .get("loss_keys")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        out.push(finding(
            "loss",
            false,
            format!(
                "프로세스 트리 이벤트 일부 손실({}). 이 창의 종료 이력과 부재 판단은 불완전할 수 있음",
                keys.join(", ")
            ),
        ));
    }
    let exits: Vec<&Value> = tree
        .get("exited")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|e| e.get("in_window").and_then(Value::as_bool) == Some(true))
                .filter(|e| e.get("closed_by").and_then(Value::as_str) == Some("exit_event"))
                .collect()
        })
        .unwrap_or_default();
    out.extend(crash_loops(&exits, summary_groups(tree)));
    out.extend(signal_exits(&exits));
    if let Some(f) = d_state_finding(tree) {
        out.push(f);
    }
    out
}

fn abnormal(exit: &Value) -> bool {
    exit.get("signal").and_then(Value::as_u64).is_some()
        || exit
            .get("exit_status")
            .and_then(Value::as_u64)
            .is_some_and(|s| s != 0)
}

/// 실행 파일 경로, 없으면 comm. 둘 다 없으면 `None`.
fn known_name(exit: &Value) -> Option<&str> {
    exit.get("exe")
        .and_then(Value::as_str)
        .or_else(|| exit.get("comm").and_then(Value::as_str))
}

fn process_name(exit: &Value) -> &str {
    known_name(exit).unwrap_or("?")
}

fn outcome(exit: &Value) -> String {
    match (
        exit.get("signal").and_then(Value::as_u64),
        exit.get("exit_status").and_then(Value::as_u64),
    ) {
        (Some(sig), _) => signal_name(sig),
        (None, Some(status)) => format!("exit {status}"),
        _ => "?".to_string(),
    }
}

/// `exited_summary.groups`(창 안 모든 종료의 `(fork_ppid, exe|comm)` 집계). rca-agent는 창 안
/// 종료가 `exited[]`에 실린 것보다 많을 때만 이 요약을 낸다. 모양:
/// `{fork_ppid, exe?, comm?, count, exit_status: {"코드": 수}, signal: {"번호": 수}, reconcile,
/// codes_other?}`이며, `exit_status`에는 0보다 큰 코드만 있다.
fn summary_groups(tree: &Value) -> &[Value] {
    tree.pointer("/exited_summary/groups")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// 크래시 루프 그룹 키: `(fork_ppid, exe 또는 comm)`.
type GroupKey<'a> = (u64, &'a str);

/// 요약 그룹의 비정상 종료 수와 결과 목록. `codes_other`는 정상 종료가 섞였을 수 있어 세지 않는다.
fn summary_abnormal(group: &Value) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut outcomes = Vec::new();
    let codes = |key: &str| -> Vec<(u64, u64)> {
        group
            .get(key)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(code, n)| Some((code.parse().ok()?, n.as_u64()?)))
                    .collect()
            })
            .unwrap_or_default()
    };
    for (sig, n) in codes("signal") {
        count += n as usize;
        outcomes.push(format!("{} ×{n}", signal_name(sig)));
    }
    for (status, n) in codes("exit_status").into_iter().filter(|(s, _)| *s != 0) {
        count += n as usize;
        outcomes.push(format!("exit {status} ×{n}"));
    }
    (count, outcomes)
}

/// 같은 부모(`fork_ppid`)가 띄운 같은 실행 파일이 창 안에서 `CRASH_LOOP_MIN_EXITS`번 이상
/// 비정상 종료했으면 크래시 루프다. `fork_ppid`나 이름이 없는 종료는 묶지 않는다: 값이 없다는
/// 것은 "같은 부모·같은 프로그램"의 근거가 아니라, 서로 무관한 종료가 한 그룹으로 합쳐질 뿐이다.
///
/// `exited_summary`가 있으면 그 그룹의 횟수와 결과를 쓴다. `exited[]`는 최대 256건이라 그 밖의
/// 종료를 놓치지만 요약은 창 안 종료를 모두 센다. 컨테이너는 같은 키의 종료 기록에서 찾는다.
fn crash_loops<'a>(exits: &[&'a Value], summary: &'a [Value]) -> Vec<Value> {
    let mut records: HashMap<GroupKey<'a>, Vec<&'a Value>> = HashMap::new();
    for exit in exits.iter().copied().filter(|e| abnormal(e)) {
        let (Some(ppid), Some(name)) = (
            exit.get("fork_ppid").and_then(Value::as_u64),
            known_name(exit),
        ) else {
            continue;
        };
        records.entry((ppid, name)).or_default().push(exit);
    }
    // 키 → (비정상 종료 수, 결과 목록). 요약이 있으면 요약 값이 기록 값을 대신한다.
    let mut groups: HashMap<GroupKey<'a>, (usize, Vec<String>)> = records
        .iter()
        .map(|(key, group)| {
            let mut outcomes: Vec<String> = group.iter().map(|e| outcome(e)).collect();
            outcomes.sort();
            outcomes.dedup();
            (*key, (group.len(), outcomes))
        })
        .collect();
    for g in summary {
        let (Some(ppid), Some(name)) = (g.get("fork_ppid").and_then(Value::as_u64), known_name(g))
        else {
            continue;
        };
        let (count, outcomes) = summary_abnormal(g);
        if count > 0 {
            groups.insert((ppid, name), (count, outcomes));
        }
    }
    let mut loops: Vec<(GroupKey<'a>, (usize, Vec<String>))> = groups
        .into_iter()
        .filter(|(_, (count, _))| *count >= CRASH_LOOP_MIN_EXITS)
        .collect();
    loops.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
    loops
        .into_iter()
        .take(MAX_FINDINGS_PER_KIND)
        .map(|(key, (count, outcomes))| {
            let (ppid, name) = key;
            let group = records.get(&key).map(Vec::as_slice).unwrap_or_default();
            // 컨테이너는 그룹의 모든 종료가 같은 컨테이너일 때만 적는다. 재시작된 컨테이너는 id가
            // 바뀌므로, 섞여 있으면 하나를 골라 적지 않는다. 비교는 전체 id로 한다(짧은 id는 겹칠 수 있다).
            // 요약이 기록보다 많이 셌으면 기록에 없는 종료의 컨테이너를 모르므로 적지 않는다.
            let mut containers = group.iter().map(|e| container(e));
            let first = containers.next().flatten();
            let place = match first {
                Some((runtime, id))
                    if group.len() == count
                        && containers.all(|c| c.as_ref() == Some(&(runtime, id.clone()))) =>
                {
                    format!(", {runtime} 컨테이너 {}", short_id(&id))
                }
                _ => String::new(),
            };
            finding(
                "crash_loop",
                true,
                format!(
                    "크래시 루프 의심: {name}(부모 pid {ppid}{place})가 창 안에서 {count}번 비정상 종료({})",
                    outcomes.join(", ")
                ),
            )
        })
        .collect()
}

/// fault 시그널·코어 덤프·SIGKILL로 끝난 개별 종료. fault와 코어 덤프는 warning, SIGKILL은
/// 원인을 단정할 수 없어 info로 싣는다. 상한이 있으므로 warning을 먼저, 그 안에서는 최근 종료를
/// 먼저 고른다(입력 순서대로 자르면 오래된 SIGKILL이 최근 SIGSEGV를 밀어낼 수 있다).
fn signal_exits(exits: &[&Value]) -> Vec<Value> {
    let is_warning = |e: &Value| {
        e.get("core_dumped").and_then(Value::as_bool) == Some(true)
            || e.get("signal")
                .and_then(Value::as_u64)
                .is_some_and(|sig| FAULT_SIGNALS.iter().any(|(n, _)| *n == sig))
    };
    let mut ordered: Vec<&Value> = exits.to_vec();
    ordered.sort_by(|a, b| {
        is_warning(b)
            .cmp(&is_warning(a))
            .then(age(a, "exit_age_seconds").total_cmp(&age(b, "exit_age_seconds")))
    });
    let mut out = Vec::new();
    for exit in ordered {
        let Some(sig) = exit.get("signal").and_then(Value::as_u64) else {
            continue;
        };
        let core = exit.get("core_dumped").and_then(Value::as_bool) == Some(true);
        let fault = FAULT_SIGNALS.iter().any(|(n, _)| *n == sig);
        if !fault && !core && sig != SIGKILL {
            continue;
        }
        let pid = exit.get("pid").and_then(Value::as_u64).unwrap_or(0);
        let mut message = format!(
            "{}({pid})가 {}로 종료{}",
            process_name(exit),
            signal_name(sig),
            if core { ", 코어 덤프" } else { "" }
        );
        if let Some(sender) = exit.get("kill_sender") {
            let code = sender
                .get("si_code_name")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let comm = sender.get("comm").and_then(Value::as_str).unwrap_or("?");
            let same = sender.get("same_process").and_then(Value::as_bool) == Some(true);
            message.push_str(&format!(
                " (시그널 생성 문맥: {}, {code})",
                if same {
                    "자기 자신".to_string()
                } else {
                    comm.to_string()
                }
            ));
        } else if sig == SIGKILL {
            message.push_str(" (송신 정보 없음. OOM 여부는 oom 신호와 맞춰 볼 것)");
        }
        out.push(finding("signal_exit", fault || core, message));
        if out.len() >= MAX_FINDINGS_PER_KIND {
            break;
        }
    }
    out
}

fn d_state_finding(tree: &Value) -> Option<Value> {
    let names: Vec<String> = tree
        .get("nodes")
        .and_then(Value::as_array)?
        .iter()
        .filter(|n| n.get("proc_state").and_then(Value::as_str) == Some("D"))
        .map(label)
        .collect();
    if names.is_empty() {
        return None;
    }
    let shown: Vec<&str> = names
        .iter()
        .take(MAX_NAMES_IN_MESSAGE)
        .map(String::as_str)
        .collect();
    let more = names.len().saturating_sub(shown.len());
    Some(finding(
        "d_state",
        names.len() >= D_STATE_WARN_NODES,
        format!(
            "D state(I/O 대기 등 중단 불가) 프로세스 {}개: {}{}",
            names.len(),
            shown.join(", "),
            if more > 0 {
                format!(" 외 {more}개")
            } else {
                String::new()
            }
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 형식 문서 §6 예시(v0.15.0)에 `proc_state`·`rss_bytes`·`kill_sender`를 더한 트리.
    fn doc_example() -> Value {
        json!({
            "available": true,
            "attribution_level": "cgroup",
            "basis": "process_tree_events",
            "schema": "process_tree.v1",
            "pid_namespace": "host",
            "tree_basis": "synced",
            "usage_fields": {"cpu": "enabled", "runq": "enabled", "block_io": "enabled", "net": "disabled:signal_disabled"},
            "nodes_total": 3,
            "nodes_truncated": false,
            "nodes_candidates": 4,
            "nodes_active_total": 4,
            "nodes_active_dropped": 0,
            "loss_in_window": false,
            "loss_keys": [],
            "exited_dropped_in_window": 0,
            "nodes": [
                {"pid": 1, "ppid": 0, "fork_ppid": 0, "start_boottime_ns": 30000000u64, "comm": "systemd",
                 "exe": "/usr/lib/systemd/systemd", "state": "live", "proc_state": "S", "rss_bytes": 12_000_000u64,
                 "in_window": {"forked": false, "execed": false, "exited": false},
                 "window": {"cpu_ns": 21_400_000u64, "runq_wait_us": 120, "block_io_bytes": 0}},
                {"pid": 1730, "ppid": 1, "fork_ppid": 1, "start_boottime_ns": 52_000_000_000u64, "comm": "containerd-shim",
                 "exe": "/usr/bin/containerd-shim-runc-v2", "state": "live", "proc_state": "D",
                 "in_window": {"forked": false, "execed": false, "exited": false},
                 "window": {"cpu_ns": 3_000_000u64, "runq_wait_us": 40, "block_io_bytes": 0}},
                {"pid": 48190, "ppid": 1730, "fork_ppid": 1730, "start_boottime_ns": 863_986_180_000_000u64, "comm": "java",
                 "exe": "/usr/lib/jvm/java-21/bin/java", "state": "exited",
                 "in_window": {"forked": false, "execed": false, "exited": true},
                 "window": {"cpu_ns": 1_210_000_000u64, "runq_wait_us": 61000, "block_io_bytes": 4096}},
                {"pid": 48211, "ppid": 1730, "fork_ppid": 1730, "start_boottime_ns": 863_987_800_000_000u64, "comm": "java",
                 "exe": "/usr/lib/jvm/java-21/bin/java", "state": "live", "proc_state": "R", "rss_bytes": 900_000_000u64,
                 "in_window": {"forked": true, "execed": true, "exited": false},
                 "window": {"cpu_ns": 9_800_000_000u64, "runq_wait_us": 1_830_000, "block_io_bytes": 73_400_320u64}}
            ],
            "exited": [
                {"seq": 9021, "pid": 48190, "ppid": 1730, "fork_ppid": 1730, "start_boottime_ns": 863_986_180_000_000u64,
                 "comm": "java", "exe": "/usr/lib/jvm/java-21/bin/java", "in_window": true, "closed_by": "exit_event",
                 "exit_age_seconds": 12.4, "lifetime_ms": 1620, "signal": 9, "core_dumped": false, "group_exit": true,
                 "cpu_total_ns": 1_612_345_678u64,
                 "kill_sender": {"pid": 1730, "comm": "containerd-shim", "sig": 9, "si_code_name": "SI_USER", "same_process": false}},
                {"seq": 9022, "pid": 50001, "comm": "cron", "in_window": true, "closed_by": "reconcile",
                 "last_seen_alive_age_seconds": 20.0, "first_missing_age_seconds": 3.5}
            ],
            "clock": {"render_boottime_ns": 864_000_200_000_000u64, "render_unix_ns": 1_792_915_200_123_456_789u64,
                      "realtime_minus_boottime_ns": 1_792_051_199_923_456_789u64, "uncertainty_ns": 812}
        })
    }

    #[test]
    fn trust_flags_and_clock_pass_through_unchanged() {
        let tree = doc_example();
        let s = summarize(&tree).unwrap();
        for key in [
            "loss_in_window",
            "loss_keys",
            "tree_basis",
            "nodes_truncated",
            "nodes_active_dropped",
            "usage_fields",
            "clock",
        ] {
            assert_eq!(s[key], tree[key], "{key}");
        }
        assert!(s[SUMMARY_KEY].as_u64().unwrap() > 0);
        assert!(s.get("nodes").is_none() && s.get("exited").is_none());
    }

    #[test]
    fn exit_event_keeps_status_and_kill_sender_verbatim() {
        let s = summarize(&doc_example()).unwrap();
        let exits = &s["exits_in_window"];
        assert_eq!(exits["total"], 1, "reconcile은 따로 센다");
        let rec = &exits["records"][0];
        assert_eq!(rec["pid"], 48190);
        assert_eq!(rec["start_boottime_ns"], 863_986_180_000_000u64);
        assert_eq!(rec["signal"], 9);
        assert_eq!(rec["kill_sender"]["si_code_name"], "SI_USER");
        assert_eq!(rec["kill_sender"]["same_process"], false);
        assert!(rec.get("killed_by").is_none());
    }

    #[test]
    fn reconcile_exits_carry_only_count_and_age_range() {
        let s = summarize(&doc_example()).unwrap();
        let r = &s["reconcile_exits"];
        assert_eq!(r["total"], 1);
        assert_eq!(r["in_window"], 1);
        let rec = &r["records"][0];
        assert_eq!(rec["last_seen_alive_age_seconds"], 20.0);
        assert_eq!(rec["first_missing_age_seconds"], 3.5);
        assert!(rec.get("signal").is_none() && rec.get("exit_status").is_none());
    }

    #[test]
    fn top_nodes_rank_by_metric_with_ancestor_chain() {
        let s = summarize(&doc_example()).unwrap();
        let cpu = &s["top_nodes"]["cpu_ns"];
        assert_eq!(cpu["measured"], 4);
        assert_eq!(cpu["top"][0]["pid"], 48211);
        assert_eq!(cpu["top"][0]["value"], 9_800_000_000u64);
        assert_eq!(
            cpu["top"][0]["chain"],
            "systemd(1) > containerd-shim(1730) > java(48211)"
        );
        // block_io가 0인 노드는 상위 목록에서 빠지지만 측정 수에는 들어간다.
        let bio = &s["top_nodes"]["block_io_bytes"];
        assert_eq!(bio["measured"], 4);
        assert_eq!(bio["top"].as_array().unwrap().len(), 2);
    }

    /// net이 꺼져 있어 노드에 필드가 없으면 "측정 안 함"이다. 빈 목록으로 싣지 않는다.
    #[test]
    fn unmeasured_metric_is_absent_not_zero() {
        let s = summarize(&doc_example()).unwrap();
        assert!(s["top_nodes"].get("net_bytes").is_none());
        assert_eq!(s["top_nodes"]["rss_bytes"]["measured"], 2);
    }

    #[test]
    fn d_state_nodes_are_listed() {
        let s = summarize(&doc_example()).unwrap();
        assert_eq!(s["d_state"]["total"], 1);
        assert_eq!(s["d_state"]["nodes"][0]["pid"], 1730);
    }

    #[test]
    fn missing_parent_marks_chain_as_cut() {
        let tree = json!({"nodes": [
            {"pid": 10, "ppid": 9, "comm": "orphan", "window": {"cpu_ns": 5}},
            {"pid": 20, "ppid": 0, "comm": "cut", "ancestors_truncated": true, "window": {"cpu_ns": 4}}
        ]});
        let s = summarize(&tree).unwrap();
        let top = &s["top_nodes"]["cpu_ns"]["top"];
        assert_eq!(top[0]["chain"], "… > orphan(10)");
        assert_eq!(top[1]["chain"], "… > cut(20)");
    }

    /// v0.11 형태: `clock`·`rss_bytes`·`proc_state`·`kill_sender`·`window`가 없다.
    #[test]
    fn old_agent_shape_summarizes_without_optional_fields() {
        let tree = json!({
            "available": true,
            "nodes": [{"pid": 1, "ppid": 0, "comm": "systemd", "state": "live"}],
            "exited": [{"pid": 7, "comm": "sh", "in_window": true, "closed_by": "exit_event", "exit_status": 7}]
        });
        let s = summarize(&tree).unwrap();
        assert!(s.get("clock").is_none());
        assert_eq!(s["top_nodes"], json!({}));
        assert_eq!(s["d_state"]["total"], 0);
        assert_eq!(s["exits_in_window"]["records"][0]["exit_status"], 7);
    }

    fn exit(pid: u64, ppid: u64, extra: Value) -> Value {
        let mut e = json!({"pid": pid, "fork_ppid": ppid, "comm": "java",
                           "exe": "/usr/bin/java", "in_window": true, "closed_by": "exit_event"});
        if let (Value::Object(base), Value::Object(more)) = (&mut e, extra) {
            base.extend(more);
        }
        e
    }

    fn kinds(fs: &[Value]) -> Vec<(&str, &str)> {
        fs.iter()
            .map(|f| (f["kind"].as_str().unwrap(), f["severity"].as_str().unwrap()))
            .collect()
    }

    /// 문서 예시: SIGKILL 1건(kill_sender SI_USER)과 D state 1개. 둘 다 원인을 단정하지 않는 info다.
    #[test]
    fn doc_example_yields_info_findings_only() {
        let fs = findings(&doc_example());
        assert_eq!(
            kinds(&fs),
            vec![("signal_exit", "info"), ("d_state", "info")]
        );
        let msg = fs[0]["message"].as_str().unwrap();
        assert!(msg.contains("SIGKILL") && msg.contains("SI_USER"), "{msg}");
        assert!(msg.contains("containerd-shim"), "{msg}");
    }

    #[test]
    fn repeated_abnormal_exits_from_same_parent_are_a_crash_loop() {
        let tree = json!({"exited": [
            exit(1, 100, json!({"exit_status": 1})),
            exit(2, 100, json!({"exit_status": 1})),
            exit(3, 100, json!({"signal": 15})),
            // 정상 종료, 다른 부모, reconcile, 창 밖 종료는 세지 않는다.
            exit(4, 100, json!({"exit_status": 0})),
            exit(5, 200, json!({"exit_status": 1})),
            exit(6, 100, json!({"closed_by": "reconcile"})),
            exit(7, 100, json!({"exit_status": 1, "in_window": false})),
        ]});
        let fs = findings(&tree);
        assert_eq!(kinds(&fs), vec![("crash_loop", "warning")]);
        let msg = fs[0]["message"].as_str().unwrap();
        assert!(msg.contains("3번"), "{msg}");
        assert!(msg.contains("exit 1") && msg.contains("SIGTERM"), "{msg}");
    }

    /// PR #77 L2·L6: 부모나 이름이 없는 종료는 같은 그룹의 근거가 아니다.
    #[test]
    fn exits_without_parent_or_name_are_not_grouped() {
        let no_parent = |pid| {
            json!({"pid": pid, "exe": "/usr/bin/java", "in_window": true,
                                     "closed_by": "exit_event", "exit_status": 1})
        };
        let no_name = |pid| {
            json!({"pid": pid, "fork_ppid": 100, "in_window": true,
                                   "closed_by": "exit_event", "exit_status": 1})
        };
        let tree = json!({"exited": [
            no_parent(1), no_parent(2), no_parent(3),
            no_name(4), no_name(5), no_name(6),
        ]});
        assert!(findings(&tree).is_empty());
    }

    /// PR #77 L3: 오래된 SIGKILL이 앞에 많아도 최근 fault 종료가 상한 안에 남는다.
    #[test]
    fn fault_exits_outrank_older_sigkills_under_the_cap() {
        let mut exited: Vec<Value> = (0..MAX_FINDINGS_PER_KIND as u64 + 2)
            .map(|i| {
                exit(
                    i,
                    1000 + i,
                    json!({"signal": 9, "exit_age_seconds": 100.0 + i as f64}),
                )
            })
            .collect();
        exited.push(exit(
            99,
            2000,
            json!({"signal": 11, "exit_age_seconds": 1.0}),
        ));
        let fs = findings(&json!({ "exited": exited }));
        assert_eq!(fs.len(), MAX_FINDINGS_PER_KIND);
        assert_eq!(fs[0]["severity"], "warning");
        assert!(fs[0]["message"].as_str().unwrap().contains("SIGSEGV"));
        // 나머지 SIGKILL은 최근 순이다.
        assert!(fs[1]["message"].as_str().unwrap().contains("(0)"));
    }

    /// PR #77 L4: 레코드를 다 싣지 못해도 age 범위는 모든 reconcile 종료로 계산한다.
    #[test]
    fn reconcile_age_range_covers_all_records() {
        let exited: Vec<Value> = (0..MAX_RECONCILE_EXITS as u64 + 4)
            .map(|i| {
                json!({"pid": i, "closed_by": "reconcile", "in_window": true,
                       "first_missing_age_seconds": 2.0 + i as f64,
                       "last_seen_alive_age_seconds": 10.0 + i as f64})
            })
            .chain(std::iter::once(
                json!({"pid": 999, "closed_by": "reconcile"}),
            ))
            .collect();
        let s = summarize(&json!({ "exited": exited })).unwrap();
        let r = &s["reconcile_exits"];
        assert_eq!(r["kept"], MAX_RECONCILE_EXITS);
        assert_eq!(r["records"][0]["first_missing_age_seconds"], 2.0);
        let range = &r["age_range_seconds"];
        assert_eq!(range["min"], 2.0);
        assert_eq!(range["max"], 10.0 + (MAX_RECONCILE_EXITS + 3) as f64);
        assert_eq!(range["records_without_age"], 1);
    }

    const HEX64: &str = "3f9c0a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab";

    #[test]
    fn container_is_parsed_from_cgroup_path() {
        let cases = [
            (format!("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-{HEX64}.scope"), Some("containerd")),
            (format!("/system.slice/docker-{HEX64}.scope"), Some("docker")),
            (format!("/machine.slice/libpod-{HEX64}.scope"), Some("podman")),
            ("/system.slice/nginx.service".to_string(), None),
            ("/init.scope".to_string(), None),
        ];
        for (path, runtime) in cases {
            let got = container(&json!({ "cgroup_path": path }));
            assert_eq!(got.as_ref().map(|(r, _)| *r), runtime, "{path}");
            if let Some((_, id)) = got {
                assert_eq!(id, HEX64, "비교용으로는 전체 id를 돌려준다");
            }
        }
        assert!(
            container(&json!({})).is_none(),
            "cgroup_path가 없으면 찾지 않는다"
        );
    }

    #[test]
    fn exits_and_top_nodes_carry_container() {
        let path = format!("/system.slice/docker-{HEX64}.scope");
        let tree = json!({
            "nodes": [{"pid": 5, "ppid": 0, "comm": "app", "cgroup_path": path, "window": {"cpu_ns": 10}},
                      {"pid": 6, "ppid": 0, "comm": "host", "cgroup_path": "/system.slice/sshd.service", "window": {"cpu_ns": 5}}],
            "exited": [exit(7, 1, json!({"cgroup_path": path, "exit_status": 1}))]
        });
        let s = summarize(&tree).unwrap();
        let expect = json!({"runtime": "docker", "id": &HEX64[..SHORT_CONTAINER_ID]});
        assert_eq!(s["exits_in_window"]["records"][0]["container"], expect);
        let top = &s["top_nodes"]["cpu_ns"]["top"];
        assert_eq!(top[0]["container"], expect);
        assert!(
            top[1].get("container").is_none(),
            "컨테이너가 아니면 키를 넣지 않는다"
        );
    }

    #[test]
    fn crash_loop_names_the_container_only_when_shared() {
        let path = format!("/system.slice/docker-{HEX64}.scope");
        let same = json!({"exited": [
            exit(1, 100, json!({"exit_status": 1, "cgroup_path": path})),
            exit(2, 100, json!({"exit_status": 1, "cgroup_path": path})),
            exit(3, 100, json!({"exit_status": 1, "cgroup_path": path})),
        ]});
        let msg = findings(&same)[0]["message"].as_str().unwrap().to_string();
        assert!(
            msg.contains(&format!("docker 컨테이너 {}", &HEX64[..SHORT_CONTAINER_ID])),
            "{msg}"
        );

        let other = format!("/system.slice/docker-{}.scope", "a".repeat(64));
        let mixed = json!({"exited": [
            exit(1, 100, json!({"exit_status": 1, "cgroup_path": path})),
            exit(2, 100, json!({"exit_status": 1, "cgroup_path": other})),
            exit(3, 100, json!({"exit_status": 1})),
        ]});
        let msg = findings(&mixed)[0]["message"].as_str().unwrap().to_string();
        assert!(!msg.contains("컨테이너"), "{msg}");

        // PR #78 L1: 짧은 id(12자)가 같아도 전체 id가 다르면 다른 컨테이너다.
        let same_prefix = format!(
            "/system.slice/docker-{}{}.scope",
            &HEX64[..SHORT_CONTAINER_ID],
            "b".repeat(64 - SHORT_CONTAINER_ID)
        );
        let prefix_clash = json!({"exited": [
            exit(1, 100, json!({"exit_status": 1, "cgroup_path": path})),
            exit(2, 100, json!({"exit_status": 1, "cgroup_path": path})),
            exit(3, 100, json!({"exit_status": 1, "cgroup_path": same_prefix})),
        ]});
        let msg = findings(&prefix_clash)[0]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!msg.contains("컨테이너"), "{msg}");
    }

    /// `exited[]`에는 2건뿐이어도 `exited_summary`가 창 안 전체를 세면 크래시 루프다.
    #[test]
    fn exited_summary_counts_exits_beyond_the_rendered_history() {
        let path = format!("/system.slice/docker-{HEX64}.scope");
        let tree = json!({
            "exited": [
                exit(1, 100, json!({"exit_status": 1, "cgroup_path": path})),
                exit(2, 100, json!({"exit_status": 1, "cgroup_path": path})),
            ],
            "exited_summary": {"basis": "all_exits_in_window", "exits_in_window": 40, "groups": [
                {"fork_ppid": 100, "exe": "/usr/bin/java", "comm": "java", "count": 40,
                 "exit_status": {"1": 30}, "signal": {"9": 5}, "reconcile": 5}
            ]}
        });
        let fs = findings(&tree);
        let msg = fs[0]["message"].as_str().unwrap();
        assert_eq!(fs[0]["kind"], "crash_loop");
        assert!(msg.contains("35번"), "reconcile은 세지 않는다: {msg}");
        assert!(
            msg.contains("exit 1 ×30") && msg.contains("SIGKILL ×5"),
            "{msg}"
        );
        // PR #79 L4: 기록 2건으로 35건 전체의 컨테이너를 단정하지 않는다.
        assert!(
            !msg.contains("컨테이너"),
            "기록에 없는 종료의 컨테이너는 모른다: {msg}"
        );
    }

    /// 요약 수와 기록 수가 같으면(모든 종료가 기록에 있으면) 기록의 컨테이너를 적는다.
    #[test]
    fn exited_summary_keeps_container_when_records_cover_all_exits() {
        let path = format!("/system.slice/docker-{HEX64}.scope");
        let tree = json!({
            "exited": [
                exit(1, 100, json!({"exit_status": 1, "cgroup_path": path})),
                exit(2, 100, json!({"exit_status": 1, "cgroup_path": path})),
                exit(3, 100, json!({"exit_status": 1, "cgroup_path": path})),
            ],
            "exited_summary": {"groups": [
                {"fork_ppid": 100, "exe": "/usr/bin/java", "count": 3,
                 "exit_status": {"1": 3}, "signal": {}, "reconcile": 0}
            ]}
        });
        let msg = findings(&tree)[0]["message"].as_str().unwrap().to_string();
        assert!(msg.contains("docker 컨테이너"), "{msg}");
    }

    /// 요약 그룹에도 부모·이름 규칙을 그대로 적용하고, 정상 종료(`codes_other` 포함)는 세지 않는다.
    #[test]
    fn exited_summary_group_rules_match_records() {
        let tree = json!({"exited_summary": {"groups": [
            {"fork_ppid": 100, "count": 9, "exit_status": {"1": 9}, "signal": {}},
            {"fork_ppid": 200, "exe": "/bin/ok", "count": 9, "exit_status": {}, "signal": {}, "codes_other": 9},
            {"fork_ppid": 300, "exe": "/bin/two", "count": 2, "exit_status": {"2": 2}, "signal": {}}
        ]}});
        assert!(findings(&tree).is_empty());
    }

    #[test]
    fn two_abnormal_exits_are_not_a_crash_loop() {
        let tree = json!({"exited": [
            exit(1, 100, json!({"exit_status": 1})),
            exit(2, 100, json!({"exit_status": 1})),
        ]});
        assert!(findings(&tree).is_empty());
    }

    #[test]
    fn fault_signal_and_core_dump_are_warnings() {
        let tree = json!({"exited": [
            exit(1, 100, json!({"signal": 11,
                "kill_sender": {"si_code_name": "SEGV_MAPERR", "same_process": true, "comm": "java"}})),
            exit(2, 200, json!({"signal": 3, "core_dumped": true})),
            // SIGTERM 단독 종료는 개별 판정을 내지 않는다.
            exit(3, 300, json!({"signal": 15})),
        ]});
        let fs = findings(&tree);
        assert_eq!(
            kinds(&fs),
            vec![("signal_exit", "warning"), ("signal_exit", "warning")]
        );
        let msg = fs[0]["message"].as_str().unwrap();
        assert!(
            msg.contains("SIGSEGV") && msg.contains("자기 자신"),
            "{msg}"
        );
        assert!(fs[1]["message"].as_str().unwrap().contains("코어 덤프"));
    }

    #[test]
    fn sigkill_without_sender_does_not_claim_oom() {
        let tree = json!({"exited": [exit(1, 100, json!({"signal": 9}))]});
        let fs = findings(&tree);
        assert_eq!(kinds(&fs), vec![("signal_exit", "info")]);
        assert!(fs[0]["message"]
            .as_str()
            .unwrap()
            .contains("oom 신호와 맞춰"));
    }

    #[test]
    fn loss_is_reported_first() {
        let tree =
            json!({"loss_in_window": true, "loss_keys": ["ringbuf_drops_exit"], "exited": []});
        let fs = findings(&tree);
        assert_eq!(kinds(&fs), vec![("loss", "info")]);
        assert!(fs[0]["message"]
            .as_str()
            .unwrap()
            .contains("ringbuf_drops_exit"));
    }

    #[test]
    fn many_d_state_nodes_are_a_warning() {
        let nodes: Vec<Value> = (1..=D_STATE_WARN_NODES as u64)
            .map(|pid| json!({"pid": pid, "comm": "kworker", "proc_state": "D"}))
            .collect();
        let fs = findings(&json!({"nodes": nodes}));
        assert_eq!(kinds(&fs), vec![("d_state", "warning")]);
        assert!(fs[0]["message"].as_str().unwrap().contains("외 2개"));
    }

    #[test]
    fn findings_survive_summary() {
        let mut tree = doc_example();
        let fs = findings(&tree);
        tree[FINDINGS_KEY] = Value::Array(fs.clone());
        assert_eq!(summarize(&tree).unwrap()[FINDINGS_KEY], Value::Array(fs));
    }

    #[test]
    fn non_object_is_not_summarized() {
        assert!(summarize(&json!([1, 2])).is_none());
    }
}
