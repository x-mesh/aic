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

fn age(record: &Value, key: &str) -> f64 {
    record.get(key).and_then(Value::as_f64).unwrap_or(f64::MAX)
}

/// 창 안에 커널 종료 이벤트로 닫힌 종료를 최근 순으로 `MAX_EXITS`개 남긴다.
fn exits_in_window(exited: &[Value]) -> Value {
    let mut events: Vec<&Value> = exited
        .iter()
        .filter(|e| e.get("in_window").and_then(Value::as_bool) == Some(true))
        .filter(|e| e.get("closed_by").and_then(Value::as_str) != Some("reconcile"))
        .collect();
    let total = events.len();
    events.sort_by(|a, b| age(a, "exit_age_seconds").total_cmp(&age(b, "exit_age_seconds")));
    let kept: Vec<Value> = events
        .into_iter()
        .take(MAX_EXITS)
        .map(|e| pick(e, EXIT_FIELDS))
        .collect();
    json!({ "total": total, "kept": kept.len(), "records": kept })
}

/// reconcile 종료는 종료 시각·상태가 없다. 개수와, 실제 종료가 들어 있는 age 범위만 싣는다.
fn reconcile_exits(exited: &[Value]) -> Value {
    let records: Vec<&Value> = exited
        .iter()
        .filter(|e| e.get("closed_by").and_then(Value::as_str) == Some("reconcile"))
        .collect();
    let kept: Vec<Value> = records
        .iter()
        .take(MAX_RECONCILE_EXITS)
        .map(|e| pick(e, RECONCILE_FIELDS))
        .collect();
    json!({
        "total": records.len(),
        "in_window": records
            .iter()
            .filter(|e| e.get("in_window").and_then(Value::as_bool) == Some(true))
            .count(),
        "kept": kept.len(),
        "records": kept,
        "note": "종료 시각과 원인을 모름. 실제 종료는 first_missing_age_seconds 전과 \
                 last_seen_alive_age_seconds 전 사이",
    })
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
    let mut v = pick(node, NODE_ID_FIELDS);
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

    #[test]
    fn non_object_is_not_summarized() {
        assert!(summarize(&json!([1, 2])).is_none());
    }
}
