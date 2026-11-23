//! rca-agent 블랙박스 고정본(`process_tree_blackbox.v1`, `GET /blackboxz/<id>`) 요약.
//!
//! 고정본은 장애 앞뒤 구간(기본 트리거 전 60초, 뒤 30초)의 1초 프레임, 종료 이력, 트리거 시점과
//! 끝 시점의 process_tree 스냅샷을 담고 기본 4 MiB까지 커진다. LLM 출력 상한(64 KiB)에 맞추려고
//! 판정에 쓰는 부분만 남긴다. 구조 정본: RCA-eBPF `internal/process_tree/blackbox.go`
//! (`BlackboxCapture`), 형식 문서 §8.
//!
//! - 트리거·범위·손실·시계는 원문 그대로 둔다. `loss`가 0이 아니면 그 구간의 프레임·종료가
//!   빠졌다는 뜻이다.
//! - 프레임은 시계열 대신 지표별 최댓값과 그 시각, 카운터 합, 종료 그룹 합으로 줄인다.
//! - 스냅샷은 process_tree 요약([`super::rca_process_tree::summarize`])을 쓴다.

use serde_json::{json, Map, Value};

use super::rca_process_tree;

/// 요약임을 알리는 키. 값은 고정본 원문의 직렬화 크기(bytes)다.
pub(crate) const SUMMARY_KEY: &str = rca_process_tree::SUMMARY_KEY;
/// 출력 상한 때문에 생략한 하위 값을 대신하는 표식 키(값은 원래 크기).
const OMITTED_KEY: &str = "aic_omitted_bytes";
/// 트리거를 남기는 수. 진행 중 캡처에 병합된 트리거가 많을 수 있다.
const MAX_TRIGGERS: usize = 16;
/// `exited_summary` 그룹을 남기는 수. rca-agent도 32개까지만 낸다.
const MAX_SUMMARY_GROUPS: usize = 32;
/// 프레임 종료 그룹 합에서 남기는 상위 그룹 수.
const TOP_EXIT_GROUPS: usize = 10;

/// 원문 그대로 통과시키는 최상위 필드.
const PASSTHROUGH_FIELDS: &[&str] = &[
    "schema",
    "id",
    "state",
    "boot_id",
    "clock",
    "range",
    "loss",
    "redaction",
    "render_window",
    "exited_overflow",
];

/// 최댓값과 시각을 남기는 프레임 `system` 지표(`BlackboxSystemSample`).
const SYSTEM_FIELDS: &[&str] = &[
    "procs_running",
    "procs_blocked",
    "load1",
    "cpu_some",
    "io_some",
    "memory_some",
    "memory_full",
];

/// 상한을 넘으면 이 순서로 생략한다. 판정의 근거(트리거·손실·프레임 최댓값)는 맨 마지막까지 남긴다.
const SHRINK_ORDER: &[&str] = &[
    "/snapshots/at_trigger/top_nodes",
    "/snapshots/at_trigger/exits_in_window",
    "/snapshots/at_end/top_nodes",
    "/snapshots/at_end/exits_in_window",
    "/frames/counters",
    "/exited_summary",
    "/exits",
];

/// 고정본을 요약한다. 객체가 아니면 `None`.
pub(crate) fn summarize(capture: &Value, max_bytes: usize) -> Option<Value> {
    let fields = capture.as_object()?;
    let mut out = Map::new();
    out.insert(SUMMARY_KEY.into(), json!(capture.to_string().len()));
    for key in PASSTHROUGH_FIELDS {
        if let Some(v) = fields.get(*key) {
            out.insert((*key).into(), v.clone());
        }
    }

    let triggers = array(capture, "triggers");
    out.insert("triggers_total".into(), json!(triggers.len()));
    out.insert(
        "triggers".into(),
        Value::Array(triggers.iter().take(MAX_TRIGGERS).cloned().collect()),
    );
    out.insert("frames".into(), frames(array(capture, "frames")));
    out.insert(
        "exits".into(),
        rca_process_tree::recent_exits(array(capture, "exited").iter().collect()),
    );
    let groups = array(capture, "exited_summary");
    if !groups.is_empty() {
        out.insert(
            "exited_summary".into(),
            json!({
                "total": groups.len(),
                "groups": groups.iter().take(MAX_SUMMARY_GROUPS).cloned().collect::<Vec<_>>(),
            }),
        );
    }
    let mut snapshots = Map::new();
    for key in ["at_trigger", "at_end"] {
        if let Some(s) = capture
            .pointer(&format!("/snapshots/{key}"))
            .and_then(rca_process_tree::summarize)
        {
            snapshots.insert(key.into(), s);
        }
    }
    out.insert("snapshots".into(), Value::Object(snapshots));

    let mut summary = Value::Object(out);
    shrink(&mut summary, max_bytes);
    Some(summary)
}

fn array<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// 1초 프레임을 지표별 최댓값(과 그 시각), 카운터 합, 종료 그룹 합으로 줄인다.
/// 프레임에 없는 지표는 싣지 않는다(측정 안 함을 0으로 보이지 않게).
fn frames(frames: &[Value]) -> Value {
    let mut out = Map::new();
    out.insert("count".into(), json!(frames.len()));
    if let (Some(first), Some(last)) = (frames.first(), frames.last()) {
        out.insert(
            "first_at".into(),
            first.get("at").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "last_at".into(),
            last.get("at").cloned().unwrap_or(Value::Null),
        );
    }

    let live: Vec<u64> = frames
        .iter()
        .filter_map(|f| f.get("live_nodes").and_then(Value::as_u64))
        .collect();
    if let (Some(min), Some(max)) = (live.iter().min(), live.iter().max()) {
        out.insert("live_nodes".into(), json!({ "min": min, "max": max }));
    }

    let mut peaks = Map::new();
    for key in SYSTEM_FIELDS {
        let peak = frames
            .iter()
            .filter_map(|f| {
                let v = f.pointer(&format!("/system/{key}"))?.as_f64()?;
                Some((v, f.get("at")))
            })
            .max_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((max, at)) = peak {
            peaks.insert((*key).into(), json!({ "max": max, "at": at }));
        }
    }
    out.insert("system_peaks".into(), Value::Object(peaks));

    out.insert("counters".into(), sum_maps(frames, "counters", usize::MAX));
    out.insert(
        "exit_groups".into(),
        sum_maps(frames, "exit_groups", TOP_EXIT_GROUPS),
    );
    Value::Object(out)
}

/// 프레임마다 있는 `{키: 수}` 객체를 키별로 더해, 0이 아닌 키를 큰 순으로 `limit`개 남긴다.
fn sum_maps(frames: &[Value], key: &str, limit: usize) -> Value {
    // fork storm에서는 종료 그룹 키가 많으므로 키마다 선형 탐색하지 않는다.
    let mut sums: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for frame in frames {
        let Some(map) = frame.get(key).and_then(Value::as_object) else {
            continue;
        };
        for (k, v) in map {
            *sums.entry(k.as_str()).or_default() += v.as_u64().unwrap_or(0);
        }
    }
    let groups = sums.len();
    let mut ranked: Vec<(&str, u64)> = sums.into_iter().filter(|(_, n)| *n > 0).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let totals: Map<String, Value> = ranked
        .into_iter()
        .take(limit)
        .map(|(k, n)| (k.to_string(), json!(n)))
        .collect();
    json!({ "distinct": groups, "top": totals })
}

/// 직렬화 길이가 `max_bytes` 이하가 되게 줄인다. 결과는 항상 유효한 JSON이다(호출부가 문자열을
/// 자르지 않아도 된다).
///
/// 1. [`SHRINK_ORDER`] 순서로 하위 값을 생략 표식으로 바꾼다.
/// 2. 그래도 넘으면 트리거를 뒤에서부터 줄인다(`cause` 등이 비정상적으로 클 때).
/// 3. 그래도 넘으면 id·state·원래 크기만 남긴 최소 객체로 바꾸고, 그 객체도 넘으면 note·id·state
///    순으로 뺀다. 마지막에는 `{"aic_omitted_bytes": N}`만 남는다. 이보다 작은 상한은 표현할 수
///    없으므로 이 객체를 그대로 돌려준다(상한은 64 KiB라 실제로는 생기지 않는다).
fn shrink(summary: &mut Value, max_bytes: usize) {
    let fits = |v: &Value| v.to_string().len() <= max_bytes;
    for pointer in SHRINK_ORDER {
        if fits(summary) {
            return;
        }
        if let Some(target) = summary.pointer_mut(pointer) {
            let size = target.to_string().len();
            *target = json!({ OMITTED_KEY: size });
        }
    }
    while !fits(summary) {
        let Some(triggers) = summary.get_mut("triggers").and_then(Value::as_array_mut) else {
            break;
        };
        if triggers.pop().is_none() {
            break;
        }
    }
    if fits(summary) {
        return;
    }
    let size = summary.to_string().len();
    *summary = json!({
        "id": summary.get("id").cloned().unwrap_or(Value::Null),
        "state": summary.get("state").cloned().unwrap_or(Value::Null),
        SUMMARY_KEY: summary.get(SUMMARY_KEY).cloned().unwrap_or(Value::Null),
        OMITTED_KEY: size,
        "note": "요약도 출력 상한을 넘어 생략했다. rca-agent의 GET /blackboxz/<id>를 직접 확인할 것",
    });
    // id·state는 서버가 준 값이라 크기를 믿을 수 없다. 덜 중요한 것부터 뺀다.
    for key in ["note", SUMMARY_KEY, "state", "id"] {
        if fits(summary) {
            return;
        }
        if let Some(fields) = summary.as_object_mut() {
            fields.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 64 * 1024;

    fn frame(sec: u64, procs_blocked: u64, groups: Value) -> Value {
        json!({
            "at": format!("2026-11-23T05:{:02}:{:02}Z", sec / 60, sec % 60),
            "counters": {"forks": 2, "exits": 1, "ringbuf_drops_exit": 0},
            "live_nodes": 300 + sec,
            "system": {"procs_running": 2, "procs_blocked": procs_blocked, "load1": 1.5, "io_some": sec as f64 / 10.0},
            "exit_groups": groups
        })
    }

    fn capture() -> Value {
        let frames: Vec<Value> = (0..90u64)
            .map(|s| {
                let groups = if s % 3 == 0 {
                    json!({"1730|/usr/bin/java": 1})
                } else {
                    json!({})
                };
                frame(s, if s == 61 { 9 } else { 0 }, groups)
            })
            .collect();
        let node = |pid: u64| {
            json!({"pid": pid, "ppid": 1, "comm": "java", "exe": "/usr/bin/java", "state": "live",
                   "window": {"cpu_ns": pid * 1000}})
        };
        let snapshot = json!({
            "available": true, "schema": "process_tree.v1", "loss_in_window": false,
            "nodes": (1..=50).map(node).collect::<Vec<_>>(), "exited": []
        });
        json!({
            "schema": "process_tree_blackbox.v1",
            "id": "0123456789abcdef",
            "boot_id": "b0",
            "state": "ready",
            "clock": {"render_unix_ns": 1u64, "realtime_minus_boottime_ns": 1u64, "uncertainty_ns": 10},
            "range": {"start": "2026-11-23T05:00:00Z", "end": "2026-11-23T05:01:30Z",
                      "pre": 60_000_000_000u64, "post": 30_000_000_000u64, "merged": false},
            "triggers": [{"id": "crash_loop", "at": "2026-11-23T05:01:00Z",
                          "cause": {"exe": "/usr/bin/java", "comm": "java", "signal": 9, "path": "fast", "count": 5}}],
            "frames": frames,
            "exited": [{"pid": 9, "comm": "java", "closed_by": "exit_event", "exit_age_seconds": 3.0, "signal": 9}],
            "exited_overflow": 0,
            "exited_summary": [{"fork_ppid": 1730, "exe": "/usr/bin/java", "count": 30,
                                "exit_status": {}, "signal": {"9": 30}, "reconcile": 0}],
            "snapshots": {"at_trigger": snapshot.clone(), "at_end": snapshot},
            "oom_events": [],
            "loss": {"frames_missed": 2, "exited_overwritten_in_range": 0, "triggers_dropped": 0},
            "redaction": {"argv_path": "omitted"},
            "render_window": "instant"
        })
    }

    #[test]
    fn capture_keeps_triggers_loss_and_range_verbatim() {
        let c = capture();
        let s = summarize(&c, LIMIT).unwrap();
        for key in ["id", "state", "range", "loss", "clock", "redaction"] {
            assert_eq!(s[key], c[key], "{key}");
        }
        assert_eq!(s["triggers"], c["triggers"]);
        assert_eq!(s["triggers_total"], 1);
        assert!(s[SUMMARY_KEY].as_u64().unwrap() > 0);
        assert!(s.get("frames").and_then(|f| f.get("count")).is_some());
        assert!(s.to_string().len() <= LIMIT);
    }

    #[test]
    fn frames_collapse_to_peaks_and_sums() {
        let s = summarize(&capture(), LIMIT).unwrap();
        let f = &s["frames"];
        assert_eq!(f["count"], 90);
        assert_eq!(f["live_nodes"], json!({"min": 300, "max": 389}));
        assert_eq!(f["system_peaks"]["procs_blocked"]["max"], 9.0);
        assert_eq!(
            f["system_peaks"]["procs_blocked"]["at"],
            "2026-11-23T05:01:01Z"
        );
        // 프레임에 없는 지표는 싣지 않는다.
        assert!(f["system_peaks"].get("memory_full").is_none());
        assert_eq!(f["counters"]["top"]["forks"], 180);
        assert!(
            f["counters"]["top"].get("ringbuf_drops_exit").is_none(),
            "0인 카운터는 뺀다"
        );
        assert_eq!(f["exit_groups"]["top"]["1730|/usr/bin/java"], 30);
    }

    #[test]
    fn exits_snapshots_and_exit_summary_are_summarized() {
        let s = summarize(&capture(), LIMIT).unwrap();
        assert_eq!(s["exits"]["records"][0]["signal"], 9);
        assert_eq!(s["exited_summary"]["groups"][0]["signal"]["9"], 30);
        let end = &s["snapshots"]["at_end"];
        assert!(end[SUMMARY_KEY].as_u64().unwrap() > 0);
        assert!(end.get("nodes").is_none());
        assert_eq!(end["top_nodes"]["cpu_ns"]["top"][0]["pid"], 50);
    }

    /// 상한이 작으면 스냅샷 상세부터 생략하고, 트리거·손실은 남긴다.
    #[test]
    fn shrink_drops_snapshot_detail_first() {
        let c = capture();
        let full = summarize(&c, usize::MAX).unwrap().to_string().len();
        let s = summarize(&c, full - 1).unwrap();
        assert!(
            s["snapshots"]["at_trigger"]["top_nodes"][OMITTED_KEY]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(s["triggers"], c["triggers"]);
        assert_eq!(s["loss"], c["loss"]);
    }

    /// PR #79 L1·L3: 생략 순서를 다 써도 넘치면(트리거 cause가 비정상적으로 큰 경우) 트리거를
    /// 줄이고, 그래도 넘치면 최소 객체로 바꾼다. 어느 단계에서도 결과는 상한 안의 유효한 JSON이다.
    #[test]
    fn oversized_triggers_still_yield_valid_json_within_limit() {
        let mut c = capture();
        let big = "x".repeat(4096);
        c["triggers"] = Value::Array(
            (0..40)
                .map(|i| json!({"id": "crash_loop", "at": format!("t{i}"), "cause": {"comm": big}}))
                .collect(),
        );
        for limit in [LIMIT, 8 * 1024, 512] {
            let s = summarize(&c, limit).unwrap();
            let text = s.to_string();
            assert!(text.len() <= limit, "limit={limit} len={}", text.len());
            serde_json::from_str::<Value>(&text).expect("유효한 JSON");
            assert_eq!(s["id"], c["id"], "id는 끝까지 남는다");
        }
        let s = summarize(&c, 512).unwrap();
        assert!(s[OMITTED_KEY].as_u64().unwrap() > 0, "최소 객체로 바뀐다");
        let s = summarize(&c, 8 * 1024).unwrap();
        assert!(
            !s["triggers"].as_array().unwrap().is_empty(),
            "트리거는 줄이되 남긴다"
        );
    }

    /// PR #79 L5: 서버가 준 id·state가 크면 최소 객체도 상한을 넘는다. 그 필드를 빼서라도 맞춘다.
    #[test]
    fn minimal_object_drops_oversized_server_fields() {
        let mut c = capture();
        c["id"] = json!("i".repeat(4096));
        c["state"] = json!("s".repeat(4096));
        let limit = 256;
        let s = summarize(&c, limit).unwrap();
        let text = s.to_string();
        assert!(text.len() <= limit, "len={}", text.len());
        serde_json::from_str::<Value>(&text).expect("유효한 JSON");
        assert!(s[OMITTED_KEY].as_u64().unwrap() > 0);
        assert!(s.get("id").is_none() && s.get("state").is_none());
    }

    #[test]
    fn non_object_is_not_summarized() {
        assert!(summarize(&json!("x"), LIMIT).is_none());
    }
}
