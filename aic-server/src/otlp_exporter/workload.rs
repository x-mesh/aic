//! 등록한 workload(PostgreSQL, Redis, nginx 등)의 수집 결과를 `aic.workload.*` metric으로 push한다.
//!
//! **어디서 오는가**: `workload_monitor`가 60초마다 정의별로 수집해 로컬 기록에 남긴 sample을
//! 채널로 받는다. 이 task는 수집하지 않고 변환과 전송만 한다.
//!
//! **무엇을 보내는가**: 지표 이름은 `aic.workload.<adapter>.<field>`이고, 대상 구분은 data point
//! 속성 `workload.id`·`workload.name`·`workload.adapter`로 싣는다. rca-web은 data point 속성만
//! 보존하고 리소스 속성은 host 식별 외에는 버리기 때문이다. 연결 주소(endpoint)와 계정은 보내지
//! 않는다. 수집 성공 여부는 `aic.workload.up`(1/0)과 `status` 속성으로 보낸다.
//!
//! **누적 카운터**: rca-web에는 rate 함수가 없으므로 누적 필드는 두 sample 사이 증가분을 보낸다
//! (`kernel` exporter와 같은 규칙). workload의 첫 sample은 기준선만 잡는다. 값이 줄면 서비스가
//! 재시작된 것으로 보고 그 필드는 이번에 보내지 않고 기준선만 새로 잡는다.

use std::collections::HashMap;
use std::sync::Arc;

use aic_common::workload::{
    workload_adapter_name, workload_metric_fields, workload_short_name, WorkloadSample,
    WorkloadSampleFailure, WorkloadSampleOutcome,
};
use tokio::sync::{mpsc, watch};

use crate::live_config::{self, LiveExporterConfig};

use super::backoff::Backoff;
use super::encode::{self, AttributedPoint};
use super::host_metrics::{MetricValue, ResourceAttrs};
use super::spool::{SignalKind, Spool};

const UP_METRIC: &str = "aic.workload.up";
const METRIC_PREFIX: &str = "aic.workload";

/// workload exporter 설정. 다른 exporter task와 spool·health를 공유한다.
pub struct WorkloadExportConfig {
    /// OTLP collector base URL. `/v1/metrics`가 append된다.
    pub endpoint: String,
    pub token: Option<String>,
    pub service_version: String,
    pub spool: Arc<Spool>,
    pub health: Arc<super::ExporterHealth>,
    /// 실행 중 다시 읽는 `[aicd.exporter]` 스냅샷. 토큰을 여기서 꺼낸다.
    pub live: Option<Arc<LiveExporterConfig>>,
}

/// 누적 필드의 직전 값. 키는 (workload id, field).
#[derive(Default)]
struct CounterBaseline(HashMap<(String, String), u64>);

fn unit_for(field: &str) -> &'static str {
    if field.contains("bytes") || field == "used_memory" || field == "bytes" {
        "By"
    } else {
        "1"
    }
}

fn status_label(outcome: &WorkloadSampleOutcome) -> &'static str {
    match outcome {
        WorkloadSampleOutcome::Collected { .. } => "collected",
        WorkloadSampleOutcome::Failed { reason, .. } => match reason {
            WorkloadSampleFailure::Unreachable => "unreachable",
            WorkloadSampleFailure::Rejected => "rejected",
            WorkloadSampleFailure::Malformed => "malformed",
        },
    }
}

fn as_int(value: u64) -> MetricValue {
    MetricValue::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// sample 하나를 보낼 점들로 바꾼다. 누적 필드는 `baseline`과 비교해 증가분만 남긴다.
fn sample_points(sample: &WorkloadSample, baseline: &mut CounterBaseline) -> Vec<AttributedPoint> {
    let adapter = workload_adapter_name(sample.adapter);
    let identity = vec![
        ("workload.id", sample.workload_id.clone()),
        (
            "workload.name",
            workload_short_name(&sample.workload_id).to_string(),
        ),
        ("workload.adapter", adapter.clone()),
    ];
    let collected = matches!(sample.outcome, WorkloadSampleOutcome::Collected { .. });
    let mut up_attributes = identity.clone();
    up_attributes.push(("status", status_label(&sample.outcome).to_string()));
    let mut points = vec![AttributedPoint {
        name: UP_METRIC.to_string(),
        unit: "1",
        value: MetricValue::Int(i64::from(collected)),
        attributes: up_attributes,
    }];
    let WorkloadSampleOutcome::Collected { metrics, .. } = &sample.outcome else {
        return points;
    };
    for field in workload_metric_fields(sample.adapter, metrics) {
        let value = if field.counter {
            let key = (sample.workload_id.clone(), field.field.clone());
            let previous = baseline.0.insert(key, field.value);
            match previous {
                Some(previous) if field.value >= previous => field.value - previous,
                // 첫 sample(기준선) 또는 값 감소(서비스 재시작) — 이번에는 보내지 않는다.
                _ => continue,
            }
        } else {
            field.value
        };
        points.push(AttributedPoint {
            name: format!("{METRIC_PREFIX}.{adapter}.{}", field.field),
            unit: unit_for(&field.field),
            value: as_int(value),
            attributes: identity.clone(),
        });
    }
    points
}

/// sample을 받는 동안 변환해 push한다. 전송 실패는 spool에 적재한다(재전송은 host metrics task가
/// 맡는다).
pub async fn serve_workload(
    cfg: WorkloadExportConfig,
    mut samples: mpsc::Receiver<WorkloadSample>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()?;
    let url = super::metrics_url(&cfg.endpoint);
    tracing::info!(url = %url, "OTLP workload exporter 시작");

    // host_metrics와 같은 방식으로 얻어야 같은 host.id로 다른 signal과 상관관계를 지을 수 있다.
    let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    let resource = ResourceAttrs {
        host_id: super::host_metrics::host_id(&host_name),
        host_name,
        os_type: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        os_desc: sysinfo::System::long_os_version().unwrap_or_default(),
    };
    let mut baseline = CounterBaseline::default();
    let mut backoff = Backoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        let sample = tokio::select! {
            sample = samples.recv() => match sample {
                Some(sample) => sample,
                None => break,
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };
        let points = sample_points(&sample, &mut baseline);
        let body = encode::encode_attributed_metrics(
            &resource,
            &cfg.service_version,
            super::unix_nanos_now(),
            &points,
        );
        if !backoff.ready() {
            if let Err(e) = cfg.spool.append(SignalKind::Metrics, &body) {
                tracing::warn!(error = %e, "OTLP workload spool append 실패 — 이 샘플 유실");
            }
            continue;
        }
        let token = live_config::effective_token(cfg.live.as_ref(), &cfg.token);
        match super::push(&client, &url, token.as_deref(), body.clone()).await {
            Ok(()) => {
                backoff.on_success();
                cfg.health.record_ok();
            }
            Err(e) => {
                tracing::warn!(error = %e, "OTLP workload push 실패 — spool에 적재");
                if let Err(e2) = cfg.spool.append(SignalKind::Metrics, &body) {
                    tracing::warn!(error = %e2, "OTLP workload spool append 실패 — 이 샘플 유실");
                }
                backoff.on_failure();
                cfg.health.record_fail(&url, &e);
            }
        }
    }
    tracing::info!("OTLP workload exporter 종료");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::workload::{
        PostgreSqlMetrics, WorkloadAdapter, WorkloadMetrics, WORKLOAD_SAMPLE_SCHEMA_VERSION,
    };

    const ID: &str = "container:docker:dnx-postgres-1:exe:/usr/local/bin/postgres";

    fn postgres(numbackends: u64, xact_commit: u64) -> WorkloadSample {
        WorkloadSample {
            schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
            workload_id: ID.into(),
            captured_at: chrono::Utc::now(),
            adapter: WorkloadAdapter::PostgreSql,
            outcome: WorkloadSampleOutcome::Collected {
                endpoint: "tcp://127.0.0.1:5432".into(),
                metrics: WorkloadMetrics::PostgreSql(PostgreSqlMetrics {
                    numbackends,
                    xact_commit,
                    xact_rollback: 0,
                    blks_read: 0,
                    blks_hit: 0,
                    tup_returned: 0,
                    tup_fetched: 0,
                    tup_inserted: 0,
                    tup_updated: 0,
                    tup_deleted: 0,
                    conflicts: 0,
                    temp_files: 0,
                    temp_bytes: 0,
                    deadlocks: 0,
                }),
            },
        }
    }

    fn value(points: &[AttributedPoint], name: &str) -> Option<i64> {
        points
            .iter()
            .find(|p| p.name == name)
            .map(|p| match p.value {
                MetricValue::Int(v) => v,
                MetricValue::Double(v) => v as i64,
            })
    }

    /// 이 테스트가 지키는 것: 누적 카운터가 증가분으로 나가는 것. 첫 sample은 기준선이고, 값이
    /// 줄면(재시작) 그 회차는 보내지 않는다. 순간 값은 매번 그대로 나간다.
    #[test]
    fn counters_become_increments_and_restarts_are_skipped() {
        let mut baseline = CounterBaseline::default();
        let first = sample_points(&postgres(3, 1000), &mut baseline);
        assert_eq!(
            value(&first, "aic.workload.postgresql.numbackends"),
            Some(3)
        );
        assert_eq!(value(&first, "aic.workload.postgresql.xact_commit"), None);
        assert_eq!(value(&first, "aic.workload.up"), Some(1));

        let second = sample_points(&postgres(4, 1060), &mut baseline);
        assert_eq!(
            value(&second, "aic.workload.postgresql.xact_commit"),
            Some(60)
        );
        assert_eq!(
            value(&second, "aic.workload.postgresql.numbackends"),
            Some(4)
        );

        let restarted = sample_points(&postgres(1, 5), &mut baseline);
        assert_eq!(
            value(&restarted, "aic.workload.postgresql.xact_commit"),
            None
        );
        let after = sample_points(&postgres(1, 25), &mut baseline);
        assert_eq!(
            value(&after, "aic.workload.postgresql.xact_commit"),
            Some(20)
        );
    }

    /// 이 테스트가 지키는 것: 대상 구분이 data point 속성에 실리고 연결 주소는 실리지 않는 것.
    #[test]
    fn points_carry_the_workload_identity_but_not_the_endpoint() {
        let points = sample_points(&postgres(3, 1000), &mut CounterBaseline::default());
        for point in &points {
            let keys = point.attributes.iter().map(|(k, _)| *k).collect::<Vec<_>>();
            assert!(keys.contains(&"workload.id"));
            assert!(keys.contains(&"workload.name"));
            assert!(keys.contains(&"workload.adapter"));
            assert!(point.attributes.iter().all(|(_, v)| !v.contains("5432")));
        }
        let name = points[0]
            .attributes
            .iter()
            .find(|(k, _)| *k == "workload.name")
            .unwrap();
        assert_eq!(name.1, "dnx-postgres-1");
    }

    #[test]
    fn a_failed_sample_reports_only_up_with_its_reason() {
        let mut sample = postgres(0, 0);
        sample.outcome = WorkloadSampleOutcome::Failed {
            reason: WorkloadSampleFailure::Rejected,
            detail: "PostgreSQL rejected the statistics request".into(),
        };
        let points = sample_points(&sample, &mut CounterBaseline::default());
        assert_eq!(points.len(), 1);
        assert_eq!(value(&points, "aic.workload.up"), Some(0));
        assert!(points[0]
            .attributes
            .contains(&("status", "rejected".to_string())));
    }

    #[test]
    fn byte_fields_use_the_byte_unit() {
        assert_eq!(unit_for("temp_bytes"), "By");
        assert_eq!(unit_for("used_memory"), "By");
        assert_eq!(unit_for("bytes"), "By");
        assert_eq!(unit_for("xact_commit"), "1");
    }
}
