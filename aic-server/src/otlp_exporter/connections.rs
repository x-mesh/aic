//! aicd OTLP connections/inventory exporter (SRE t7).
//!
//! opt-in(config `[aicd.exporter]`의 `connections_enabled`, 기본 exporter 활성 시 true)으로,
//! aicd가 주기적으로 `aic snapshot inventory --json`(hidden CLI leaf, aic-client
//! `agent::net_inventory`)을 spawn해 listen/established 소켓 + host IP를 얻은 뒤 OTLP
//! Logs(scope=`aic.connections`)로 인코딩해 `{endpoint}/v1/logs`로 push한다.
//!
//! **JSON wire contract**: 이 파일의 [`InventorySnapshot`]/[`RawConnection`]은 `aic-client`의
//! `agent::net_inventory::{InventorySnapshot, ConnectionInfo}`와 필드명이 반드시 일치해야 한다
//! (직접 타입 공유가 아니라 프로세스 경계를 넘는 JSON 계약이다 — aic-server는 aic-client에
//! 의존하지 않으므로 crate 경계에서 독립적으로 정의한다. 한쪽 필드명을 바꾸면 반드시 양쪽 다
//! 갱신할 것).
//!
//! spawn 실패/timeout/파싱 실패는 캡처 자체의 문제라 push/spool/backoff와 무관하게 다음 주기까지
//! 단순 skip한다(재시도해도 같은 이유로 또 실패할 가능성이 높다 — collector 도달 불가와는 다른
//! 성격의 실패).
//!
//! t8: 스냅샷 캡처는 성공했지만 push가 실패하면 공유 [`super::Spool`]에 적재한다. 드레인은 하지
//! 않는다(host metrics task(`serve`)가 단일 드레인 주체 — spool.rs 모듈 doc 참고). backoff는 이
//! task 자신의 push 성패만으로 독립 관리한다(events.rs와 동일 이유).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::watch;

use super::backoff::Backoff;
use super::logs_proto::{self, ConnectionEntry, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// `aic snapshot inventory --json` stdout 상한. 정상 환경에서 연결 수백 개도 이 한도를 훨씬
/// 밑돈다 — 초과분은 신뢰할 수 없는 출력으로 간주해 이번 주기를 스킵한다(OOM/무한 출력 방어).
const MAX_INVENTORY_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// connections exporter 실행 설정.
#[derive(Debug, Clone)]
pub struct ConnectionsConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 캡처 주기.
    pub interval: Duration,
    /// spawn할 `aic` 실행 파일 경로.
    pub aic_bin: PathBuf,
    /// `aic snapshot inventory --json` 프로세스 타임아웃(hung 방어).
    pub timeout: Duration,
    /// 오프라인 spool(SRE t8). host metrics/events config와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 네 exporter task가 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// connections exporter를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
pub async fn serve_connections(
    cfg: ConnectionsConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let url = super::logs_url(&cfg.endpoint);
    tracing::info!(
        url = %url,
        interval_secs = cfg.interval.as_secs(),
        aic_bin = %cfg.aic_bin.display(),
        "OTLP connections exporter 시작"
    );

    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff = Backoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                match capture_inventory(&cfg.aic_bin, cfg.timeout).await {
                    Ok(snapshot) => {
                        if snapshot.connections.is_empty() {
                            continue;
                        }
                        let entries: Vec<ConnectionEntry<'_>> = snapshot
                            .connections
                            .iter()
                            .map(|c| ConnectionEntry {
                                protocol: &c.protocol,
                                state: &c.state,
                                local_addr: &c.local_addr,
                                local_port: c.local_port,
                                peer_addr: c.peer_addr.as_deref(),
                                peer_port: c.peer_port,
                                process: c.process.as_deref(),
                                direction: c.direction.as_deref(),
                            })
                            .collect();
                        let resource = ResourceAttrs {
                            host_name: &snapshot.host.name,
                            host_id: &snapshot.host.id,
                            os_type: &snapshot.host.os,
                            host_ip: snapshot.host.ip.as_deref(),
                        };
                        let body = logs_proto::encode_connections(
                            &entries,
                            &resource,
                            &cfg.service_version,
                            super::unix_nanos_now(),
                        );

                        if !backoff.ready() {
                            if let Err(e) = cfg.spool.append(SignalKind::Logs, &body) {
                                tracing::warn!(error = %e, "OTLP connections spool append 실패 — 이 스냅샷 유실");
                            }
                            continue;
                        }

                        match super::push_logs(&client, &url, cfg.token.as_deref(), body.clone()).await {
                            Ok(()) => {
                                backoff.on_success();
                                cfg.health.record_ok();
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "OTLP connections push 실패 — spool에 적재");
                                if let Err(e2) = cfg.spool.append(SignalKind::Logs, &body) {
                                    tracing::warn!(error = %e2, "OTLP connections spool append 실패 — 이 스냅샷 유실");
                                }
                                backoff.on_failure();
                                cfg.health.record_fail();
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "connections 스냅샷 캡처/파싱 실패 — 다음 주기까지 skip");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("OTLP connections exporter 종료");
    Ok(())
}

/// `aic_bin snapshot inventory --json`을 spawn해 stdout을 [`InventorySnapshot`]으로 파싱한다.
/// timeout 초과, spawn 실패, non-zero exit, 출력 상한 초과, JSON 파싱 실패 모두 `Err`.
async fn capture_inventory(
    aic_bin: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<InventorySnapshot> {
    let mut cmd = tokio::process::Command::new(aic_bin);
    cmd.args(["snapshot", "inventory", "--json"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let child = cmd.spawn()?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "aic snapshot inventory가 {}초 내에 끝나지 않음",
                timeout.as_secs()
            )
        })??;

    if !output.status.success() {
        anyhow::bail!("aic snapshot inventory가 {} 로 종료", output.status);
    }
    if output.stdout.len() > MAX_INVENTORY_OUTPUT_BYTES {
        anyhow::bail!(
            "aic snapshot inventory 출력이 상한({MAX_INVENTORY_OUTPUT_BYTES} bytes)을 초과함 — 신뢰할 수 없는 출력으로 간주"
        );
    }
    let snapshot: InventorySnapshot = serde_json::from_slice(&output.stdout)?;
    Ok(snapshot)
}

// ── JSON wire contract (aic-client net_inventory와 필드명 동기화 — 모듈 doc 참고) ──────

#[derive(Debug, Deserialize)]
struct InventorySnapshot {
    #[allow(dead_code)]
    schema_version: u32,
    host: HostMeta,
    connections: Vec<RawConnection>,
}

#[derive(Debug, Deserialize)]
struct HostMeta {
    name: String,
    /// host_metrics.rs의 `host_id()`와 동일 기법(`/etc/machine-id` 등)으로 aic-client
    /// `net_inventory`가 독립적으로 계산한다 — 같은 물리 호스트라면 동일 값이 나와 metrics/events/
    /// connections 세 signal의 resource.host.id로 상관관계를 지을 수 있다.
    id: String,
    ip: Option<String>,
    os: String,
}

#[derive(Debug, Deserialize)]
struct RawConnection {
    protocol: String,
    state: String,
    local_addr: String,
    local_port: u16,
    peer_addr: Option<String>,
    peer_port: Option<u16>,
    /// 소켓 소유 프로세스명. `Option`+`default`라 이 필드를 모르는 **구 `aic` 바이너리**와의 버전
    /// skew에도 스냅샷 전체가 실패하지 않는다(반대 방향인 신 client + 구 server는
    /// `deny_unknown_fields`가 없어 이미 안전하다).
    #[serde(default)]
    process: Option<String>,
    /// `"listen"`|`"inbound"`|`"outbound"` — aic-client가 스냅샷 전체를 보고 파생한 값을 그대로
    /// 통과시킨다. 여기서 재해석하지 않는다: 판정에 필요한 문맥은 client만 갖고 있다.
    #[serde(default)]
    direction: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// stdout에 고정 JSON을 출력하는 실행 가능한 shell 스크립트를 만든다(실제 `aic` 바이너리
    /// 없이 spawn+timeout+parse 파이프라인 전체를 결정적으로 검증하기 위한 test double).
    fn fake_aic_bin(dir: &tempfile::TempDir, script: &str) -> std::path::PathBuf {
        let path = dir.path().join("fake-aic");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{script}").unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// `ETXTBSY`("Text file busy")인가.
    fn is_text_file_busy(e: &anyhow::Error) -> bool {
        e.downcast_ref::<std::io::Error>()
            .and_then(|io| io.raw_os_error())
            == Some(libc::ETXTBSY)
    }

    /// [`capture_inventory`]를 ETXTBSY에 한해 짧게 재시도한다.
    ///
    /// 리눅스에서만 나는 멀티스레드 exec 레이스다(rust-lang/rust#114554): 이 테스트가 방금 쓴
    /// `fake-aic`를 exec하는 순간, **다른 테스트 스레드가 fork한 자식**이 아직 그 파일의 write-fd를
    /// 상속해 들고 있으면(CLOEXEC은 exec 시점에야 닫힌다) 커널이 `ETXTBSY`로 exec을 거부한다.
    /// 그 자식이 자기 exec을 끝내면 fd가 닫히고 우리 exec이 통과하므로, 잠깐 기다렸다 다시 건다.
    ///
    /// **프로덕션 경로에는 없는 문제다** — 실제 `aic` 바이너리는 방금 쓴 파일이 아니다. 그래서
    /// [`capture_inventory`] 자체는 건드리지 않고 테스트에서만 감싼다.
    async fn capture_inventory_retrying(
        bin: &std::path::Path,
        timeout: Duration,
    ) -> anyhow::Result<InventorySnapshot> {
        for _ in 0..50 {
            match capture_inventory(bin, timeout).await {
                Err(e) if is_text_file_busy(&e) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => return other,
            }
        }
        capture_inventory(bin, timeout).await
    }

    #[tokio::test]
    async fn capture_inventory_parses_valid_json_output() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"schema_version":1,"host":{"name":"web-1","id":"host-abc123","ip":"10.0.0.5","os":"linux"},"connections":[{"protocol":"tcp","state":"LISTEN","local_addr":"0.0.0.0","local_port":22,"peer_addr":null,"peer_port":null}]}"#;
        let bin = fake_aic_bin(&dir, &format!("cat <<'EOF'\n{json}\nEOF"));

        let snapshot = capture_inventory_retrying(&bin, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(snapshot.host.name, "web-1");
        assert_eq!(snapshot.host.id, "host-abc123");
        assert_eq!(snapshot.host.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].local_port, 22);
    }

    #[tokio::test]
    async fn capture_inventory_parses_process_and_direction() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"schema_version":1,"host":{"name":"web-1","id":"host-abc123","ip":"10.0.0.5","os":"linux"},"connections":[{"protocol":"tcp","state":"ESTAB","local_addr":"192.168.1.5","local_port":22,"peer_addr":"192.168.1.10","peer_port":54321,"process":"sshd","direction":"inbound"}]}"#;
        let bin = fake_aic_bin(&dir, &format!("cat <<'EOF'\n{json}\nEOF"));

        let snapshot = capture_inventory_retrying(&bin, Duration::from_secs(5))
            .await
            .unwrap();
        let c = &snapshot.connections[0];
        assert_eq!(c.process.as_deref(), Some("sshd"));
        assert_eq!(c.direction.as_deref(), Some("inbound"));
    }

    /// 구 `aic` 바이너리(process/direction 필드가 없는 스냅샷)와의 버전 skew에서도 파싱이 실패하지
    /// 않아야 한다 — 필드가 빠지면 `None`이 되고, exporter는 attr을 생략해 rca가 폴백 파생을 돈다.
    #[tokio::test]
    async fn capture_inventory_accepts_snapshot_without_process_and_direction() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"schema_version":1,"host":{"name":"web-1","id":"host-abc123","ip":"10.0.0.5","os":"linux"},"connections":[{"protocol":"tcp","state":"LISTEN","local_addr":"0.0.0.0","local_port":22,"peer_addr":null,"peer_port":null}]}"#;
        let bin = fake_aic_bin(&dir, &format!("cat <<'EOF'\n{json}\nEOF"));

        let snapshot = capture_inventory_retrying(&bin, Duration::from_secs(5))
            .await
            .unwrap();
        let c = &snapshot.connections[0];
        assert_eq!(c.process, None);
        assert_eq!(c.direction, None);
    }

    #[tokio::test]
    async fn capture_inventory_errors_on_nonzero_exit() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_aic_bin(&dir, "exit 1");
        let err = capture_inventory_retrying(&bin, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("종료"), "err={err}");
    }

    #[tokio::test]
    async fn capture_inventory_errors_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_aic_bin(&dir, "echo 'not json'");
        assert!(capture_inventory_retrying(&bin, Duration::from_secs(5))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn capture_inventory_times_out_on_hung_process() {
        let dir = tempfile::tempdir().unwrap();
        let bin = fake_aic_bin(&dir, "sleep 30");
        let err = capture_inventory_retrying(&bin, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("끝나지 않음"), "err={err}");
    }

    #[tokio::test]
    async fn capture_inventory_errors_on_spawn_failure() {
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/aic");
        assert!(capture_inventory(&missing, Duration::from_secs(5))
            .await
            .is_err());
    }
}
