//! aicd OTLP DNS observer (Phase 2, 도메인 수집 `topology-domain` 결정).
//!
//! opt-in(config `[aicd.exporter]`의 `dns_enabled`, 기본 false — 도메인은 운영/PII 정보)으로,
//! aicd가 **eBPF getaddrinfo uprobe**로 프로세스의 이름 해석(FQDN↔IP)을 관측해 OTLP
//! Logs(scope=`aic.dns`)로 `{endpoint}/v1/logs`에 push한다. RCA가 connection의
//! `remote_addr == answer_ip`(+시각·host)로 조인해 숫자 IP에 도메인을 붙일 수 있게 하는 신호다.
//!
//! **현재는 골격이다**: 실제 eBPF 프로그램(aya getaddrinfo uprobe object + perf buffer 루프 +
//! 유저메모리 파싱), aya 의존성, CAP_BPF 권한 게이트는 **Linux 세션**(mem `b496b0e0`)에서 채운다.
//! 이 파일은 config 게이트·task 배선·플랫폼 게이트·Phase 1 인코더 연결(전송 규약)까지만 확정한다.
//! `dns_enabled=true`로 켜도 관측 백엔드가 없어 지금은 데이터가 나오지 않는다(로그만).
//!
//! **`serve_connections`와의 차이**: connections는 `aic snapshot inventory`를 주기 exec하는 주기
//! 캡처지만, DNS는 uprobe 이벤트 스트림이라 주기(interval)가 없다 — 그래서 `DnsConfig`에는
//! `interval`/`aic_bin`/`timeout`이 없다.
//!
//! t8 spool 규약은 connections와 동일하다: push 실패 시 공유 [`super::Spool`]에
//! `SignalKind::Logs`로 적재하고, 드레인은 하지 않는다(host metrics task(`serve`)가 단일 드레인 주체).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use super::logs_proto::{self, ResourceAttrs};
use super::{SignalKind, Spool};

/// HTTP 요청 타임아웃 — 다른 exporter task와 동일 값. Linux eBPF 루프가 reqwest 클라이언트를 만들
/// 때 쓴다(Phase 2 골격이라 아직 미사용).
#[allow(dead_code)]
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// DNS observer 실행 설정. connections 동형이되 uprobe 스트림이라 `interval`/`aic_bin`/`timeout`은 없다.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// OTLP collector base URL. `/v1/logs`가 append된다.
    pub endpoint: String,
    /// `Authorization: Bearer` 토큰. None이면 헤더 없이 전송.
    pub token: Option<String>,
    /// resource `service.version`으로 붙일 aicd 버전.
    pub service_version: String,
    /// 오프라인 spool(SRE t8). 다른 exporter config와 동일 인스턴스를 공유한다.
    pub spool: Arc<Spool>,
    /// 전송 건강 카운터. 다른 exporter task가 공유해 chat status bar가 한 번에 읽는다.
    pub health: Arc<super::ExporterHealth>,
}

/// DNS observer를 실행한다. `shutdown`이 true가 되면 graceful하게 종료한다.
///
/// **골격**: 실제 관측 백엔드(Linux eBPF uprobe)가 없어 지금은 로그를 남기고 shutdown까지 idle한다.
/// Linux 세션에서 이 idle 자리에 aya uprobe 로더 + perf buffer 루프를 꽂고, 관측 이벤트마다
/// [`to_observation`] → [`DnsSink::emit`]을 호출한다.
pub async fn serve_dns(cfg: DnsConfig, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    // cfg는 Linux eBPF 루프가 DnsSink로 감쌀 전송 컨텍스트다. 골격 단계에선 관측 백엔드가 없어
    // 참조만 하고 idle한다(계약 유지 + 미사용 경고 방지).
    let _ = &cfg;

    #[cfg(not(target_os = "linux"))]
    tracing::info!("DNS observer: 미지원 플랫폼 — 비활성(eBPF getaddrinfo uprobe는 Linux 전용)");
    #[cfg(target_os = "linux")]
    tracing::info!(
        "DNS observer: eBPF 미구현 — 백로그(Linux 세션, mem b496b0e0)에서 채운다. 현재 no-op"
    );

    // shutdown까지 대기 — 다른 exporter task와 동일한 정상 종료 흐름을 지킨다.
    loop {
        if *shutdown.borrow() {
            break;
        }
        if shutdown.changed().await.is_err() {
            break;
        }
    }
    tracing::info!("OTLP dns observer 종료");
    Ok(())
}

/// DNS 관측을 collector로 흘려보내는 전송 컨텍스트.
///
/// **Phase 2 골격**: Linux eBPF 루프가 이 sink를 들고, getaddrinfo uprobe 이벤트마다 [`DnsSink::emit`]을
/// 호출한다. 지금은 관측 백엔드가 없어 프로덕션 경로에 연결돼 있지 않다. `client`/`url`은 [`serve_dns`]가
/// [`DnsConfig`]로 만들어 채운다(reqwest 클라이언트에 [`HTTP_TIMEOUT`] 적용).
#[allow(dead_code)]
struct DnsSink<'a> {
    client: &'a reqwest::Client,
    url: &'a str,
    token: Option<&'a str>,
    service_version: &'a str,
    spool: &'a Spool,
    health: &'a super::ExporterHealth,
}

impl DnsSink<'_> {
    /// 하나의 DNS 관측을 `aic.dns` protobuf로 인코딩해 push한다(실패 시 spool 적재 + health 갱신).
    /// connections의 push 규약([`super::push_logs`] → 실패 시 [`Spool::append`] +
    /// [`super::ExporterHealth::record_fail`])을 그대로 따른다. 드레인은 하지 않는다.
    #[allow(dead_code)]
    async fn emit(
        &self,
        obs: &logs_proto::DnsObservation<'_>,
        resource: &ResourceAttrs<'_>,
        time_unix_nano: u64,
    ) {
        let body = logs_proto::encode_dns_observations(
            std::slice::from_ref(obs),
            resource,
            self.service_version,
            time_unix_nano,
        );
        match super::push_logs(self.client, self.url, self.token, body.clone()).await {
            Ok(()) => self.health.record_ok(),
            Err(e) => {
                tracing::warn!(error = %e, "OTLP dns push 실패 — spool에 적재");
                if let Err(e2) = self.spool.append(SignalKind::Logs, &body) {
                    tracing::warn!(error = %e2, "OTLP dns spool append 실패 — 이 관측 유실");
                }
                self.health.record_fail();
            }
        }
    }
}

/// uprobe 파싱 결과를 [`logs_proto::DnsObservation`]으로 변환하는 순수 함수.
///
/// **Phase 2 골격**: Linux eBPF 루프가 getaddrinfo 인자/반환을 읽어 이 함수로 조립한다.
///
/// **TTL(중요)**: getaddrinfo uprobe는 DNS TTL을 노출하지 않는다(resolver를 추상화하므로). 그래서
/// `ttl`/`expires_at_unix_nano`를 0으로 두고, 수신측(RCA)은 이 소스에 TTL 기반 만료 판정을 적용하지
/// 않는다. 정확한 TTL은 향후 UDP/53 패킷 파싱 보강 시(별도 결정) 확보한다. `source`는 `"dns"` —
/// resolver 경유 관측이라는 뜻이다.
#[allow(dead_code)]
fn to_observation<'a>(
    question_name: &'a str,
    question_type: &'a str,
    answers: &'a [&'a str],
    pid: Option<i64>,
    process_name: Option<&'a str>,
) -> logs_proto::DnsObservation<'a> {
    logs_proto::DnsObservation {
        question_name,
        question_type,
        answers,
        ttl: 0,
        expires_at_unix_nano: 0,
        source: "dns",
        pid,
        process_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn to_observation_maps_fields_and_zeroes_ttl_for_uprobe_source() {
        let answers = ["1.2.3.4", "5.6.7.8"];
        let obs = to_observation("api.example.com", "A", &answers, Some(42), Some("curl"));
        assert_eq!(obs.question_name, "api.example.com");
        assert_eq!(obs.question_type, "A");
        assert_eq!(obs.answers, &["1.2.3.4", "5.6.7.8"]);
        // getaddrinfo uprobe는 TTL을 못 준다 — 0으로 두고 수신측이 만료 판정을 스킵하게 한다.
        assert_eq!(obs.ttl, 0);
        assert_eq!(obs.expires_at_unix_nano, 0);
        assert_eq!(obs.source, "dns");
        assert_eq!(obs.pid, Some(42));
        assert_eq!(obs.process_name, Some("curl"));
    }

    #[test]
    fn to_observation_then_encode_produces_valid_aic_dns_protobuf() {
        // to_observation → Phase 1 encode_dns_observations 배선이 유효한 aic.dns 요청을 만든다.
        let answers = ["10.0.0.1"];
        let obs = to_observation("a.example.com", "A", &answers, None, None);
        let resource = ResourceAttrs {
            host_name: "h",
            host_id: "id",
            os_type: "linux",
            host_ip: None,
        };
        let bytes =
            logs_proto::encode_dns_observations(std::slice::from_ref(&obs), &resource, "0.27.0", 1);
        let req =
            logs_proto::ExportLogsServiceRequest::decode(bytes.as_slice()).expect("valid protobuf");
        assert_eq!(
            req.resource_logs[0].scope_logs[0]
                .scope
                .as_ref()
                .unwrap()
                .name,
            "aic.dns"
        );
    }
}
