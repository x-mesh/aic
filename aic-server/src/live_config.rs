//! 실행 중 다시 읽는 `[aicd.exporter]` 스냅샷.
//!
//! aicd는 config를 기동 시 한 번만 읽었다. 주기 하나, 토큰 하나를 바꾸려 해도 데몬을 재시작해야
//! 했고 재시작은 수집 공백을 만든다 — 그 공백은 spool이 메워주지 못한다(꺼져 있던 동안은 수집
//! 자체를 안 한다). 그래서 **이미 각 exporter의 tick 안에서 소비되는 값**만 골라, 스냅샷을 갈아
//! 끼우면 다음 tick부터 새 값이 쓰이게 한다.
//!
//! 여기 실리지 **않는** 값이 더 중요하다. endpoint·spool 상한·task를 띄우는 `*_enabled`는 자원을
//! 다시 만들어야 하므로 여전히 재시작이 필요하다. 스냅샷은 통째로 최신이지만 읽는 쪽이 자기
//! 필드만 꺼내 쓰므로, 반영되지 않는 필드를 여기에 담아도 조용히 무시될 뿐이다.
//!
//! 반영은 두 경로다. 주기가 긴 task(셀프업데이트는 기본 1시간)가 다음 tick까지 기다렸다 바뀌면
//! 설정을 고친 사람에게는 반영이 안 된 것과 구별되지 않으므로, [`LiveExporterConfig::store`]가
//! 세대 카운터를 올려 대기 중인 task를 깨운다. 깨어난 task는 주기만 다시 잡고 다시 기다린다 —
//! 설정 변경이 수집이나 업데이트 확인을 앞당기지는 않는다.

use aic_common::AicdExporterConfig;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::watch;

/// exporter task들이 공유하는 `[aicd.exporter]`의 최신 스냅샷.
///
/// `RwLock<Arc<_>>`인 이유: 읽기는 tick당 한 번(초 단위)이라 경합이 없고, 읽은 값을 `Arc`로
/// 들고 나가면 lock을 즉시 놓을 수 있어 느린 tick이 재적용을 막지 않는다.
pub struct LiveExporterConfig {
    /// 환경변수 `AIC_EXPORTER_TOKEN`는 프로세스 수명 동안 고정이라 생성 시 한 번만 읽는다.
    /// config 평문보다 우선한다는 기존 규칙(`load_*_config`와 동일)을 재적용 때도 지키려면
    /// 스냅샷과 분리해 들고 있어야 한다 — 안 그러면 파일을 다시 읽을 때마다 env가 밀린다.
    token_override: Option<String>,
    snapshot: RwLock<Arc<AicdExporterConfig>>,
    /// 재적용 알림. 값은 세대 카운터일 뿐 내용을 나르지 않는다 — 구독자는 깨어나서 스냅샷을
    /// 직접 읽는다.
    generation: watch::Sender<u64>,
}

impl LiveExporterConfig {
    pub fn new(initial: AicdExporterConfig) -> Self {
        Self {
            token_override: std::env::var("AIC_EXPORTER_TOKEN").ok(),
            snapshot: RwLock::new(Arc::new(initial)),
            generation: watch::Sender::new(0),
        }
    }

    /// 현재 스냅샷. 호출부는 tick 시작에 한 번 받아 그 tick 내내 같은 값을 쓴다 — 한 tick
    /// 중간에 값이 갈리면 같은 배치의 앞뒤가 다른 설정으로 만들어진다.
    pub fn get(&self) -> Arc<AicdExporterConfig> {
        // lock이 poison돼도 값 자체는 유효하다(쓰는 쪽이 panic해도 `Arc` 교체는 원자적이다).
        // 여기서 panic하면 exporter task가 통째로 죽으므로 직전 스냅샷을 그대로 쓴다.
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 새 스냅샷으로 교체하고 대기 중인 task를 깨운다. 내용이 같으면 교체도 알림도 하지 않고
    /// `false`를 돌려준다 — config 파일을 만질 때마다 "재적용" 로그가 뜨면 진짜 변경 신호가 묻힌다.
    pub fn store(&self, next: AicdExporterConfig) -> bool {
        {
            let mut guard = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
            if **guard == next {
                return false;
            }
            *guard = Arc::new(next);
        }
        self.generation.send_modify(|g| *g += 1);
        true
    }

    /// 재적용 알림 구독. 구독 시점의 세대는 이미 본 것으로 표시되므로, 이후 변경에만 깨어난다.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// 지금 전송에 쓸 토큰. env override가 있으면 config를 다시 읽어도 그쪽이 이긴다.
    pub fn token(&self) -> Option<String> {
        self.token_override
            .clone()
            .or_else(|| self.get().token.clone())
    }
}

impl std::fmt::Debug for LiveExporterConfig {
    /// 각 exporter의 `Config`가 `Debug`를 파생하므로 이 타입도 필요하다. 토큰은 유무만 드러낸다 —
    /// `Config`를 통째로 로그에 찍는 순간 자격이 평문으로 남는다.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveExporterConfig")
            .field("token_override", &self.token_override.is_some())
            .field("generation", &*self.generation.borrow())
            .finish_non_exhaustive()
    }
}

/// 지금 전송에 쓸 토큰. 라이브 스냅샷이 없으면(테스트 등) 기동 시 값 그대로.
pub fn effective_token(
    live: Option<&Arc<LiveExporterConfig>>,
    fallback: &Option<String>,
) -> Option<String> {
    match live {
        Some(l) => l.token(),
        None => fallback.clone(),
    }
}

/// 재적용 알림을 기다린다. 구독자가 없으면 영원히 기다린다 — `select!`에서 이 브랜치가 아예
/// 없는 것과 같아져, 라이브 스냅샷 유무로 루프 모양이 갈리지 않는다.
pub async fn changed(rx: &mut Option<watch::Receiver<u64>>) {
    match rx {
        Some(r) => {
            let _ = r.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// config의 주기 초를 `Duration`으로 바꾼다. 0초는 busy loop이고 `tokio::time::interval`은
/// 아예 panic하므로, 기동 경로(`load_*_config`)와 같은 하한을 재적용에도 적용한다.
pub fn live_interval(secs: u64) -> Duration {
    Duration::from_secs(secs.max(1))
}

/// ticker의 주기를 바꾼다. 같은 값이면 아무것도 하지 않는다.
///
/// `exporter`는 로그에서 어느 task의 주기가 바뀌었는지 가리키는 이름이다 — 다섯 task가 같은
/// 문구를 쓰므로 이게 없으면 로그만 보고는 구분할 수 없다.
pub fn retune_ticker(ticker: &mut tokio::time::Interval, next: Duration, exporter: &'static str) {
    let current = ticker.period();
    if current == next {
        return;
    }
    tracing::info!(
        exporter,
        from_secs = current.as_secs(),
        to_secs = next.as_secs(),
        "수집 주기 변경 적용"
    );
    // `interval()`은 첫 tick이 즉시 완료된다 — 주기를 바꿀 때마다 수집이 한 번 더 도는 걸 막으려고
    // 첫 tick을 새 주기만큼 뒤로 민다.
    *ticker = tokio::time::interval_at(tokio::time::Instant::now() + next, next);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_token(token: Option<&str>) -> LiveExporterConfig {
        LiveExporterConfig {
            token_override: token.map(str::to_string),
            snapshot: RwLock::new(Arc::new(AicdExporterConfig::default())),
            generation: watch::Sender::new(0),
        }
    }

    #[test]
    fn storing_the_same_content_reports_no_change() {
        // 재적용 로그가 config 파일을 만질 때마다 뜨면 "뭔가 바뀌었다"는 신호가 죽는다.
        let live = LiveExporterConfig::new(AicdExporterConfig::default());
        assert!(!live.store(AicdExporterConfig::default()));
    }

    #[test]
    fn a_changed_field_is_visible_to_the_next_reader() {
        let live = LiveExporterConfig::new(AicdExporterConfig::default());
        let next = AicdExporterConfig {
            interval_secs: AicdExporterConfig::default().interval_secs + 7,
            ..AicdExporterConfig::default()
        };
        assert!(live.store(next.clone()));
        assert_eq!(live.get().interval_secs, next.interval_secs);
    }

    #[tokio::test]
    async fn a_real_change_wakes_a_waiting_task() {
        // 셀프업데이트는 기본 1시간 주기다 — 깨우지 않으면 주기를 줄여도 한 시간 뒤에야 바뀐다.
        let live = Arc::new(LiveExporterConfig::new(AicdExporterConfig::default()));
        let mut rx = Some(live.subscribe());
        let next = AicdExporterConfig {
            self_update_interval_secs: 60,
            ..AicdExporterConfig::default()
        };
        assert!(live.store(next));
        // 이미 알림이 대기 중이므로 즉시 반환한다.
        changed(&mut rx).await;
    }

    #[tokio::test]
    async fn no_subscription_means_the_branch_never_fires() {
        let mut rx = None;
        tokio::select! {
            _ = changed(&mut rx) => panic!("구독이 없는데 깨어났다"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    #[test]
    fn an_env_token_outranks_a_reloaded_config_token() {
        // config를 다시 읽는다고 해서 운영자가 env로 주입한 자격이 밀리면 안 된다.
        let live = with_token(Some("from-env"));
        live.store(AicdExporterConfig {
            token: Some("rotated-in-config".into()),
            ..AicdExporterConfig::default()
        });
        assert_eq!(live.token().as_deref(), Some("from-env"));
    }

    #[test]
    fn without_an_env_token_the_reloaded_config_token_wins() {
        let live = with_token(None);
        live.store(AicdExporterConfig {
            token: Some("rotated-in-config".into()),
            ..AicdExporterConfig::default()
        });
        assert_eq!(live.token().as_deref(), Some("rotated-in-config"));
    }

    #[test]
    fn a_zero_interval_never_reaches_tokio() {
        // `tokio::time::interval(Duration::ZERO)`는 panic한다 — 오타 하나로 데몬이 죽으면 안 된다.
        assert_eq!(live_interval(0), Duration::from_secs(1));
        assert_eq!(live_interval(30), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn retuning_to_the_same_period_keeps_the_ticker() {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.tick().await; // `interval`의 첫 tick은 즉시 완료된다.
        retune_ticker(&mut ticker, Duration::from_secs(60), "test");
        assert_eq!(ticker.period(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn retuning_does_not_fire_an_extra_tick() {
        // 주기를 바꿀 때마다 수집이 한 번 더 돌면, 주기를 줄이는 것만으로 부하가 튄다.
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.tick().await;
        retune_ticker(&mut ticker, Duration::from_secs(30), "test");
        assert_eq!(ticker.period(), Duration::from_secs(30));
        tokio::select! {
            _ = ticker.tick() => panic!("주기 변경 직후 tick이 즉시 발생했다"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
}
