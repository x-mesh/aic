//! exporter 전송 건강 상태 — 네 exporter task가 공유하는 카운터.
//!
//! 왜 필요한가: exporter는 aicd 안에서 조용히 돈다. push가 계속 실패해도 aicd 로그에만 WARN이
//! 남을 뿐, chat을 쓰는 사람은 "내 행위가 서버로 나가고 있다"고 **믿을 뿐 확인할 방법이 없다**.
//! 실제로 구버전 aicd가 exporter 없이 돌던 동안 아무도 눈치채지 못한 사고가 있었다. 그래서
//! 전송 성패를 카운터로 남기고, `GetExporterStatus` IPC로 chat status bar가 읽어간다.
//!
//! 네 task(host metrics/events/connections/agent)가 같은 인스턴스를 `Arc`로 공유한다 — 사람이
//! 알고 싶은 건 "이 호스트의 텔레메트리가 서버에 닿고 있나"이지 어느 signal이 실패했는지가
//! 아니기 때문이다. 개별 signal의 실패는 로그에 남는다.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use super::logs::DropCounters;
use super::{DropReason, PushError, SignalKind, Spool};

/// exporter 전송 카운터 + spool 참조. 모든 필드는 lock-free다(push 경로에 락을 넣지 않는다).
#[derive(Debug)]
pub struct ExporterHealth {
    push_ok_total: AtomicU64,
    push_fail_total: AtomicU64,
    /// 마지막 push 성공 시각(unix seconds). 0이면 "성공한 적 없음".
    last_ok_unix: AtomicU64,
    /// agent exporter task(`serve_agent`)가 **지금 살아있는지**. config 플래그가 아니라 실제 생존
    /// 여부를 담는다 — `agent_enabled=true`여도 endpoint 미설정·spool 실패로 task가 안 뜨거나,
    /// 떴다가 죽을 수 있고, 그 경우 이벤트는 똑같이 버려지기 때문이다. 사람이 알아야 하는 건
    /// 설정값이 아니라 **지금 내 이벤트를 받아 갈 구독자가 있느냐**다.
    ///
    /// **"떴다"가 아니라 "살아있다"**임에 유의: spawn 여부만 새기면 단방향 래치가 되어, task가
    /// 죽은 뒤에도 영원히 "살아있음"으로 남는다. 반대로 task가 **켜는** 구조면 spawn~task 시작
    /// 사이가 거짓 false인 창이 되어, 멀쩡히 전달될 메모를 "유실"이라 오보한다.
    ///
    /// 그래서 켜기/끄기의 주체를 나눈다:
    /// - **켠다**: 부모(aicd_main)가 **구독(`bus.subscribe()`) 직후, spawn 전에** 켠다. 구독이
    ///   성립한 순간이 곧 "이 이벤트는 버려지지 않는다"가 참이 되는 시점이다(task가 아직 첫
    ///   `recv()`를 안 돌려도 채널 버퍼가 보존한다). 그래서 창이 없다.
    /// - **끈다**: task 안의 RAII 가드([`AgentLiveGuard`])가 종료(정상·에러·panic) 시 Drop으로 끈다.
    ///
    /// (가드가 켜기까지 하면 안 되는 이유가 하나 더 있다: task가 즉시 죽어 Drop이 false를 쓴 **뒤에**
    /// 부모가 true를 쓰면 다시 래치된다. 켜기를 spawn 전에 두면 그 경쟁 자체가 없다.)
    /// 초기값 false(=아직 구독자 없음)도 사실과 어긋나지 않는다.
    agent_live: AtomicBool,
    /// **config에서 agent exporter를 켜 두었는가**(`[aicd.exporter] agent_enabled`).
    /// `agent_live`(실제 생존)와 다른 축이다 — 둘을 합쳐야 "설정이 꺼짐"과 "설정은 켰는데 못 떴음"을
    /// 구분해 맞는 조치를 안내할 수 있다(후자에 "설정을 켜라"고 하면 오진이다).
    agent_configured: AtomicBool,
    /// 오프라인 spool — 밀린 배치 수/버린 수를 여기서 읽는다.
    spool: Arc<Spool>,
    /// collector base URL(표시용).
    endpoint: String,
    /// **마지막 push 실패 한 건**. 예전에는 실패 수만 셌기 때문에, 유실을 발견해도 collector가
    /// 죽은 건지 토큰이 거부된 건지 알 수 없어 aicd 로그를 직접 여는 수밖에 없었다 — 그 한 줄을
    /// 상태에 실어 chat status bar와 `aic doctor`가 사유까지 보여 줄 수 있게 한다.
    ///
    /// `Mutex`인 이유: 값이 문자열 둘이라 원자 타입으로 담을 수 없다. push **실패** 경로에서만
    /// 잠그므로(성공 경로는 건드리지 않는다) 정상 동작 중에는 경합이 없다.
    last_failure: Mutex<Option<StoredFailure>>,
    /// 로그 수집기의 드롭 카운터 — `collector_dropped`(200 응답인데 수신측이 버린 레코드 수)를
    /// 읽는다. exporter보다 나중에 만들어지므로 [`Self::attach_drop_counters`]로 1회 주입한다.
    drop_counters: OnceLock<Arc<DropCounters>>,
}

/// [`ExporterHealth::last_failure`]에 보관하는 실패 1건. IPC 타입과 달리 시각을 절대값으로 들고
/// 있다가 스냅샷 시점에 경과 초로 환산한다(보관 시점의 "몇 초 전"은 읽는 순간 이미 틀린 값이다).
#[derive(Debug, Clone)]
struct StoredFailure {
    unix_secs: u64,
    url: String,
    permanent: bool,
    message: String,
}

impl ExporterHealth {
    pub fn new(endpoint: String, spool: Arc<Spool>) -> Self {
        Self {
            push_ok_total: AtomicU64::new(0),
            push_fail_total: AtomicU64::new(0),
            last_ok_unix: AtomicU64::new(0),
            agent_live: AtomicBool::new(false),
            agent_configured: AtomicBool::new(false),
            spool,
            endpoint,
            last_failure: Mutex::new(None),
            drop_counters: OnceLock::new(),
        }
    }

    /// 로그 수집기의 드롭 카운터를 연결한다(aicd_main이 기동 시 1회).
    ///
    /// collector가 200으로 받고도 `partial_success`로 레코드를 버리면 push는 성공이라 실패
    /// 카운터가 오르지 않는다 — 그 유실은 이 카운터에만 남는다. 연결하지 않으면 0으로 보고한다
    /// (모르는 값을 지어내지 않는다).
    pub fn attach_drop_counters(&self, counters: Arc<DropCounters>) {
        let _ = self.drop_counters.set(counters);
    }

    /// agent exporter task의 생존 여부를 기록한다.
    ///
    /// **단방향 래치가 아니다** — 반드시 `false`로 되돌아갈 수 있어야 한다. "떴다"와 "살아있다"는
    /// 다른 명제다: `serve_agent`가 endpoint 오류·spool 실패·panic으로 죽으면 구독자는 사라지는데,
    /// 켜진 채로 남으면 `/record now`가 그 뒤로도 영원히 "잘 기록됐다"고 보고한다.
    ///
    /// 호출 규약(`agent_live` 필드 doc 참고): **켜는 건 부모가 구독 직후·spawn 전에 한 번**,
    /// **끄는 건 task 안의 [`AgentLiveGuard`]가 Drop에서**. 순서를 지켜야 유실 창도, 래치도 없다.
    pub fn set_agent_live(&self, live: bool) {
        self.agent_live.store(live, Ordering::Relaxed);
    }

    /// config에서 agent exporter를 켜 두었는지 기록한다(aicd_main이 기동 시 1회).
    /// 생존(`agent_live`)과 **다른 축**이다 — 이 둘이 있어야 "설정이 꺼짐"과 "설정은 켰는데 못 떴음"을
    /// 구분해 안내할 수 있다.
    pub fn set_agent_configured(&self, configured: bool) {
        self.agent_configured.store(configured, Ordering::Relaxed);
    }

    /// push 1건 성공. 마지막 성공 시각도 갱신한다.
    pub fn record_ok(&self) {
        self.push_ok_total.fetch_add(1, Ordering::Relaxed);
        self.last_ok_unix.store(unix_now_secs(), Ordering::Relaxed);
    }

    /// push 1건 실패(spool에 적재됨). **사유를 함께 남긴다** — 실패 수만으로는 무엇을 고쳐야
    /// 하는지 알 수 없고, 그때마다 aicd 로그를 여는 것이 유일한 방법이었다.
    ///
    /// `url`은 실패한 요청 주소(`.../v1/metrics` 또는 `.../v1/logs`)라 어느 신호가 막혔는지도
    /// 함께 드러난다.
    pub fn record_fail(&self, url: &str, err: &PushError) {
        self.push_fail_total.fetch_add(1, Ordering::Relaxed);
        let stored = StoredFailure {
            unix_secs: unix_now_secs(),
            url: url.to_string(),
            permanent: err.is_permanent(),
            message: err.reason().to_string(),
        };
        // 잠금이 poison돼도 건강 보고 때문에 exporter를 죽이지는 않는다 — 사유 한 건을 못 남길 뿐이다.
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some(stored);
        }
    }

    /// collector가 배치를 **영구 거부**해 버렸다 — push 자체는 도달했으므로 실패 카운터는 올리지
    /// 않고, 마지막 사유만 갱신한다. 이 경로가 없으면 app log 배치가 통째로 사라진 이유가 상태
    /// 어디에도 남지 않는다(카운터는 `spool_dropped_rejected`/`aic.log.dropped`가 든다).
    pub fn record_rejection(&self, url: &str, err: &PushError) {
        let stored = StoredFailure {
            unix_secs: unix_now_secs(),
            url: url.to_string(),
            permanent: err.is_permanent(),
            message: err.reason().to_string(),
        };
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some(stored);
        }
    }

    /// push 1건 실패인데 **사유를 모르는** 경우(로컬 spool 디렉토리 오류 등 collector와 무관한
    /// 실패). 카운터만 올리고 마지막 사유는 건드리지 않는다 — 없는 원인을 지어내면 그 다음 진단이
    /// 통째로 엉뚱한 곳을 향한다.
    pub fn record_fail_without_cause(&self) {
        self.push_fail_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 현재 상태 스냅샷 — IPC 응답으로 그대로 나간다.
    pub fn snapshot(&self) -> aic_common::ExporterStatus {
        let last_ok = self.last_ok_unix.load(Ordering::Relaxed);
        aic_common::ExporterStatus {
            enabled: true, // 이 객체가 존재한다는 것 자체가 exporter 활성이라는 뜻이다.
            // 이 aicd는 값을 **안다** — 그래서 Some이다. `None`은 이 필드를 모르는 구버전만 낸다.
            agent_enabled: Some(self.agent_live.load(Ordering::Relaxed)),
            agent_configured: Some(self.agent_configured.load(Ordering::Relaxed)),
            endpoint: self.endpoint.clone(),
            push_ok_total: self.push_ok_total.load(Ordering::Relaxed),
            push_fail_total: self.push_fail_total.load(Ordering::Relaxed),
            // 아직 한 번도 성공한 적 없으면 None — "10초 전 성공"과 "성공한 적 없음"은 전혀 다른
            // 상태라, 0초로 뭉개지 않는다.
            last_ok_secs_ago: (last_ok > 0).then(|| unix_now_secs().saturating_sub(last_ok)),
            spool_batches: self.spool.batch_count() as u64,
            // R3: SignalKind별로 쿼터/드랍 카운터가 나뉘었지만, chat status bar가 알고 싶은 건
            // "데이터가 실제로 유실됐는가" 하나이지 어느 kind에서 드랍됐는지가 아니다 — 셋을 합산.
            spool_dropped: [SignalKind::Metrics, SignalKind::Logs, SignalKind::AppLogs]
                .into_iter()
                .map(|k| self.spool.dropped_count(k))
                .sum(),
            // 합계와 달리 **사유**는 조치를 고르는 근거다: 쿼터는 상한/수집량, 나이 cap은 장기
            // 미도달, 영구 거부는 인증·스키마 문제다.
            spool_dropped_quota: self.spool.dropped_by_reason(DropReason::Quota),
            spool_dropped_age: self.spool.dropped_by_reason(DropReason::Age),
            spool_dropped_rejected: self.spool.dropped_by_reason(DropReason::Rejected),
            collector_dropped: self
                .drop_counters
                .get()
                .map(|c| c.by_collector_dropped.load(Ordering::Relaxed))
                .unwrap_or(0),
            last_failure: self.last_failure.lock().ok().and_then(|slot| {
                slot.as_ref().map(|f| aic_common::ExporterFailure {
                    secs_ago: unix_now_secs().saturating_sub(f.unix_secs),
                    url: f.url.clone(),
                    permanent: f.permanent,
                    message: f.message.clone(),
                })
            }),
        }
    }
}

/// agent exporter task의 **종료**를 반드시 반영하는 RAII 가드.
///
/// **이 가드는 켜지 않는다 — 끄기만 한다.** 켜는 건 부모가 구독 직후·spawn 전에 이미 했다
/// (`agent_live` 필드 doc 참고). 가드가 켜는 구조였을 때 두 가지가 잘못됐다:
/// 1. spawn~task 시작 사이가 **거짓 false**인 창이 되어, 멀쩡히 전달될 메모를 "유실"로 오보했다.
///    (aicd 기동 직후는 chat이 붙는 시점과 정확히 겹친다.)
/// 2. task가 즉시 죽어 Drop이 false를 쓴 **뒤에** 부모가 true를 쓰면 다시 래치될 수 있었다.
///
/// task 안에서 들고 있으면 정상 종료·에러 종료·panic(unwind) 어느 경로로 나가든 Drop이 실행되므로,
/// "떴다가 죽었는데 살아있다고 보고"하는 창이 없다.
///
/// **왜 `JoinHandle::is_finished()`가 아닌가**: health를 읽는 쪽(`GetExporterStatus` 핸들러)은
/// handle을 들고 있지 않다 — `ExporterHealth`만 `Arc`로 공유한다. 상태를 읽는 지점에서 확인할 수
/// 있어야 하므로, 생존을 health 자신에 새기는 가드가 맞다.
pub struct AgentLiveGuard {
    health: Arc<ExporterHealth>,
}

impl AgentLiveGuard {
    /// 가드를 만든다. **여기서 `true`로 켜지 않는다**(위 doc 참고) — 종료 시 끄는 책임만 진다.
    pub fn new(health: Arc<ExporterHealth>) -> Self {
        Self { health }
    }
}

impl Drop for AgentLiveGuard {
    fn drop(&mut self) {
        self.health.set_agent_live(false);
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> ExporterHealth {
        let dir = tempfile::tempdir().unwrap();
        let quotas = aic_common::SpoolQuotas {
            metrics: 1024 * 1024,
            logs: 1024 * 1024,
            app_logs: 1024 * 1024,
        };
        let spool = Arc::new(Spool::open(dir.path().to_path_buf(), quotas).unwrap());
        // tempdir이 drop되면 경로가 사라지지만, batch_count는 실패 시 0을 돌려주므로 테스트에
        // 지장이 없다. 카운터 동작만 검증한다.
        std::mem::forget(dir);
        ExporterHealth::new("http://localhost:4318".to_string(), spool)
    }

    #[test]
    fn fresh_health_has_never_succeeded() {
        let h = health();
        let s = h.snapshot();
        assert_eq!(s.push_ok_total, 0);
        assert_eq!(s.push_fail_total, 0);
        // 성공한 적 없음은 None — "방금 성공(0초 전)"과 구분되어야 한다.
        assert_eq!(s.last_ok_secs_ago, None);
    }

    #[test]
    fn agent_live_guard_only_clears_never_arms() {
        // **거짓 false 창 회귀 테스트**: 가드가 `true`까지 켜면, 부모가 spawn한 뒤 task가 실제로
        // 시작하기 전까지가 "살아있지 않다"고 거짓 보고되는 창이 된다 — 그 창에 `/record now`를
        // 치면 **멀쩡히 전달될 메모를 유실이라고 오보**한다(aicd 기동 직후 = chat이 붙는 시점).
        //
        // 그래서 켜기는 부모(구독 직후·spawn 전)의 책임이고, 가드는 **끄기만** 한다.
        let h = Arc::new(health());
        let g = AgentLiveGuard::new(h.clone());
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "가드가 스스로 켰다 — 켜기는 부모 몫이다(그래야 spawn 전에 켤 수 있다)"
        );
        drop(g);
    }

    #[test]
    fn agent_live_guard_clears_liveness_on_every_exit_including_panic() {
        // **단방향 래치 회귀 테스트**: "떴다"는 "살아있다"가 아니다. serve_agent가 endpoint 오류·
        // spool 실패·panic으로 죽으면 구독자는 사라지는데, agent_live가 켜진 채 남으면
        // `/record now`가 그 뒤로 영원히 "잘 기록됐다"(Delivered)고 조용한 성공을 보고한다.
        let h = Arc::new(health());
        assert_eq!(h.snapshot().agent_enabled, Some(false), "초기값은 미기동");

        // 부모가 구독 직후 켠다(aicd_main이 spawn 전에 하는 일).
        h.set_agent_live(true);

        // 정상 종료: task 안의 가드가 scope를 벗어나면 꺼진다.
        {
            let _live = AgentLiveGuard::new(h.clone());
            assert_eq!(
                h.snapshot().agent_enabled,
                Some(true),
                "task가 도는 동안은 켜져 있어야"
            );
        }
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "task가 끝났는데 살아있다고 보고한다(단방향 래치)"
        );

        // panic 경로: unwind에서도 Drop이 돌아 꺼져야 한다(exporter task의 panic이 정확히 이 경우다).
        h.set_agent_live(true);
        let h2 = h.clone();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _live = AgentLiveGuard::new(h2);
            panic!("exporter task가 죽었다");
        }));
        assert!(res.is_err(), "panic이 나야 하는 테스트");
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "panic으로 죽었는데 살아있다고 보고한다"
        );
    }

    #[test]
    fn configured_and_live_are_independent_axes() {
        // "설정이 꺼짐"과 "설정은 켰는데 뜨지 못함"은 사용자가 할 일이 다르다(전자는 설정을 켜고,
        // 후자는 aicd 로그를 본다). 두 축을 따로 실어야 클라이언트가 구분해 안내할 수 있다.
        let h = health();
        assert_eq!(h.snapshot().agent_configured, Some(false));

        h.set_agent_configured(true);
        let s = h.snapshot();
        assert_eq!(s.agent_configured, Some(true), "설정은 켜져 있다");
        assert_eq!(s.agent_enabled, Some(false), "그런데 아직 떠 있지 않다");
    }

    #[test]
    fn agent_liveness_is_reported_and_defaults_to_not_live() {
        // chat `/record now <메모>`가 "이 메모가 서버에 남는가"를 판단하는 유일한 근거다.
        // 이 aicd는 값을 아는 버전이므로 **항상 Some**을 낸다 — None(모름)은 구버전만 낸다.
        let h = health();
        assert_eq!(
            h.snapshot().agent_enabled,
            Some(false),
            "task가 아직 안 떴으면 false여야 한다(사실과 어긋나지 않게)"
        );

        // agent exporter task가 실제로 뜨면 true.
        h.set_agent_live(true);
        assert_eq!(h.snapshot().agent_enabled, Some(true));

        // 부모 게이트(enabled)와는 별개의 축이다 — 이 객체가 존재하면 부모는 켜진 것이다.
        assert!(h.snapshot().enabled);
    }

    #[test]
    fn ok_and_fail_are_counted_separately() {
        let h = health();
        h.record_ok();
        h.record_ok();
        h.record_fail(
            "http://localhost:4318/v1/metrics",
            &PushError::Transient("collector 연결 거부".to_string()),
        );
        let s = h.snapshot();
        assert_eq!(s.push_ok_total, 2);
        assert_eq!(s.push_fail_total, 1);
        // 성공한 적이 있으므로 이제 Some이고, 방금이라 0초 근처다.
        assert!(s.last_ok_secs_ago.is_some_and(|secs| secs <= 1));
    }

    #[test]
    fn failure_carries_cause_so_the_operator_knows_what_to_fix() {
        // 이 테스트가 지키는 것: "19건 유실"만 보이고 원인은 aicd 로그를 열어야만 알 수 있던 상태로
        // 되돌아가지 않는 것. 사유·URL·영구 여부가 상태에 함께 실려야 조치를 고를 수 있다.
        let h = health();
        assert_eq!(h.snapshot().last_failure, None, "실패 전에는 사유가 없다");

        h.record_fail(
            "http://collector:4318/v1/logs",
            &PushError::Permanent("collector가 401 Unauthorized 응답".to_string()),
        );

        let f = h.snapshot().last_failure.expect("사유가 실려야 한다");
        assert_eq!(
            f.url, "http://collector:4318/v1/logs",
            "어느 신호가 막혔는지"
        );
        assert!(
            f.permanent,
            "4xx는 기다려도 낫지 않는다 — 설정을 고쳐야 한다"
        );
        assert!(f.message.contains("401"), "원인: {}", f.message);
        assert!(
            !f.message.contains("영구 실패"),
            "분류는 permanent 필드가 들고, message는 원인만 담는다: {}",
            f.message
        );
        assert_eq!(h.snapshot().push_fail_total, 1);
    }

    #[test]
    fn rejection_records_cause_without_counting_a_push_failure() {
        // 영구 거부는 **도달한** 요청이라 push 실패가 아니다(backoff도 걸지 않는다). 그래도 배치는
        // 사라졌으므로 사유는 남아야 한다 — 이게 없으면 app log가 통째로 증발한 이유를 어디서도
        // 볼 수 없다.
        let h = health();
        h.record_rejection(
            "http://collector:4318/v1/logs",
            &PushError::Permanent("collector가 413 Payload Too Large 응답".to_string()),
        );
        let s = h.snapshot();
        assert_eq!(s.push_fail_total, 0, "도달했으므로 실패 카운터는 그대로");
        assert!(s.last_failure.is_some_and(|f| f.message.contains("413")));
    }

    #[test]
    fn unknown_cause_failure_does_not_invent_one() {
        // 로컬 spool 오류처럼 collector와 무관한 실패에 그럴듯한 사유를 지어내면, 다음 진단이
        // 통째로 엉뚱한 곳(수신 서버)을 향한다.
        let h = health();
        h.record_fail_without_cause();
        let s = h.snapshot();
        assert_eq!(s.push_fail_total, 1);
        assert_eq!(s.last_failure, None, "모르는 원인을 지어내지 않는다");
    }

    #[test]
    fn collector_dropped_is_zero_until_counters_are_attached() {
        // 배선되지 않았으면 0으로 보고한다 — "0건 폐기"와 "모름"을 구분할 방법이 없으므로,
        // 적어도 지어내지는 않는다(배선은 aicd_main이 기동 시 1회 한다).
        let h = health();
        assert_eq!(h.snapshot().collector_dropped, 0);

        let counters = Arc::new(DropCounters::new());
        counters
            .by_collector_dropped
            .fetch_add(7, Ordering::Relaxed);
        h.attach_drop_counters(counters);
        assert_eq!(h.snapshot().collector_dropped, 7);
    }

    #[test]
    fn endpoint_is_carried_for_display() {
        let h = health();
        assert_eq!(h.snapshot().endpoint, "http://localhost:4318");
        assert!(h.snapshot().enabled);
    }
}
