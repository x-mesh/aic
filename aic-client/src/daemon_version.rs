//! 실행 중인 데몬과 디스크의 binary 사이 버전 skew 판정.
//!
//! `make install`과 `aic update`는 디스크의 binary만 바꾼다. 이미 떠 있는 `aicd`는
//! 자기 메모리의 옛 코드로 계속 도므로, 재시작 전까지는 새 기능(예: OTLP exporter)이
//! config에 켜져 있어도 동작하지 않는다. 경로가 같아 `stat`으로는 구분되지 않고,
//! 두 빌드의 semver가 같을 수도 있어(미출시 develop 빌드) `--version` 비교만으로도
//! 부족하다 — 그래서 실행 중인 프로세스에 `GetVersion`으로 직접 묻고, 여기서
//! 그 답을 이 CLI 자신의 빌드와 대조한다.

use aic_common::DaemonVersion;

/// 이 `aic` binary의 빌드 identity. 데몬 쪽 `env!` 3종과 같은 build.rs가 주입한다.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CLI_COMMIT: &str = env!("AIC_BUILD_COMMIT");
pub const CLI_BUILD_INFO: &str = env!("AIC_BUILD_INFO");

/// 실행 중인 데몬이 이 CLI와 같은 빌드인지.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skew {
    /// 같은 빌드 — 재시작할 이유가 없다.
    Current,
    /// 다른 빌드가 돌고 있다. 재시작하면 디스크의 새 binary로 교체된다.
    Stale,
    /// `GetVersion` 자체를 모르는 데몬 — 이 요청보다 오래된 빌드다. 버전을 물을 수
    /// 없다는 사실이 곧 구버전이라는 증거이므로 [`Skew::Stale`]과 같이 다루되,
    /// 표시할 버전 문자열이 없다는 점만 다르다.
    Legacy,
}

impl Skew {
    /// 재시작이 필요한가. `Stale`과 `Legacy` 모두 해당한다.
    pub fn needs_restart(self) -> bool {
        matches!(self, Skew::Stale | Skew::Legacy)
    }
}

/// 데몬의 응답을 이 CLI의 빌드와 대조한다.
///
/// `running`이 `None`이면 데몬이 `GetVersion`을 모른다는 뜻 → [`Skew::Legacy`].
///
/// commit이 판정의 1차 기준이다 — 미출시 develop 빌드는 semver가 같은 채로 코드만
/// 다를 수 있어서다(실제로 0.27.0 두 빌드가 그랬다). 다만 git 밖 빌드(릴리스
/// tarball, crates.io)는 commit이 빈 문자열이라, 어느 한쪽이라도 비어 있으면
/// semver로만 판정한다 — 없는 정보로 "다르다"고 단정하지 않는다.
pub fn classify(running: Option<&DaemonVersion>) -> Skew {
    let Some(running) = running else {
        return Skew::Legacy;
    };
    if running.version != CLI_VERSION {
        return Skew::Stale;
    }
    if !running.commit.is_empty() && !CLI_COMMIT.is_empty() && running.commit != CLI_COMMIT {
        return Skew::Stale;
    }
    Skew::Current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(version: &str, commit: &str) -> DaemonVersion {
        DaemonVersion {
            version: version.to_string(),
            commit: commit.to_string(),
            build_info: String::new(),
        }
    }

    #[test]
    fn same_version_and_commit_is_current() {
        let running = v(CLI_VERSION, CLI_COMMIT);
        assert_eq!(classify(Some(&running)), Skew::Current);
    }

    #[test]
    fn different_version_is_stale() {
        let running = v("0.1.0", CLI_COMMIT);
        assert_eq!(classify(Some(&running)), Skew::Stale);
    }

    #[test]
    fn same_version_different_commit_is_stale() {
        // 미출시 develop 빌드 — semver는 같고 commit만 다르다. 이 케이스를 놓치면
        // exporter가 없는 구 aicd가 조용히 계속 도는 실제 사고가 재현된다.
        let running = v(CLI_VERSION, "1cbb929");
        assert_eq!(classify(Some(&running)), Skew::Stale);
        assert!(classify(Some(&running)).needs_restart());
    }

    #[test]
    fn empty_commit_falls_back_to_semver_only() {
        // 릴리스 tarball 빌드는 commit이 없다 — semver가 같으면 같은 빌드로 본다.
        let running = v(CLI_VERSION, "");
        assert_eq!(classify(Some(&running)), Skew::Current);
    }

    #[test]
    fn no_version_response_is_legacy() {
        assert_eq!(classify(None), Skew::Legacy);
        assert!(classify(None).needs_restart());
    }

    #[test]
    fn current_does_not_need_restart() {
        assert!(!Skew::Current.needs_restart());
    }
}
