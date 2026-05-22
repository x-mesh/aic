//! `/local` 내장 sysinfo probe 목록.
//!
//! 각 probe는 **shell chain 없이** 단일 bounded Safe 명령이다(필요 시 `| head`로만 제한).
//! 실행은 `run_command::execute_with_corr` 프리미티브를 그대로 재사용해 timeout/cap/
//! redaction/audit/correlation을 동일하게 적용한다. env/curl/ping/dig/docker/kube/logs/
//! systemctl 등은 의도적으로 제외(읽기 전용 로컬 스냅샷만).

/// `/local`이 보여줄 섹션 이름(자동완성·필터에도 사용).
pub(crate) const LOCAL_SECTIONS: &[&str] = &[
    "date", "host", "os", "uptime", "disk", "memory", "ip", "route", "ports",
];

/// OS에 맞는 (섹션, 명령) 목록. 각 명령은 하드코딩된 bounded Safe 명령.
pub(crate) fn local_probes() -> Vec<(&'static str, String)> {
    // Probe Catalog(`agent::probes`)에서 LOCAL_SECTIONS 순서로 해석한다(명령은 catalog의 단일 출처).
    super::probes::resolve_ids(LOCAL_SECTIONS)
}

/// 섹션 이름으로 필터(없으면 전체). 대소문자 무시.
pub(crate) fn probes_for(section: Option<&str>) -> Vec<(&'static str, String)> {
    match section {
        None => local_probes(),
        Some(want) => {
            let want = want.to_lowercase();
            local_probes()
                .into_iter()
                .filter(|(name, _)| *name == want)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk_guard::{classify, RiskLevel};

    #[test]
    fn every_probe_is_safe_and_bounded() {
        for (section, cmd) in local_probes() {
            // shell chain/메타문자 금지(파이프 `|`만 허용).
            for bad in [';', '&', '$', '`', '>', '<', '\n'] {
                assert!(!cmd.contains(bad), "probe {section} has '{bad}': {cmd}");
            }
            // 각 probe는 risk_guard Safe(자동 실행 가능)여야 한다.
            assert_eq!(
                classify(&cmd).level,
                RiskLevel::Safe,
                "probe {section} not Safe: {cmd}"
            );
        }
    }

    #[test]
    fn sections_cover_local_sections_const() {
        let names: Vec<&str> = local_probes().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, LOCAL_SECTIONS);
    }

    #[test]
    fn probes_for_filters_by_section() {
        let only = probes_for(Some("disk"));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, "disk");
        // 알 수 없는 섹션 → 빈 목록.
        assert!(probes_for(Some("bogus")).is_empty());
        // None → 전체.
        assert_eq!(probes_for(None).len(), LOCAL_SECTIONS.len());
    }
}
