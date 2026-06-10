//! `/local` 내장 sysinfo probe 목록.
//!
//! 각 probe는 **shell chain 없이** 단일 bounded Safe 명령이다(필요 시 `| head`로만 제한).
//! 실행은 `run_command::execute_with_corr` 프리미티브를 그대로 재사용해 timeout/cap/
//! redaction/audit/correlation을 동일하게 적용한다. env/curl/ping/dig/kube/logs/
//! systemctl 등은 의도적으로 제외(읽기 전용 로컬 스냅샷만). docker probe는 설치 호스트에서만
//! 덧붙는다(미설치 노이즈 0 — `/diagnose`와 동일한 `docker_available` 게이팅).

/// `/local`이 보여줄 기본 섹션 이름(자동완성·필터에도 사용).
pub(crate) const LOCAL_SECTIONS: &[&str] = &[
    "date", "host", "os", "uptime", "disk", "memory", "fd", "ip", "route", "ports",
];

/// docker 설치 호스트에서 기본 섹션 뒤에 덧붙는 docker 섹션(상태→리소스→디스크 순).
pub(crate) const LOCAL_DOCKER_SECTIONS: &[&str] = &["docker_ps", "docker_stats", "docker_df"];

/// docker 가용 여부에 따른 전체 섹션 이름 목록. 순수 함수(테스트 가능).
pub(crate) fn sections_with(docker: bool) -> Vec<&'static str> {
    let mut names = LOCAL_SECTIONS.to_vec();
    if docker {
        names.extend_from_slice(LOCAL_DOCKER_SECTIONS);
    }
    names
}

/// 현재 호스트에서 사용 가능한 섹션 이름 목록(자동완성·오류 안내 공용).
pub(crate) fn available_sections() -> Vec<&'static str> {
    sections_with(super::diagnose::docker_available())
}

/// OS에 맞는 (섹션, 명령) 목록. 각 명령은 하드코딩된 bounded Safe 명령.
pub(crate) fn local_probes() -> Vec<(&'static str, String)> {
    local_probes_with(super::diagnose::docker_available())
}

/// docker 가용성 주입 버전. 순수 함수(테스트 가능). 명령은 Probe Catalog(`agent::probes`) 단일 출처.
pub(crate) fn local_probes_with(docker: bool) -> Vec<(&'static str, String)> {
    super::probes::resolve_ids(&sections_with(docker))
}

/// 섹션 이름들로 필터(빈 목록이면 전체). 대소문자 무시, 결과는 요청 순서(중복 제거).
/// 알 수 없는 섹션이 하나라도 있으면 `Err(그 목록)` — 일부만 조용히 실행하지 않는다(결정적).
pub(crate) fn probes_for(
    sections: &[String],
) -> Result<Vec<(&'static str, String)>, Vec<String>> {
    probes_for_with(sections, super::diagnose::docker_available())
}

/// `probes_for`의 docker 가용성 주입 버전. 순수 함수(테스트 가능).
pub(crate) fn probes_for_with(
    sections: &[String],
    docker: bool,
) -> Result<Vec<(&'static str, String)>, Vec<String>> {
    let all = local_probes_with(docker);
    if sections.is_empty() {
        return Ok(all);
    }
    let mut unknown = Vec::new();
    let mut picked: Vec<(&'static str, String)> = Vec::new();
    for want in sections {
        let want_lc = want.to_lowercase();
        match all.iter().find(|(name, _)| *name == want_lc) {
            Some(p) => {
                if !picked.iter().any(|(name, _)| *name == p.0) {
                    picked.push(p.clone());
                }
            }
            None => unknown.push(want.clone()),
        }
    }
    if unknown.is_empty() {
        Ok(picked)
    } else {
        Err(unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk_guard::{classify, RiskLevel};

    #[test]
    fn every_probe_is_safe_and_bounded() {
        // docker 포함 superset 기준으로 전수 검증.
        for (section, cmd) in local_probes_with(true) {
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
        let names: Vec<&str> = local_probes_with(false).iter().map(|(n, _)| *n).collect();
        assert_eq!(names, LOCAL_SECTIONS);
        // docker 가용이면 기본 섹션 뒤에 docker 섹션이 그대로 덧붙는다.
        let with_docker: Vec<&str> = local_probes_with(true).iter().map(|(n, _)| *n).collect();
        let mut expect = LOCAL_SECTIONS.to_vec();
        expect.extend_from_slice(LOCAL_DOCKER_SECTIONS);
        assert_eq!(with_docker, expect);
    }

    #[test]
    fn probes_for_filters_by_sections() {
        // 단일 섹션.
        let only = probes_for_with(&["disk".to_string()], false).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].0, "disk");
        // 다중 섹션 — 요청 순서 유지 + 대소문자 무시 + 중복 제거.
        let multi = probes_for_with(
            &["memory".to_string(), "DISK".to_string(), "memory".to_string()],
            false,
        )
        .unwrap();
        let names: Vec<&str> = multi.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["memory", "disk"]);
        // 알 수 없는 섹션이 섞이면 전체 거부(Err에 해당 이름만).
        assert_eq!(
            probes_for_with(&["disk".to_string(), "bogus".to_string()], false).unwrap_err(),
            vec!["bogus".to_string()]
        );
        // docker 미설치면 docker 섹션도 unknown, 설치면 유효.
        assert!(probes_for_with(&["docker_ps".to_string()], false).is_err());
        assert_eq!(
            probes_for_with(&["docker_ps".to_string()], true).unwrap()[0].0,
            "docker_ps"
        );
        // 빈 목록 → 전체.
        assert_eq!(probes_for_with(&[], false).unwrap().len(), LOCAL_SECTIONS.len());
    }
}
