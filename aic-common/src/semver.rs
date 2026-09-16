//! 버전 비교. `aic update`와 aicd의 셀프업데이트가 같은 판정을 쓰도록 공유한다.
//!
//! 두 곳이 각자 비교하면 CLI는 "이미 최신"이라 하고 데몬은 계속 내려받는 식으로
//! 갈릴 수 있다. 판정이 한 벌이어야 한다.

/// `a`가 `b`보다 낮으면 -1, 같으면 0, 높으면 1.
///
/// `v` prefix와 `-rc.1`/`+build` suffix는 **버려지고** major/minor/patch만 본다.
/// 따라서 `0.41.5-rc.1`과 `0.41.5`는 같다고 판정된다 — semver 규칙과 다르다.
/// 릴리스 자산이 세 자리 tag으로만 올라가므로 지금은 문제가 되지 않지만,
/// prerelease를 실제로 배포하게 되면 여기부터 고쳐야 한다.
///
/// 파싱되지 않는 자리는 "더 낮은 것"으로 취급한다 — 알 수 없는 버전을 최신으로
/// 오인해 업데이트를 건너뛰는 쪽보다, 한 번 더 받는 쪽이 안전하다.
pub fn compare(a: &str, b: &str) -> i32 {
    let (ax, a_dirty) = parse(a);
    let (bx, b_dirty) = parse(b);
    for (av, bv) in ax.iter().zip(bx.iter()) {
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }
    match (a_dirty, b_dirty) {
        (true, false) => -1,
        (false, true) => 1,
        _ => 0,
    }
}

fn parse(v: &str) -> ([u32; 3], bool) {
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = match v.find(['-', '+']) {
        Some(i) => &v[..i],
        None => v,
    };
    let mut out = [0u32; 3];
    let mut dirty = false;
    let parts: Vec<&str> = v.split('.').collect();
    for (i, slot) in out.iter_mut().enumerate() {
        match parts.get(i) {
            None => dirty = true,
            Some(s) => match s.parse::<u32>() {
                Ok(n) => *slot = n,
                Err(_) => dirty = true,
            },
        }
    }
    (out, dirty)
}

#[cfg(test)]
mod tests {
    use super::compare;

    #[test]
    fn ordering_ignores_prefix_and_suffix() {
        assert_eq!(compare("0.41.5", "0.41.5"), 0);
        assert_eq!(compare("v0.41.5", "0.41.5"), 0);
        assert_eq!(compare("0.41.4", "0.41.5"), -1);
        assert_eq!(compare("0.42.0", "0.41.5"), 1);
        assert_eq!(compare("1.0.0", "0.99.99"), 1);
    }

    #[test]
    fn a_prerelease_suffix_is_dropped_not_ordered() {
        // semver라면 rc가 낮지만 이 비교는 suffix를 버린다. 셀프업데이트가
        // "같음 → 아무것도 안 함"으로 읽는 자리이므로 명시해 둔다: rc를 쓰는
        // 호스트는 같은 세 자리 릴리스로 자동 이동하지 않는다.
        assert_eq!(compare("0.41.5-rc.1", "0.41.5"), 0);
        assert_eq!(compare("0.41.5+build.7", "0.41.5"), 0);
    }

    #[test]
    fn an_unparseable_version_sorts_low() {
        // "최신인지 모르겠으면 낮게 본다" — 알 수 없는 문자열을 최신으로 읽어
        // 업데이트를 건너뛰는 것보다, 한 번 더 받는 쪽이 낫다.
        assert_eq!(compare("garbage", "0.41.5"), -1);
        assert_eq!(compare("0.41", "0.41.0"), -1);
    }
}
