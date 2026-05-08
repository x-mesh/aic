//! Build-time assertion: 정확히 하나의 phase-3_N feature 만 활성이어야 한다.
//!
//! Central_Store_Flag와 Phase-별 기본값(R8)은 빌드 시점에 결정된다.
//! 하나 이하거나 둘 이상이면 빌드를 중단해 런타임에서 `current_phase()`가
//! 애매해지는 것을 막는다.
//!
//! 기본값은 `phase-3_1` (aic-common Cargo.toml의 `default` feature set).

fn main() {
    let phases = [
        ("CARGO_FEATURE_PHASE_3_1", "phase-3_1"),
        ("CARGO_FEATURE_PHASE_3_2", "phase-3_2"),
        ("CARGO_FEATURE_PHASE_3_3", "phase-3_3"),
        ("CARGO_FEATURE_PHASE_3_4", "phase-3_4"),
        ("CARGO_FEATURE_PHASE_3_5", "phase-3_5"),
    ];

    let active: Vec<&str> = phases
        .iter()
        .filter(|(env, _)| std::env::var(env).is_ok())
        .map(|(_, name)| *name)
        .collect();

    if active.is_empty() {
        panic!(
            "aic-common: 활성화된 phase-3_N feature가 없습니다. \
             `--features phase-3_1` (또는 다른 하나)을 지정하세요."
        );
    }
    if active.len() > 1 {
        panic!(
            "aic-common: 정확히 하나의 phase-3_N feature만 활성이어야 합니다. \
             지금 활성: {:?}. `--no-default-features`와 함께 단일 phase를 지정하세요.",
            active
        );
    }

    // build.rs가 Cargo.toml 변경 외에 rerun될 필요가 없음을 명시.
    println!("cargo:rerun-if-changed=build.rs");
}
