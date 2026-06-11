//! `--version` 빌드 메타데이터(commit/branch/dirty/빌드 시각)를 rustc-env로 주입한다.
//!
//! - `AIC_BUILD_INFO`: `0.18.1 (b652397* develop, 2026-06-11T00:12:34Z)` — clap `version`용 완성 문자열.
//! - `AIC_BUILD_COMMIT`: `b652397*` — 배너 등 짧은 표기용(`*`=dirty, git 밖 빌드면 빈 문자열).
//! - `AIC_BUILD_BRANCH`: `develop` — 배너용 브랜치(detached HEAD/비-git 빌드면 빈 문자열).
//!
//! git 밖 빌드(릴리스 tarball, crates.io)는 git 메타 없이 버전+빌드 시각만 남는다(빌드 실패 없음).
//! aic-client/build.rs와 동일한 사본 — 각 바이너리가 자기 재빌드 시점의 정보를 갖도록 crate마다 둔다.

use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn main() {
    // 소스/커밋/브랜치가 바뀌면 rerun → dirty 표시와 빌드 시각이 재빌드 기준으로 갱신된다.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(git_dir) = run("git", &["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/refs");
        println!("cargo:rerun-if-changed={git_dir}/packed-refs");
    }

    let hash = run("git", &["rev-parse", "--short", "HEAD"]);
    // detached HEAD(릴리스 tag 빌드 등)는 "HEAD"로 나온다 — 그대로 표시.
    let branch = run("git", &["rev-parse", "--abbrev-ref", "HEAD"]);
    // porcelain 출력이 비어있지 않으면 워킹트리에 미커밋 변경이 있다(dirty).
    let dirty = run("git", &["status", "--porcelain"]).is_some();
    let built = run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_default();

    let commit = hash
        .as_ref()
        .map(|h| format!("{h}{}", if dirty { "*" } else { "" }))
        .unwrap_or_default();

    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut meta: Vec<String> = Vec::new();
    if !commit.is_empty() {
        meta.push(match &branch {
            Some(b) => format!("{commit} {b}"),
            None => commit.clone(),
        });
    }
    if !built.is_empty() {
        meta.push(built);
    }
    let info = if meta.is_empty() {
        pkg
    } else {
        format!("{pkg} ({})", meta.join(", "))
    };
    println!("cargo:rustc-env=AIC_BUILD_INFO={info}");
    println!("cargo:rustc-env=AIC_BUILD_COMMIT={commit}");
    // detached HEAD("HEAD")는 배너에선 의미가 없어 비워둔다(--version 문자열에는 그대로 남음).
    let branch_display = branch.as_deref().filter(|b| *b != "HEAD").unwrap_or("");
    println!("cargo:rustc-env=AIC_BUILD_BRANCH={branch_display}");
}
