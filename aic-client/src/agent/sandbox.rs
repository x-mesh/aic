//! cwd 기반 파일 접근 샌드박스.
//!
//! root는 세션 시작 시점 cwd를 `canonicalize`한 절대 경로로 고정한다(불변).
//! 모든 도구 경로는 [`Sandbox::resolve`]를 통과해야 하며, 정규화 후 root 하위가
//! 아니면 거부한다. symlink·`..`·절대경로를 통한 탈출은 `canonicalize`가 실제
//! 경로를 풀어낸 뒤 `starts_with`로 검사해 차단한다.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::gitignore::Gitignore;
use super::tools::ToolError;

#[derive(Clone)]
pub struct Sandbox {
    root: PathBuf,
    /// 루트의 .gitignore/.git/info/exclude 기반 매처. Arc로 clone 비용 최소화.
    gitignore: Arc<Gitignore>,
}

impl Sandbox {
    /// 현재 cwd를 root로 하는 샌드박스. cwd 확인/정규화 실패 시 에러.
    pub fn from_cwd() -> Result<Self, ToolError> {
        let cwd =
            std::env::current_dir().map_err(|e| ToolError::new(format!("cwd 확인 실패: {e}")))?;
        Self::new(cwd)
    }

    /// 임의 root로 샌드박스를 만든다(테스트·명시적 root용). root를 canonicalize하고
    /// 해당 root의 gitignore 규칙을 로드한다.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ToolError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|e| ToolError::new(format!("sandbox root 확인 실패: {e}")))?;
        let gitignore = Arc::new(Gitignore::load(&root));
        Ok(Self { root, gitignore })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 절대 경로를 root 기준 slash 구분 상대경로로 변환한다(root 밖이면 None).
    pub fn relative(&self, abs: &Path) -> Option<String> {
        abs.strip_prefix(&self.root)
            .ok()
            .map(|r| r.to_string_lossy().replace('\\', "/"))
    }

    /// 절대 경로가 gitignore 규칙에 의해 제외되는지 판정한다.
    /// root 자체이거나 root 밖이면 false(샌드박스 검사는 resolve가 담당).
    pub fn is_ignored(&self, abs: &Path, is_dir: bool) -> bool {
        match self.relative(abs) {
            Some(rel) if !rel.is_empty() => self.gitignore.is_ignored(&rel, is_dir),
            _ => false,
        }
    }

    /// 입력 경로를 root 기준으로 결합·정규화한 뒤 root 하위인지 검증한다.
    ///
    /// 존재하지 않는 경로는 거부한다(읽기 전용 Phase 1 — 쓰기는 Phase 2).
    /// symlink는 `canonicalize`가 실제 대상으로 해소하므로, 링크가 root 밖을
    /// 가리키면 `starts_with` 검사에서 거부된다.
    pub fn resolve(&self, input: &str) -> Result<PathBuf, ToolError> {
        if input.contains('\0') {
            return Err(ToolError::new("경로에 NUL 바이트가 포함되어 거부"));
        }
        let raw = Path::new(input);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.root.join(raw)
        };
        let canonical = joined
            .canonicalize()
            .map_err(|e| ToolError::new(format!("경로 확인 실패: {input} ({e})")))?;
        if !canonical.starts_with(&self.root) {
            return Err(ToolError::new(format!("샌드박스 밖 경로 거부: {input}")));
        }
        Ok(canonical)
    }

    /// 쓰기용 경로 해소(Phase 2). `resolve`와 달리 **존재하지 않는 새 파일 경로**도
    /// 허용한다. 입력 경로에서 존재하는 가장 가까운 조상을 `canonicalize`해 root 하위인지
    /// 검증한 뒤, 그 canonical 조상에 나머지(아직 없는) 컴포넌트를 합쳐 최종 절대 경로를
    /// 만든다(symlink·`..`·절대경로 탈출은 조상 canonicalize가 실제 경로를 풀어 차단).
    ///
    /// 부모 디렉터리가 아직 없어도 허용한다 — 호출부(`write_file`)가 `create_dir_all`로
    /// sandbox 내에 생성한다. 입력 경로 컴포넌트에 `..`이 포함되면 거부한다(부분 정규화로
    /// 인한 탈출 차단). 마지막 컴포넌트가 정상 파일명이 아니면 거부한다.
    pub fn resolve_for_write(&self, input: &str) -> Result<PathBuf, ToolError> {
        use std::path::Component;
        if input.contains('\0') {
            return Err(ToolError::new("경로에 NUL 바이트가 포함되어 거부"));
        }
        let raw = Path::new(input);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.root.join(raw)
        };
        // `..`은 부분(아직 미존재) 구간에서 탈출에 악용될 수 있으므로 입력에 있으면 거부한다.
        // (존재 구간은 canonicalize가 풀지만, 미존재 구간은 풀리지 않으므로 명시 거부.)
        if joined
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(ToolError::new(format!("쓰기 경로에 '..' 사용 거부: {input}")));
        }

        // 존재하는 가장 가까운 조상을 canonicalize해 경계를 검증하고, 나머지(미존재)
        // 컴포넌트를 그 위에 누적한다.
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        let mut probe = joined.as_path();
        let canonical_base = loop {
            match probe.canonicalize() {
                Ok(c) => break c,
                Err(_) => {
                    let name = probe.file_name().ok_or_else(|| {
                        ToolError::new(format!("쓰기 대상 경로를 확인할 수 없음: {input}"))
                    })?;
                    tail.push(name.to_os_string());
                    probe = probe.parent().ok_or_else(|| {
                        ToolError::new(format!("경로 확인 실패: {input}"))
                    })?;
                }
            }
        };
        if !canonical_base.starts_with(&self.root) {
            return Err(ToolError::new(format!("샌드박스 밖 경로 거부: {input}")));
        }
        // tail은 leaf→root 순으로 쌓였으므로 역순으로 붙인다.
        let mut target = canonical_base;
        for comp in tail.into_iter().rev() {
            target.push(comp);
        }
        if target.file_name().is_none() {
            return Err(ToolError::new(format!("쓰기 대상 파일명을 확인할 수 없음: {input}")));
        }
        Ok(target)
    }

    /// 이미 확보한 절대 경로가 root 하위인지 검사한다(walk 결과 필터용).
    /// 정규화에 실패하면(깨진 symlink 등) false.
    pub fn contains(&self, path: &Path) -> bool {
        path.canonicalize()
            .map(|c| c.starts_with(&self.root))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_sandbox() -> (tempfile::TempDir, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        // macOS의 /var → /private/var symlink 때문에 root도 canonicalize 기준으로 만든다.
        let sb = Sandbox::new(dir.path()).unwrap();
        (dir, sb)
    }

    #[test]
    fn resolve_normal_subfile_ok() {
        let (dir, sb) = tmp_sandbox();
        let f = dir.path().join("a.txt");
        fs::write(&f, "x").unwrap();
        let resolved = sb.resolve("a.txt").unwrap();
        assert!(resolved.starts_with(sb.root()));
        assert!(resolved.ends_with("a.txt"));
    }

    #[test]
    fn resolve_parent_escape_rejected() {
        let (dir, sb) = tmp_sandbox();
        // 상위 디렉터리에 파일을 만들어도 `..` 탈출은 거부되어야 한다.
        let parent_file = dir.path().parent().unwrap().join("escape_target.txt");
        let _ = fs::write(&parent_file, "secret");
        let err = sb.resolve("../escape_target.txt").unwrap_err();
        assert!(err.message.contains("샌드박스 밖") || err.message.contains("경로 확인 실패"));
        let _ = fs::remove_file(parent_file);
    }

    #[test]
    fn resolve_absolute_outside_rejected() {
        let (_dir, sb) = tmp_sandbox();
        let err = sb.resolve("/etc/hosts").unwrap_err();
        assert!(err.message.contains("샌드박스 밖") || err.message.contains("경로 확인 실패"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_symlink_escape_rejected() {
        use std::os::unix::fs::symlink;
        let (dir, sb) = tmp_sandbox();
        // sandbox 안에 root 밖(/etc)을 가리키는 symlink를 만든다.
        let link = dir.path().join("evil");
        symlink("/etc", &link).unwrap();
        // canonicalize가 /etc로 해소 → root 하위 아님 → 거부.
        let err = sb.resolve("evil/hosts").unwrap_err();
        assert!(err.message.contains("샌드박스 밖") || err.message.contains("경로 확인 실패"));
    }

    #[test]
    fn resolve_nonexistent_rejected() {
        let (_dir, sb) = tmp_sandbox();
        assert!(sb.resolve("does-not-exist.txt").is_err());
    }

    #[test]
    fn resolve_for_write_new_file_ok() {
        let (_dir, sb) = tmp_sandbox();
        // 존재하지 않는 새 파일도 부모(root) 검증을 통과해야 한다.
        let p = sb.resolve_for_write("new.txt").unwrap();
        assert!(p.starts_with(sb.root()));
        assert!(p.ends_with("new.txt"));
    }

    #[test]
    fn resolve_for_write_new_nested_file_ok() {
        let (_dir, sb) = tmp_sandbox();
        // 부모 디렉터리가 아직 없어도(중첩) 허용 — 호출부가 create_dir_all.
        let p = sb.resolve_for_write("a/b/c.txt").unwrap();
        assert!(p.starts_with(sb.root()));
        assert!(p.ends_with("c.txt"));
    }

    #[test]
    fn resolve_for_write_existing_file_ok() {
        let (dir, sb) = tmp_sandbox();
        let f = dir.path().join("exists.txt");
        fs::write(&f, "x").unwrap();
        let p = sb.resolve_for_write("exists.txt").unwrap();
        assert!(p.starts_with(sb.root()));
        assert!(p.ends_with("exists.txt"));
    }

    #[test]
    fn resolve_for_write_parent_escape_rejected() {
        let (_dir, sb) = tmp_sandbox();
        let err = sb.resolve_for_write("../escape.txt").unwrap_err();
        assert!(err.message.contains("'..'") || err.message.contains("샌드박스 밖"));
    }

    #[test]
    fn resolve_for_write_absolute_outside_rejected() {
        let (_dir, sb) = tmp_sandbox();
        let err = sb.resolve_for_write("/tmp/evil-aic-write.txt").unwrap_err();
        assert!(err.message.contains("샌드박스 밖") || err.message.contains("경로 확인 실패"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_for_write_symlink_escape_rejected() {
        use std::os::unix::fs::symlink;
        let (dir, sb) = tmp_sandbox();
        // sandbox 안에 root 밖(/tmp)을 가리키는 symlink dir를 만들고 그 안에 쓰기 시도.
        let link = dir.path().join("evil");
        symlink("/tmp", &link).unwrap();
        let err = sb.resolve_for_write("evil/pwned.txt").unwrap_err();
        assert!(err.message.contains("샌드박스 밖") || err.message.contains("경로 확인 실패"));
    }
}
