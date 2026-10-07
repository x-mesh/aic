//! Docker 컨테이너 메타데이터(`<containers_dir>/<id>/config.v2.json`) 읽기.
//!
//! aicd의 컨테이너 로그 수집과 `aic workload discover`가 같은 파일에서 이름과 이미지를 읽는다.

use std::path::Path;

/// docker의 기본 컨테이너 디렉토리. 컨테이너마다 `<id>/` 하위 디렉토리가 있다.
pub const DOCKER_CONTAINERS_DIR: &str = "/var/lib/docker/containers";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockerContainerMeta {
    /// `Name` 필드에서 앞 `/`를 뗀 값. 비어 있으면 `None`.
    pub name: Option<String>,
    /// `Config.Image`, 없으면 top-level `Image`.
    pub image: Option<String>,
}

/// `<container_dir>/config.v2.json`을 읽는다. 파일이 없거나 읽을 수 없거나 JSON이 아니면 두 값
/// 모두 `None`이다.
pub fn read_docker_container_meta(container_dir: &Path) -> DockerContainerMeta {
    let Ok(content) = std::fs::read_to_string(container_dir.join("config.v2.json")) else {
        return DockerContainerMeta::default();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return DockerContainerMeta::default();
    };
    let name = value
        .get("Name")
        .and_then(|n| n.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty());
    let image = value
        .get("Config")
        .and_then(|c| c.get("Image"))
        .and_then(|i| i.as_str())
        .or_else(|| value.get("Image").and_then(|i| i.as_str()))
        .map(|s| s.to_string());
    DockerContainerMeta { name, image }
}
