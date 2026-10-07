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
    /// `NetworkSettings.Ports`에서 호스트에 공개한 TCP 포트.
    pub published_tcp: Vec<PublishedPort>,
    /// `NetworkSettings.Networks.*.IPAddress`. host 네트워크면 비어 있다.
    pub network_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    pub container_port: u16,
    /// 빈 값이면 모든 주소에 공개했다는 뜻이다.
    pub host_ip: String,
    pub host_port: u16,
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
    let network = value.get("NetworkSettings");
    let published_tcp = network
        .and_then(|n| n.get("Ports"))
        .and_then(|p| p.as_object())
        .map(|ports| {
            ports
                .iter()
                .filter_map(|(key, bindings)| {
                    let container_port = key.strip_suffix("/tcp")?.parse().ok()?;
                    Some((container_port, bindings.as_array()?))
                })
                .flat_map(|(container_port, bindings)| {
                    bindings.iter().filter_map(move |binding| {
                        Some(PublishedPort {
                            container_port,
                            host_ip: binding.get("HostIp")?.as_str()?.to_string(),
                            host_port: binding.get("HostPort")?.as_str()?.parse().ok()?,
                        })
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let network_ips = network
        .and_then(|n| n.get("Networks"))
        .and_then(|n| n.as_object())
        .map(|networks| {
            networks
                .values()
                .filter_map(|network| network.get("IPAddress")?.as_str())
                .filter(|ip| !ip.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    DockerContainerMeta {
        name,
        image,
        published_tcp,
        network_ips,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_published_ports_and_network_addresses() {
        let dir = std::env::temp_dir().join(format!(
            "aic-docker-meta-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.v2.json"),
            r#"{"Name":"/db","Config":{"Image":"postgres:17","Env":["POSTGRES_PASSWORD=x"]},
               "NetworkSettings":{
                 "Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"15432"}],
                          "8080/tcp":null,"53/udp":[{"HostIp":"","HostPort":"53"}]},
                 "Networks":{"app":{"IPAddress":"172.19.0.2"},"none":{"IPAddress":""}}}}"#,
        )
        .unwrap();
        let meta = read_docker_container_meta(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(meta.name.as_deref(), Some("db"));
        assert_eq!(
            meta.published_tcp,
            vec![PublishedPort {
                container_port: 5432,
                host_ip: "127.0.0.1".into(),
                host_port: 15432,
            }]
        );
        assert_eq!(meta.network_ips, vec!["172.19.0.2".to_string()]);
    }
}
