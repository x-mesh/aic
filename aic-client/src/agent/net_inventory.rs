//! 연결/inventory JSON 스냅샷 (SRE t7: OTLP connections exporter가 주기 spawn하는 hidden CLI leaf).
//!
//! `aic snapshot inventory --json`(main.rs, hidden subcommand)이 호출하는 구현체다. **주의**:
//! 이 subcommand는 t7 작업 지시서가 가정한 `aic snapshot capture --json`과 다른 이름이다 —
//! 기존 `aic snapshot capture`는 opt-in 게이트(`AIC_SNAPSHOT_RECORD`)가 걸린 전체 redacted
//! markdown 스냅샷(디스크/프로세스/git status 등)을 영구 store에 append하는, 이 기능과는 무관한
//! 별개 기능이라 그대로 재사용하면 의미가 섞인다. 대신 machine-readable 전용 hidden leaf를 새로
//! 추가했다(사람이 직접 쓰는 명령이 아니라 `--help`에 노출하지 않는다).
//!
//! Linux는 `ss -tuna`, macOS는 `lsof -nP -iTCP -iUDP`로 LISTEN/ESTABLISHED 소켓을 조회한다.
//! 파싱 로직은 OS 무관 순수 함수([`parse_ss`]/[`parse_lsof`])로 분리해, 실제 프로세스를 spawn하지
//! 않고 고정 fixture 문자열로 두 포맷 모두 결정적으로 테스트한다(`capture()`/`run_os_probe()` 자체는
//! 실제 시스템 명령에 의존해 유닛 테스트 대상이 아니다 — 기존 `local_probes`류 패턴과 동일).
//!
//! **JSON wire contract**: 여기의 구조체 필드명은 `aic-server`의 `otlp_exporter::connections`
//! (`InventorySnapshot`/`HostMeta`/`RawConnection`)와 반드시 일치해야 한다(직접 타입 공유가 아니라
//! 프로세스 경계를 넘는 JSON 계약 — 필드명을 바꾸면 양쪽 다 갱신할 것).

use serde::Serialize;
use std::net::UdpSocket;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HostMeta {
    pub name: String,
    /// host_metrics(aic-server)의 host_id()와 동일 기법(`/etc/machine-id` 등) — 같은 물리 호스트면
    /// 동일 값이 나와 metrics/events/connections 세 signal을 상관지을 수 있다.
    pub id: String,
    pub ip: Option<String>,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConnectionInfo {
    /// `"tcp"` | `"udp"`.
    pub protocol: String,
    /// `"LISTEN"` | `"ESTABLISHED"` | `"UNCONN"` 등 — OS 소켓 상태 문자열을 그대로 옮긴다(값
    /// 자체를 정규화하지 않는다. 정규화가 필요해지면 exporter 쪽에서 매핑하는 게 낫다).
    pub state: String,
    pub local_addr: String,
    pub local_port: u16,
    pub peer_addr: Option<String>,
    pub peer_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InventorySnapshot {
    pub schema_version: u32,
    pub host: HostMeta,
    pub connections: Vec<ConnectionInfo>,
}

const SCHEMA_VERSION: u32 = 1;

/// 실제 캡처(OS 명령 spawn + 파싱). best-effort가 아니라 실패 시 그대로 `Err`를 전파한다 — 호출부
/// (`aic snapshot inventory --json`)는 exit code로 실패를 표면화하고, 주기 spawn하는 aicd
/// connections exporter는 이번 주기를 skip한다(store에 아무것도 남기지 않는 read-only 명령이라
/// 재시도해도 부작용 없음).
pub fn capture() -> anyhow::Result<InventorySnapshot> {
    let text = run_os_probe()?;
    let connections = if cfg!(target_os = "macos") {
        parse_lsof(&text)
    } else {
        parse_ss(&text)
    };
    let name = hostname();
    Ok(InventorySnapshot {
        schema_version: SCHEMA_VERSION,
        host: HostMeta {
            id: host_id(&name),
            name,
            ip: primary_ip(),
            os: std::env::consts::OS.to_string(),
        },
        connections,
    })
}

fn hostname() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string())
}

/// host_metrics(aic-server otlp_exporter)의 동일 이름 함수와 같은 기법 — Linux는 machine-id 파일,
/// 그 외는 hostname 폴백. 두 crate가 서로 의존하지 않아(aic-client는 aic-server에 의존하지 않고,
/// 반대도 마찬가지) 여기서 독립적으로 재구현한다(중복은 8줄 남짓이라 공유 모듈을 새로 파는 비용보다
/// 낮다).
fn host_id(fallback: &str) -> String {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let id = s.trim();
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }
    fallback.to_string()
}

/// 로컬 outbound 인터페이스 IP. UDP `connect`는 커널 라우팅 테이블 조회만 하고 실제 패킷을 보내지
/// 않는다 — 오프라인이어도 기본 라우트가 있으면 성공한다(sntp류 네트워크 질의가 아니다). 실패하면
/// `None`(host 메타는 best-effort — ip 하나로 전체 스냅샷을 실패시키지 않는다).
fn primary_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

#[cfg(target_os = "macos")]
fn run_os_probe() -> anyhow::Result<String> {
    let out = std::process::Command::new("lsof")
        .args(["-nP", "-iTCP", "-iUDP"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn run_os_probe() -> anyhow::Result<String> {
    let out = std::process::Command::new("ss").args(["-tuna"]).output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `host:port` 또는 `[ipv6]:port` 형태를 분리한다. `port`가 `*`거나 파싱 불가면 `None`(ss/lsof의
/// wildcard peer, 예: `0.0.0.0:*`를 "peer 없음"으로 표현하는 데 쓴다).
fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.parse().ok());
        }
    }
    match s.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().ok()),
        None => (s.to_string(), None),
    }
}

/// Linux `ss -tuna` 출력을 파싱한다. 컬럼: `Netid State Recv-Q Send-Q "Local Address:Port"
/// "Peer Address:Port"`(+선택적 Process). 헤더 줄(`Netid`로 시작)과 필드 부족 줄은 skip한다.
pub(crate) fn parse_ss(text: &str) -> Vec<ConnectionInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[0].eq_ignore_ascii_case("netid") {
            continue;
        }
        let protocol = fields[0].to_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }
        let state = fields[1].to_string();
        let (local_addr, local_port) = split_host_port(fields[4]);
        let (peer_addr, peer_port) = match split_host_port(fields[5]) {
            (addr, Some(port)) => (Some(addr), Some(port)),
            (_, None) => (None, None),
        };
        out.push(ConnectionInfo {
            protocol,
            state,
            local_addr,
            local_port: local_port.unwrap_or(0),
            peer_addr,
            peer_port,
        });
    }
    out
}

/// macOS `lsof -nP -iTCP -iUDP` 출력을 파싱한다. 컬럼 수가 USER/COMMAND 값에 따라 흔들릴 수 있어
/// 뒤에서부터 인덱싱한다: 마지막 필드가 `(STATE)`면 `[..., PROTO, NAME, (STATE)]`, 아니면(주로 UDP)
/// `[..., PROTO, NAME]`.
pub(crate) fn parse_lsof(text: &str) -> Vec<ConnectionInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0].eq_ignore_ascii_case("command") {
            continue;
        }
        let last = *fields.last().unwrap();
        let (state, name, proto) = if last.starts_with('(') && last.ends_with(')') {
            let name = fields[fields.len() - 2];
            let proto = fields[fields.len() - 3];
            (last.trim_matches(|c| c == '(' || c == ')').to_string(), name, proto)
        } else {
            let name = last;
            let proto = fields[fields.len() - 2];
            ("UNCONN".to_string(), name, proto)
        };
        let protocol = proto.to_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }
        let (local_part, peer_part) = match name.split_once("->") {
            Some((l, p)) => (l, Some(p)),
            None => (name, None),
        };
        let (local_addr, local_port) = split_host_port(local_part);
        let (peer_addr, peer_port) = match peer_part.map(split_host_port) {
            Some((addr, Some(port))) => (Some(addr), Some(port)),
            _ => (None, None),
        };
        out.push(ConnectionInfo {
            protocol,
            state,
            local_addr,
            local_port: local_port.unwrap_or(0),
            peer_addr,
            peer_port,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── split_host_port ──────────────────────────────────────────

    #[test]
    fn split_host_port_handles_ipv4_wildcard_and_ipv6() {
        assert_eq!(split_host_port("0.0.0.0:22"), ("0.0.0.0".to_string(), Some(22)));
        assert_eq!(split_host_port("0.0.0.0:*"), ("0.0.0.0".to_string(), None));
        assert_eq!(split_host_port("[::1]:22"), ("::1".to_string(), Some(22)));
        assert_eq!(split_host_port("[::]:*"), ("::".to_string(), None));
    }

    // ── parse_ss (Linux) ─────────────────────────────────────────

    const SS_FIXTURE: &str = "\
Netid  State      Recv-Q Send-Q     Local Address:Port      Peer Address:Port
udp    UNCONN     0      0               0.0.0.0:68              0.0.0.0:*
tcp    LISTEN     0      128             0.0.0.0:22               0.0.0.0:*
tcp    LISTEN     0      128                [::]:22                  [::]:*
tcp    ESTAB      0      0            192.168.1.5:22          192.168.1.10:54321
";

    #[test]
    fn parse_ss_skips_header_and_parses_all_rows() {
        let conns = parse_ss(SS_FIXTURE);
        assert_eq!(conns.len(), 4);
    }

    #[test]
    fn parse_ss_listen_has_no_peer() {
        let conns = parse_ss(SS_FIXTURE);
        let listen = conns.iter().find(|c| c.local_port == 22 && c.protocol == "tcp" && c.local_addr == "0.0.0.0").unwrap();
        assert_eq!(listen.state, "LISTEN");
        assert_eq!(listen.peer_addr, None);
        assert_eq!(listen.peer_port, None);
    }

    #[test]
    fn parse_ss_established_has_peer() {
        let conns = parse_ss(SS_FIXTURE);
        let estab = conns.iter().find(|c| c.state == "ESTAB").unwrap();
        assert_eq!(estab.local_addr, "192.168.1.5");
        assert_eq!(estab.local_port, 22);
        assert_eq!(estab.peer_addr.as_deref(), Some("192.168.1.10"));
        assert_eq!(estab.peer_port, Some(54321));
    }

    #[test]
    fn parse_ss_handles_ipv6_bracket_listen() {
        let conns = parse_ss(SS_FIXTURE);
        let v6 = conns.iter().find(|c| c.local_addr == "::").unwrap();
        assert_eq!(v6.local_port, 22);
        assert_eq!(v6.peer_addr, None);
    }

    #[test]
    fn parse_ss_udp_unconn_row() {
        let conns = parse_ss(SS_FIXTURE);
        let udp = conns.iter().find(|c| c.protocol == "udp").unwrap();
        assert_eq!(udp.state, "UNCONN");
        assert_eq!(udp.local_port, 68);
    }

    #[test]
    fn parse_ss_empty_input_yields_empty() {
        assert!(parse_ss("").is_empty());
        assert!(parse_ss("Netid State Recv-Q Send-Q Local Peer\n").is_empty());
    }

    // ── parse_lsof (macOS) ───────────────────────────────────────

    const LSOF_FIXTURE: &str = "\
COMMAND   PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd     1    root   26u  IPv4 0x1234567890abcdef      0t0  TCP *:22 (LISTEN)
sshd      456    root    4u  IPv4 0x1234567890abcde0      0t0  TCP 192.168.1.5:22->192.168.1.10:54321 (ESTABLISHED)
launchd     1    root   27u  IPv6 0x1234567890abcde2      0t0  TCP [::1]:22 (LISTEN)
mdnsd      78    _mdns   4u  IPv4 0x1234567890abcde1      0t0  UDP *:5353
";

    #[test]
    fn parse_lsof_skips_header_and_parses_all_rows() {
        let conns = parse_lsof(LSOF_FIXTURE);
        assert_eq!(conns.len(), 4);
    }

    #[test]
    fn parse_lsof_listen_wildcard_has_no_peer() {
        let conns = parse_lsof(LSOF_FIXTURE);
        let listen = conns
            .iter()
            .find(|c| c.protocol == "tcp" && c.state == "LISTEN" && c.local_addr == "*")
            .unwrap();
        assert_eq!(listen.local_port, 22);
        assert_eq!(listen.peer_addr, None);
    }

    #[test]
    fn parse_lsof_established_has_peer() {
        let conns = parse_lsof(LSOF_FIXTURE);
        let estab = conns.iter().find(|c| c.state == "ESTABLISHED").unwrap();
        assert_eq!(estab.local_addr, "192.168.1.5");
        assert_eq!(estab.local_port, 22);
        assert_eq!(estab.peer_addr.as_deref(), Some("192.168.1.10"));
        assert_eq!(estab.peer_port, Some(54321));
    }

    #[test]
    fn parse_lsof_handles_ipv6_bracket_listen() {
        let conns = parse_lsof(LSOF_FIXTURE);
        let v6 = conns.iter().find(|c| c.local_addr == "::1").unwrap();
        assert_eq!(v6.local_port, 22);
        assert_eq!(v6.state, "LISTEN");
    }

    #[test]
    fn parse_lsof_udp_without_state_paren_defaults_unconn() {
        let conns = parse_lsof(LSOF_FIXTURE);
        let udp = conns.iter().find(|c| c.protocol == "udp").unwrap();
        assert_eq!(udp.state, "UNCONN");
        assert_eq!(udp.local_port, 5353);
        assert_eq!(udp.local_addr, "*");
    }

    #[test]
    fn parse_lsof_empty_input_yields_empty() {
        assert!(parse_lsof("").is_empty());
        assert!(parse_lsof("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n").is_empty());
    }

    // ── InventorySnapshot JSON shape ───────────────────────────────

    #[test]
    fn inventory_snapshot_serializes_with_expected_keys() {
        let snap = InventorySnapshot {
            schema_version: 1,
            host: HostMeta {
                name: "web-1".to_string(),
                id: "abc123".to_string(),
                ip: Some("10.0.0.5".to_string()),
                os: "linux".to_string(),
            },
            connections: vec![ConnectionInfo {
                protocol: "tcp".to_string(),
                state: "LISTEN".to_string(),
                local_addr: "0.0.0.0".to_string(),
                local_port: 22,
                peer_addr: None,
                peer_port: None,
            }],
        };
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["host"]["name"], "web-1");
        assert_eq!(json["host"]["id"], "abc123");
        assert_eq!(json["connections"][0]["local_port"], 22);
        assert!(json["connections"][0]["peer_addr"].is_null());
    }
}
