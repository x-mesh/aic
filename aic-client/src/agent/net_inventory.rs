//! 연결/inventory JSON 스냅샷 (SRE t7: OTLP connections exporter가 주기 spawn하는 hidden CLI leaf).
//!
//! `aic snapshot inventory --json`(main.rs, hidden subcommand)이 호출하는 구현체다. **주의**:
//! 이 subcommand는 t7 작업 지시서가 가정한 `aic snapshot capture --json`과 다른 이름이다 —
//! 기존 `aic snapshot capture`는 opt-in 게이트(`AIC_SNAPSHOT_RECORD`)가 걸린 전체 redacted
//! markdown 스냅샷(디스크/프로세스/git status 등)을 영구 store에 append하는, 이 기능과는 무관한
//! 별개 기능이라 그대로 재사용하면 의미가 섞인다. 대신 machine-readable 전용 hidden leaf를 새로
//! 추가했다(사람이 직접 쓰는 명령이 아니라 `--help`에 노출하지 않는다).
//!
//! Linux는 `ss -tiunap`, macOS는 `lsof -nP +c 0 -iTCP -iUDP`로 LISTEN/ESTABLISHED 소켓을 조회한다.
//! 파싱 로직은 OS 무관 순수 함수([`parse_ss`]/[`parse_lsof`])로 분리해, 실제 프로세스를 spawn하지
//! 않고 고정 fixture 문자열로 두 포맷 모두 결정적으로 테스트한다(`capture()`/`run_os_probe()` 자체는
//! 실제 시스템 명령에 의존해 유닛 테스트 대상이 아니다 — 기존 `local_probes`류 패턴과 동일).
//!
//! `direction`은 OS가 주는 값이 아니라 **스냅샷 전체를 보고 파생한다**([`annotate_directions`]) —
//! 같은 스냅샷 안의 바인드 소켓 포트 집합과 대조해야만 "우리가 accept한 연결"과 "우리가 건 연결"을
//! 가를 수 있어서, 소켓 한 줄만 보는 파서 단계에서는 불가능하다.
//!
//! `process`는 자주 `None`이다. Linux `ss -p`는 타 사용자 소유 소켓의 프로세스를 읽으려면
//! root/CAP_SYS_PTRACE가 필요한데 aicd는 user unit이라(daemon_install.rs) 그런 소켓은 Process
//! 컬럼이 통째로 비어서 나온다(에러가 아니라 정상 경로다). **방향 판정은 이 권한과 무관하다** —
//! `ss`는 권한 없이도 시스템 전역 소켓 *목록*은 다 보여주므로 바인드 포트 집합은 언제나 완전하다.
//!
//! **JSON wire contract**: 여기의 구조체 필드명은 `aic-server`의 `otlp_exporter::connections`
//! (`InventorySnapshot`/`HostMeta`/`RawConnection`)와 반드시 일치해야 한다(직접 타입 공유가 아니라
//! 프로세스 경계를 넘는 JSON 계약 — 필드명을 바꾸면 양쪽 다 갱신할 것).

use serde::Serialize;
use std::collections::HashSet;
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

/// 연결 방향. rca 수신측(`otlp/decode.rs`의 `parse_direction`)이 **소문자만** 인식하므로
/// `rename_all`이 wire contract다 — 바꾸면 rca가 폴백 파생으로 조용히 되돌아간다.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// 바인드/수신 대기 소켓 (peer 없음).
    Listen,
    /// 우리가 accept한 연결 — local_port가 이 호스트의 서비스 포트다.
    Inbound,
    /// 우리가 건 연결.
    Outbound,
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
    /// 소켓을 소유한 프로세스 이름(실행 파일 이름이지 argv가 아니다 — 커맨드라인 인자는 애초에
    /// 들어오지 않는다). 권한이 없거나 커널 소켓이면 `None`(모듈 doc 참고).
    pub process: Option<String>,
    /// 소켓 생성 이후 로컬→피어 누적 송신 바이트. Linux `ss -i`의 `tcp_info`에서 얻으며,
    /// 지원하지 않는 프로토콜/OS에서는 0이다.
    pub bytes_sent: u64,
    /// 소켓 생성 이후 피어→로컬 누적 수신 바이트. Linux `ss -i`의 `tcp_info`에서 얻으며,
    /// 지원하지 않는 프로토콜/OS에서는 0이다.
    pub bytes_recv: u64,
    /// [`annotate_directions`]가 스냅샷 전체를 보고 확정한다. 파싱 단계에서는 peer 유무만 아는
    /// context-free 초기값이 들어간다.
    pub direction: Direction,
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
    let mut connections = if cfg!(target_os = "macos") {
        parse_lsof(&text)
    } else {
        parse_ss(&text)
    };
    // 파서는 소켓을 한 줄씩만 본다 — 방향은 스냅샷 전체가 모여야 정해진다.
    annotate_directions(&mut connections);
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

/// `+c 0`은 COMMAND truncate(기본 9자)를 끈다 — 안 그러면 `Google Chrome Helper`가 `Google Ch`로
/// 잘려 프로세스명이 무의미해진다. 길어진 COMMAND에 섞이는 공백은 [`parse_lsof`]가 컬럼 산술로
/// 복원한다.
#[cfg(target_os = "macos")]
fn run_os_probe() -> anyhow::Result<String> {
    let out = std::process::Command::new("lsof")
        .args(["-nP", "+c", "0", "-iTCP", "-iUDP"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `-p`(Process 컬럼)는 root 없이는 **자기 소유** 소켓만 이름을 채운다 — 나머지는 컬럼이 비고,
/// 소켓 행 자체는 그대로 나온다(에러가 아니다). aicd는 user unit이라 이게 정상 경로다. 방향 판정은
/// 전역 소켓 *목록*만 있으면 되므로 이 권한 부족의 영향을 받지 않는다(모듈 doc 참고).
#[cfg(not(target_os = "macos"))]
fn run_os_probe() -> anyhow::Result<String> {
    let out = std::process::Command::new("ss")
        .args(["-tiunap"])
        .output()?;
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

/// peer 유무만 보는 context-free 초기 방향 — 파서가 소켓 한 줄만 보고 정할 수 있는 최선이다.
/// [`annotate_directions`]가 스냅샷 문맥을 얹어 Outbound 중 실제로는 inbound인 것을 승격한다.
fn initial_direction(peer_port: Option<u16>) -> Direction {
    match peer_port {
        None => Direction::Listen,
        Some(_) => Direction::Outbound,
    }
}

/// 스냅샷 전체를 보고 각 연결의 방향을 확정한다.
///
/// peer가 없는 소켓 = 바인드/수신 대기 소켓이고, 그 `(protocol, local_port)`가 이 호스트의
/// **서비스 포트**다. peer가 있는 소켓의 local_port가 서비스 포트면 우리가 accept한 inbound고,
/// 아니면 우리가 건 outbound다.
///
/// **`state` 문자열을 보지 않는다.** UDP엔 LISTEN 상태가 없어서(UNCONN) state 기반 규칙은 UDP
/// 서버 포트를 통째로 놓친다 — `udp UNCONN 0.0.0.0:53`이 서비스 포트로 안 잡히면 그 포트로 들어온
/// 연결이 전부 outbound로 오분류된다. peer 유무는 TCP/UDP 공통이라 이 문제가 없고, OS별 상태
/// 문자열 차이(`ESTAB` vs `ESTABLISHED`)에도 영향받지 않는다.
///
/// **키에 주소를 넣지 않는다.** 그래야 `0.0.0.0:22`와 `[::]:22`가 동시에 LISTEN인 dual-stack이
/// 자연히 하나로 접히고, 특정 IP에만 바인딩된 리스너(`127.0.0.1:8080`)도 그대로 매칭된다.
///
/// **알려진 한계**: 리스너가 ephemeral 대역(32768~60999)에 있고 outbound 연결의 source port가
/// 우연히 그 값과 같으면 inbound로 오분류된다. 주소까지 매칭해도 wildcard 리스너 케이스는 못 잡아
/// 이득이 작아 단순함을 택했다.
pub(crate) fn annotate_directions(conns: &mut [ConnectionInfo]) {
    let server_ports: HashSet<(&str, u16)> = conns
        .iter()
        .filter(|c| c.peer_port.is_none())
        .map(|c| (c.protocol.as_str(), c.local_port))
        .collect();
    // server_ports가 conns를 빌려 있으므로 방향을 먼저 계산해두고 나서 쓴다.
    let directions: Vec<Direction> = conns
        .iter()
        .map(|c| {
            if c.peer_port.is_none() {
                Direction::Listen
            } else if server_ports.contains(&(c.protocol.as_str(), c.local_port)) {
                Direction::Inbound
            } else {
                Direction::Outbound
            }
        })
        .collect();
    for (c, d) in conns.iter_mut().zip(directions) {
        c.direction = d;
    }
}

/// lsof가 COMMAND 안의 출력 불가 문자를 내보내는 `\xHH` 이스케이프를 되돌린다 — 실측상 공백이
/// `\x20`으로 나오므로(`Slack\x20Helper`), 디코딩하지 않으면 그 문자열이 그대로 rca에 저장된다.
/// 유효한 2자리 hex가 아니면 원문을 그대로 둔다(디코딩 실패로 이름을 잃는 것보다 낫다).
fn unescape_lsof(s: &str) -> String {
    if !s.contains("\\x") {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'\\' && i + 3 < bytes.len() + 1 && bytes.get(i + 1) == Some(&b'x'))
            .then(|| s.get(i + 2..i + 4))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .filter(|b| b.is_ascii());
        match hex {
            Some(b) => {
                out.push(b as char);
                i += 4;
            }
            None => {
                // 멀티바이트 문자를 쪼개지 않도록 char 경계 단위로 넘긴다.
                let ch = s[i..].chars().next().expect("i는 항상 char 경계");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// `ss -p`의 Process 컬럼(`users:(("sshd",pid=1234,fd=3))`)에서 **첫 번째** 프로세스 이름을 뽑는다.
/// 한 소켓을 여러 프로세스가 공유하면(fork된 워커 등) 대개 이름이 같아 첫 항목으로 충분하다.
/// 구 iproute2의 `users:(("sshd",1234,3))` 형식도 같은 규칙으로 잡힌다. 프로세스 정보가 없으면
/// (권한 부족·커널 소켓) 컬럼이 통째로 비어 `None`.
pub(crate) fn parse_ss_process(field: &str) -> Option<String> {
    let start = field.find("((\"")? + 3;
    let rest = &field[start..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    (!name.is_empty()).then(|| name.to_string())
}

/// `ss -i`의 TCP 상세 줄에서 누적 바이트 카운터를 읽어 직전 소켓 행에 붙인다. 커널/iproute2가
/// 필드를 제공하지 않거나 숫자가 깨졌으면 0을 유지한다.
fn annotate_tcp_info_counters(conn: Option<&mut ConnectionInfo>, fields: &[&str]) {
    let Some(conn) = conn.filter(|c| c.protocol == "tcp") else {
        return;
    };
    for field in fields {
        if let Some(value) = field
            .strip_prefix("bytes_sent:")
            .and_then(|v| v.parse().ok())
        {
            conn.bytes_sent = value;
        } else if let Some(value) = field
            .strip_prefix("bytes_received:")
            .and_then(|v| v.parse().ok())
        {
            conn.bytes_recv = value;
        }
    }
}

/// Linux `ss -tiunap` 출력을 파싱한다. 기본 행 컬럼은 `Netid State Recv-Q Send-Q
/// "Local Address:Port" "Peer Address:Port"`(+선택적 Process)이고, 뒤따르는 `-i` 상세 줄의
/// `bytes_sent`/`bytes_received`를 직전 TCP 소켓에 연결한다. `-p` 없는 6컬럼 출력도 계속
/// 파싱된다(`process`가 `None`이 될 뿐이다).
pub(crate) fn parse_ss(text: &str) -> Vec<ConnectionInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || fields[0].eq_ignore_ascii_case("netid") {
            continue;
        }
        let protocol = fields[0].to_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            annotate_tcp_info_counters(out.last_mut(), &fields);
            continue;
        }
        if fields.len() < 6 {
            continue;
        }
        let state = fields[1].to_string();
        let (local_addr, local_port) = split_host_port(fields[4]);
        let (peer_addr, peer_port) = match split_host_port(fields[5]) {
            (addr, Some(port)) => (Some(addr), Some(port)),
            (_, None) => (None, None),
        };
        // Process 컬럼은 있을 수도(권한 있는 소켓) 없을 수도(권한 부족·커널 소켓) 있다.
        // 프로세스명에 공백이 섞이는 경우까지 대비해 6번 이후를 전부 이어붙여 넘긴다.
        let process = fields
            .get(6..)
            .filter(|rest| !rest.is_empty())
            .and_then(|rest| parse_ss_process(&rest.join(" ")));
        out.push(ConnectionInfo {
            protocol,
            state,
            local_addr,
            local_port: local_port.unwrap_or(0),
            peer_addr,
            peer_port,
            process,
            bytes_sent: 0,
            bytes_recv: 0,
            direction: initial_direction(peer_port),
        });
    }
    out
}

/// macOS `lsof -nP +c 0 -iTCP -iUDP` 출력을 파싱한다. 컬럼 수가 USER/COMMAND 값에 따라 흔들릴 수
/// 있어 뒤에서부터 인덱싱한다: 마지막 필드가 `(STATE)`면 `[..., PROTO, NAME, (STATE)]`,
/// 아니면(주로 UDP) `[..., PROTO, NAME]`.
///
/// **COMMAND의 공백**: macOS lsof는 실측상 공백을 `\x20`으로 이스케이프해서 내보내므로
/// (`Slack\x20Helper`) COMMAND는 항상 1토큰이다 — [`unescape_lsof`]가 그걸 되돌린다. 다만 그
/// 이스케이프에 기대지 않고 COMMAND 토큰 수를 **역산**한다: COMMAND 뒤로는
/// `PID USER FD TYPE DEVICE SIZE/OFF NODE NAME` 8개가 고정이고 `(STATE)`만 선택적이라, 뒤에서부터
/// 세면 앞이 몇 토큰이든 복원된다. 이스케이프하지 않는 lsof 빌드를 만나도 이름을 잃지 않는다.
pub(crate) fn parse_lsof(text: &str) -> Vec<ConnectionInfo> {
    /// COMMAND 뒤에 항상 오는 컬럼 수: PID USER FD TYPE DEVICE SIZE/OFF NODE NAME.
    const FIXED_COLS_AFTER_COMMAND: usize = 8;

    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0].eq_ignore_ascii_case("command") {
            continue;
        }
        let last = *fields.last().unwrap();
        let has_state = last.starts_with('(') && last.ends_with(')');
        let (state, name, proto) = if has_state {
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
        // 0이면 컬럼 가정이 깨진 비정상 행 — 첫 토큰으로 폴백한다(행을 통째로 버리지 않는다).
        let cmd_end = fields
            .len()
            .saturating_sub(FIXED_COLS_AFTER_COMMAND + usize::from(has_state))
            .max(1);
        let process = Some(unescape_lsof(&fields[..cmd_end].join(" ")));
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
            process,
            bytes_sent: 0,
            bytes_recv: 0,
            direction: initial_direction(peer_port),
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

    #[test]
    fn parse_ss_without_process_column_still_parses() {
        // `-p` 없는 6컬럼 출력(구 버전/권한 없는 환경)도 계속 파싱돼야 한다.
        let conns = parse_ss(SS_FIXTURE);
        assert!(conns.iter().all(|c| c.process.is_none()));
    }

    // ── parse_ss with -p (Process 컬럼) ───────────────────────────────

    /// 마지막에서 두 번째 행이 핵심: 권한 부족으로 **Process 컬럼이 통째로 없는** 6-field 행이다.
    const SS_P_FIXTURE: &str = "\
Netid  State   Recv-Q Send-Q     Local Address:Port      Peer Address:Port   Process
udp    UNCONN  0      0               0.0.0.0:53              0.0.0.0:*       users:((\"named\",pid=900,fd=20))
udp    ESTAB   0      0            192.168.1.5:53          192.168.1.99:41234 users:((\"named\",pid=900,fd=21))
tcp    LISTEN  0      128             0.0.0.0:22               0.0.0.0:*      users:((\"sshd\",pid=1234,fd=3))
tcp    LISTEN  0      128                [::]:22                  [::]:*      users:((\"sshd\",pid=1234,fd=4))
tcp    ESTAB   0      0            192.168.1.5:22          192.168.1.10:54321 users:((\"sshd\",pid=4567,fd=5),(\"sshd\",pid=4568,fd=5))
tcp    ESTAB   0      0            192.168.1.5:51234       140.82.113.4:443
";

    #[test]
    fn parse_ss_extracts_process_name() {
        let conns = parse_ss(SS_P_FIXTURE);
        let listen = conns
            .iter()
            .find(|c| c.local_port == 22 && c.state == "LISTEN" && c.local_addr == "0.0.0.0")
            .unwrap();
        assert_eq!(listen.process.as_deref(), Some("sshd"));
        // 여러 프로세스가 한 소켓을 공유해도 첫 항목만.
        let estab = conns.iter().find(|c| c.local_port == 22 && c.state == "ESTAB").unwrap();
        assert_eq!(estab.process.as_deref(), Some("sshd"));
    }

    #[test]
    fn parse_ss_missing_process_column_is_none_not_skipped() {
        // 권한 부족 행은 버려지면 안 된다 — 방향 판정에 필요한 소켓이다.
        let conns = parse_ss(SS_P_FIXTURE);
        let outbound = conns.iter().find(|c| c.local_port == 51234).unwrap();
        assert_eq!(outbound.process, None);
        assert_eq!(outbound.peer_port, Some(443));
    }

    #[test]
    fn parse_ss_attaches_tcp_info_bytes_to_the_preceding_socket() {
        const SS_I_FIXTURE: &str = "\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 0 0 10.0.0.5:51234 10.0.0.8:443 users:((\"curl\",pid=7,fd=3))
     cubic wscale:7,7 rto:204 rtt:1.5/0.3 bytes_sent:1048576 bytes_acked:1048577 bytes_received:8192 segs_out:42
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=8,fd=4))
     cubic cwnd:10
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:((\"named\",pid=9,fd=5))
";
        let conns = parse_ss(SS_I_FIXTURE);
        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].bytes_sent, 1_048_576);
        assert_eq!(conns[0].bytes_recv, 8_192);
        assert_eq!(conns[1].bytes_sent, 0);
        assert_eq!(conns[1].bytes_recv, 0);
        assert_eq!(conns[2].bytes_sent, 0);
        assert_eq!(conns[2].bytes_recv, 0);
    }

    #[test]
    fn parse_ss_ignores_malformed_tcp_info_counters() {
        const MALFORMED: &str = "\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp ESTAB 0 0 10.0.0.5:51234 10.0.0.8:443
     cubic bytes_sent:not-a-number bytes_received:also-bad
";
        let conns = parse_ss(MALFORMED);
        assert_eq!(conns[0].bytes_sent, 0);
        assert_eq!(conns[0].bytes_recv, 0);
    }

    #[test]
    fn parse_ss_process_handles_modern_legacy_and_garbage() {
        assert_eq!(
            parse_ss_process("users:((\"sshd\",pid=1234,fd=3))").as_deref(),
            Some("sshd")
        );
        // 구 iproute2 형식.
        assert_eq!(parse_ss_process("users:((\"sshd\",1234,3))").as_deref(), Some("sshd"));
        assert_eq!(parse_ss_process(""), None);
        assert_eq!(parse_ss_process("garbage"), None);
        assert_eq!(parse_ss_process("users:((\"\",pid=1,fd=2))"), None);
    }

    // ── annotate_directions ──────────────────────────────────────────

    fn directions_of(fixture: &str) -> Vec<ConnectionInfo> {
        let mut conns = parse_ss(fixture);
        annotate_directions(&mut conns);
        conns
    }

    #[test]
    fn annotate_directions_marks_listen_inbound_and_outbound() {
        let conns = directions_of(SS_P_FIXTURE);

        let listen = conns
            .iter()
            .find(|c| c.local_port == 22 && c.state == "LISTEN" && c.local_addr == "0.0.0.0")
            .unwrap();
        assert_eq!(listen.direction, Direction::Listen);

        // local_port 22가 서비스 포트 → 우리가 accept한 연결.
        let inbound = conns.iter().find(|c| c.local_port == 22 && c.state == "ESTAB").unwrap();
        assert_eq!(inbound.direction, Direction::Inbound);

        // ephemeral source port → 우리가 건 연결.
        let outbound = conns.iter().find(|c| c.local_port == 51234).unwrap();
        assert_eq!(outbound.direction, Direction::Outbound);
    }

    #[test]
    fn annotate_directions_handles_udp_which_has_no_listen_state() {
        // UDP엔 LISTEN이 없다(UNCONN). state 기반 규칙이었다면 udp/53이 서비스 포트로 안 잡혀
        // 그 포트로 들어온 연결이 outbound로 오분류된다.
        let conns = directions_of(SS_P_FIXTURE);
        let bound = conns
            .iter()
            .find(|c| c.protocol == "udp" && c.peer_port.is_none())
            .unwrap();
        assert_eq!(bound.direction, Direction::Listen);
        let inbound = conns
            .iter()
            .find(|c| c.protocol == "udp" && c.peer_port.is_some())
            .unwrap();
        assert_eq!(inbound.direction, Direction::Inbound, "udp/53 must be a server port");
    }

    #[test]
    fn annotate_directions_collapses_dual_stack_listeners() {
        // 0.0.0.0:22 와 [::]:22 가 동시에 LISTEN이어도 키가 (proto, port)라 하나로 접힌다.
        let conns = directions_of(SS_P_FIXTURE);
        let v6_listen = conns.iter().find(|c| c.local_addr == "::").unwrap();
        assert_eq!(v6_listen.direction, Direction::Listen);
        let inbound = conns.iter().find(|c| c.local_port == 22 && c.state == "ESTAB").unwrap();
        assert_eq!(inbound.direction, Direction::Inbound);
    }

    #[test]
    fn annotate_directions_splits_a_loopback_pair() {
        // 같은 호스트 안의 클라이언트/서버 양 끝이 정확히 갈려야 한다.
        const LOOPBACK: &str = "\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128    127.0.0.1:8080     0.0.0.0:*
tcp   ESTAB  0      0      127.0.0.1:8080     127.0.0.1:54321
tcp   ESTAB  0      0      127.0.0.1:54321    127.0.0.1:8080
";
        let conns = directions_of(LOOPBACK);
        let server_side = conns
            .iter()
            .find(|c| c.local_port == 8080 && c.peer_port == Some(54321))
            .unwrap();
        assert_eq!(server_side.direction, Direction::Inbound);
        let client_side = conns
            .iter()
            .find(|c| c.local_port == 54321 && c.peer_port == Some(8080))
            .unwrap();
        assert_eq!(client_side.direction, Direction::Outbound);
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

    #[test]
    fn parse_lsof_extracts_the_command_column() {
        let conns = parse_lsof(LSOF_FIXTURE);
        let estab = conns.iter().find(|c| c.state == "ESTABLISHED").unwrap();
        assert_eq!(estab.process.as_deref(), Some("sshd"));
        // STATE 없는 UDP 행도 (컬럼이 하나 적어도) 산술이 맞아야 한다.
        let udp = conns.iter().find(|c| c.protocol == "udp").unwrap();
        assert_eq!(udp.process.as_deref(), Some("mdnsd"));
    }

    #[test]
    fn parse_lsof_unescapes_a_spaced_command() {
        // 실측: macOS lsof는 COMMAND의 공백을 `\x20`으로 이스케이프한다. 디코딩하지 않으면
        // `Slack\x20Helper`가 그대로 rca에 저장된다.
        const ESCAPED: &str = "\
COMMAND   PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Slack\\x20Helper 920 jinwoo 26u  IPv4 0xedd82b33a6b8365a      0t0  TCP 192.168.1.92:49649->52.193.110.50:443 (ESTABLISHED)
";
        let conns = parse_lsof(ESCAPED);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].process.as_deref(), Some("Slack Helper"));
        assert_eq!(conns[0].local_port, 49649);
        assert_eq!(conns[0].peer_port, Some(443));
    }

    #[test]
    fn parse_lsof_recovers_a_literal_spaced_command() {
        // 이스케이프하지 않는 lsof 빌드를 만나도 컬럼 역산으로 이름을 복원해야 한다 —
        // fields[0]만 쓰면 "Google"이 된다.
        const SPACED: &str = "\
COMMAND   PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google Chrome Helper 555 jinwoo 30u  IPv4 0x1234567890abcdef      0t0  TCP 10.0.0.5:52000->142.250.0.1:443 (ESTABLISHED)
";
        let conns = parse_lsof(SPACED);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].process.as_deref(), Some("Google Chrome Helper"));
    }

    #[test]
    fn unescape_lsof_decodes_hex_and_leaves_the_rest_alone() {
        assert_eq!(unescape_lsof("Slack\\x20Helper"), "Slack Helper");
        assert_eq!(unescape_lsof("postgres"), "postgres");
        assert_eq!(unescape_lsof("com.docker.backend"), "com.docker.backend");
        // 유효한 hex가 아니면 원문 유지 — 디코딩 실패로 이름을 잃지 않는다.
        assert_eq!(unescape_lsof("weird\\xZZname"), "weird\\xZZname");
        assert_eq!(unescape_lsof("trailing\\x"), "trailing\\x");
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
                process: Some("sshd".to_string()),
                bytes_sent: 1_024,
                bytes_recv: 2_048,
                direction: Direction::Listen,
            }],
        };
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["host"]["name"], "web-1");
        assert_eq!(json["host"]["id"], "abc123");
        assert_eq!(json["connections"][0]["local_port"], 22);
        assert!(json["connections"][0]["peer_addr"].is_null());
        assert_eq!(json["connections"][0]["process"], "sshd");
        assert_eq!(json["connections"][0]["bytes_sent"], 1_024);
        assert_eq!(json["connections"][0]["bytes_recv"], 2_048);
        // 소문자여야 한다 — rca의 `parse_direction`이 소문자만 인식한다. 이 assert가 wire contract.
        assert_eq!(json["connections"][0]["direction"], "listen");
    }

    #[test]
    fn direction_serializes_lowercase_for_every_variant() {
        for (d, expected) in [
            (Direction::Listen, "listen"),
            (Direction::Inbound, "inbound"),
            (Direction::Outbound, "outbound"),
        ] {
            assert_eq!(serde_json::to_value(d).unwrap(), expected);
        }
    }
}
