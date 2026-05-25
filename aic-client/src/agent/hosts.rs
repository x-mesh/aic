//! SSH 멀티호스트 진단(RFC-005 Phase 1)의 호스트 인벤토리.
//!
//! 주(主) 인벤토리는 `~/.aic/hosts.toml`. `[options] ssh_config_import = true`(기본)면
//! `~/.ssh/config`의 Host 블록을 자동 흡수하고, `[[hosts]]`가 overlay로 덮어쓴다.
//!
//! RFC-005 §4.1 파싱 위임 경계: aic는 `HostName/User/Port/ProxyJump/IdentityFile`만
//! 추출한다. 그 외 directive(`Match`, `Include`, `%h`/`%r`/`%p` 토큰, `ProxyCommand`,
//! `CanonicalizeHostname`)는 `ssh` 프로세스가 직접 해석하므로 aic는 파싱하지 않고
//! `ssh_config_warnings`에 흔적만 남긴다.
//!
//! 이 모듈은 **순수 파싱·해석**만 담당한다. 실제 SSH 호출은 `remote::ssh_process`(Phase 2)에서.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// 한 호스트의 최종 해석값(hosts.toml + ssh_config overlay 결과).
///
/// `source`는 디버깅 surface — `aic hosts show <name>`이 어느 필드가 어디서 왔는지
/// 표시할 때 사용한다(red-team O1 해소).
#[derive(Debug, Clone, Serialize)]
pub struct HostEntry {
    pub name: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
    /// RFC-005 §4.1: 기본 false. bastion 신뢰 시만 hosts.toml에서 true.
    pub forward_agent: bool,
    pub proxy_jump: Option<String>,
    pub host_key_check: HostKeyCheck,
    pub connect_timeout_secs: u32,
    pub tags: Vec<String>,
    pub source: HostSource,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyCheck {
    Strict,
    AcceptNew,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostSource {
    HostsToml,
    SshConfig,
    /// ssh_config에서 흡수된 뒤 hosts.toml로 일부 필드 overlay된 호스트.
    Overlay,
}

/// `@web-tier` 그룹 정의.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostGroup {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `[options]` 섹션.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    #[serde(default = "default_true")]
    pub ssh_config_import: bool,
    #[serde(default = "default_host_key_check")]
    pub default_host_key_check: String,
    /// RFC-005 §4.2 S1: 기본 false, 원격 `$SHELL` 감지 시 자동 true 강제(Phase 2).
    #[serde(default)]
    pub remote_shell_wrap: bool,
}

fn default_true() -> bool {
    true
}
fn default_host_key_check() -> String {
    "strict".into()
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ssh_config_import: true,
            default_host_key_check: "strict".into(),
            remote_shell_wrap: false,
        }
    }
}

/// `[concurrency]` 섹션 (RFC-005 §4.5 — Phase 2/3에서 사용).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Concurrency {
    #[serde(default = "default_max_parallel")]
    pub max_parallel: usize,
    #[serde(default = "default_per_host_timeout")]
    pub per_host_timeout_secs: u32,
    #[serde(default = "default_wall_timeout")]
    pub wall_clock_timeout_secs: u32,
}

fn default_max_parallel() -> usize {
    8
}
fn default_per_host_timeout() -> u32 {
    30
}
fn default_wall_timeout() -> u32 {
    300
}

impl Default for Concurrency {
    fn default() -> Self {
        Self {
            max_parallel: 8,
            per_host_timeout_secs: 30,
            wall_clock_timeout_secs: 300,
        }
    }
}

// ── 디스크 표현(serde Deserialize 전용) ──────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct HostsTomlDoc {
    #[serde(default)]
    options: Options,
    #[serde(default)]
    concurrency: Concurrency,
    #[serde(default)]
    groups: BTreeMap<String, HostGroup>,
    /// `[[hosts]]` 배열.
    #[serde(default, rename = "hosts")]
    host_entries: Vec<HostsTomlEntry>,
}

#[derive(Debug, Deserialize)]
struct HostsTomlEntry {
    name: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<PathBuf>,
    forward_agent: Option<bool>,
    proxy_jump: Option<String>,
    host_key_check: Option<String>,
    connect_timeout_secs: Option<u32>,
    #[serde(default)]
    tags: Vec<String>,
}

// ── 인벤토리(메모리 표현) ────────────────────────────────────────────

/// 로드 + ssh_config import + overlay 적용 완료된 인벤토리.
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub options: Options,
    pub concurrency: Concurrency,
    pub groups: BTreeMap<String, HostGroup>,
    /// name → 최종 해석값.
    pub hosts: BTreeMap<String, HostEntry>,
    /// ssh_config 흡수 중 위임 처리된 directive 흔적(`aic hosts show`에서 노출).
    pub ssh_config_warnings: Vec<String>,
}

impl Inventory {
    /// `~/.aic/hosts.toml` + `~/.ssh/config`로 기본 로드.
    pub fn load() -> Result<Self> {
        let hosts_toml = home_path(".aic/hosts.toml")?;
        let ssh_config = home_path(".ssh/config")?;
        Self::load_from(&hosts_toml, &ssh_config)
    }

    /// 임의 경로로 로드(테스트 + 사용자 지정용). 두 파일 모두 없어도 빈 인벤토리 반환.
    pub fn load_from(hosts_toml: &Path, ssh_config: &Path) -> Result<Self> {
        // 1) hosts.toml 파싱(없으면 default 빈 디스크 표현)
        let toml_doc: HostsTomlDoc = if hosts_toml.exists() {
            let s = fs::read_to_string(hosts_toml)
                .with_context(|| format!("read {}", hosts_toml.display()))?;
            toml::from_str(&s)
                .with_context(|| format!("parse {}", hosts_toml.display()))?
        } else {
            HostsTomlDoc::default()
        };

        // 2) ssh_config import(옵션 + 파일 존재)
        let (mut hosts, ssh_config_warnings) =
            if toml_doc.options.ssh_config_import && ssh_config.exists() {
                parse_ssh_config(ssh_config)?
            } else {
                (BTreeMap::new(), Vec::new())
            };

        // 3) hosts.toml overlay — 같은 name이면 필드별 덮어쓰기, 없으면 신규
        for e in &toml_doc.host_entries {
            apply_overlay(&mut hosts, e, &toml_doc.options);
        }

        Ok(Self {
            options: toml_doc.options,
            concurrency: toml_doc.concurrency,
            groups: toml_doc.groups,
            hosts,
            ssh_config_warnings,
        })
    }

    /// 패턴 해석:
    /// - `@group_name` → 그룹 멤버 호스트들(순서 유지)
    /// - `name`        → 단일 호스트
    ///
    /// 그룹/호스트 미존재면 명확한 에러(red-team U2 행동 경로 부재 완화).
    pub fn resolve_pattern(&self, pat: &str) -> Result<Vec<&HostEntry>> {
        if let Some(group) = pat.strip_prefix('@') {
            let g = self
                .groups
                .get(group)
                .ok_or_else(|| anyhow!("group not found: @{group}"))?;
            let mut out = Vec::with_capacity(g.hosts.len());
            for h in &g.hosts {
                let e = self.hosts.get(h).ok_or_else(|| {
                    anyhow!("group @{group} references unknown host: {h}")
                })?;
                out.push(e);
            }
            Ok(out)
        } else {
            let e = self
                .hosts
                .get(pat)
                .ok_or_else(|| anyhow!("host not found: {pat}"))?;
            Ok(vec![e])
        }
    }

    pub fn host(&self, name: &str) -> Option<&HostEntry> {
        self.hosts.get(name)
    }
}

// ── 헬퍼 ────────────────────────────────────────────────────────────

fn home_path(rel: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("$HOME not set"))?;
    Ok(home.join(rel))
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

fn parse_host_key_check(s: &str) -> HostKeyCheck {
    match s {
        "accept-new" | "accept_new" | "AcceptNew" => HostKeyCheck::AcceptNew,
        _ => HostKeyCheck::Strict,
    }
}

fn apply_overlay(
    hosts: &mut BTreeMap<String, HostEntry>,
    e: &HostsTomlEntry,
    options: &Options,
) {
    let default_check = parse_host_key_check(&options.default_host_key_check);
    let was_in_ssh_config = hosts.contains_key(&e.name);
    let entry = hosts.entry(e.name.clone()).or_insert_with(|| HostEntry {
        name: e.name.clone(),
        hostname: String::new(),
        user: whoami(),
        port: 22,
        identity_file: None,
        forward_agent: false,
        proxy_jump: None,
        host_key_check: default_check,
        connect_timeout_secs: 10,
        tags: Vec::new(),
        source: HostSource::HostsToml,
    });
    if let Some(h) = &e.hostname {
        entry.hostname = h.clone();
    } else if entry.hostname.is_empty() {
        // ssh_config에 HostName 없고 hosts.toml에도 없으면 name 자체를 host로(ssh가 해석)
        entry.hostname = entry.name.clone();
    }
    if let Some(u) = &e.user {
        entry.user = u.clone();
    }
    if let Some(p) = e.port {
        entry.port = p;
    }
    if let Some(id) = &e.identity_file {
        entry.identity_file = Some(id.clone());
    }
    if let Some(fa) = e.forward_agent {
        entry.forward_agent = fa;
    }
    if let Some(pj) = &e.proxy_jump {
        entry.proxy_jump = Some(pj.clone());
    }
    if let Some(hkc) = &e.host_key_check {
        entry.host_key_check = parse_host_key_check(hkc);
    }
    if let Some(t) = e.connect_timeout_secs {
        entry.connect_timeout_secs = t;
    }
    if !e.tags.is_empty() {
        entry.tags = e.tags.clone();
    }
    entry.source = if was_in_ssh_config {
        HostSource::Overlay
    } else {
        HostSource::HostsToml
    };
}

/// `~/.ssh/config`의 Host 블록만 흡수.
///
/// RFC-005 §4.1 위임 경계: HostName/User/Port/ProxyJump/IdentityFile만 추출하고
/// Match/Include/ProxyCommand/CanonicalizeHostname은 경고만 남긴다. Wildcard host
/// 패턴(`*.prod`, `?`, `!`)은 정확한 이름이 아니므로 인벤토리에서 제외(ssh가 해석할
/// 것이라 가정).
fn parse_ssh_config(
    path: &Path,
) -> Result<(BTreeMap<String, HostEntry>, Vec<String>)> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut hosts: BTreeMap<String, HostEntry> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut current: Option<HostEntry> = None;
    // Match 블록 안의 directive는 매칭 조건이 평가되어야 적용되는데, aic는 그 평가를
    // ssh 프로세스에 위임한다. 따라서 Match 라인 이후 다음 Host 라인이 나올 때까지
    // 모든 directive를 건너뛴다(skip-until-next-host). 그렇지 않으면 직전 Host 블록에
    // 잘못 누설된다(예: Host web-02 다음 Match 블록의 `User matched`가 web-02에 적용).
    let mut in_match_block = false;

    let flush = |slot: &mut Option<HostEntry>, hosts: &mut BTreeMap<String, HostEntry>| {
        if let Some(h) = slot.take() {
            if !h.name.is_empty() && !contains_wildcard(&h.name) {
                hosts.insert(h.name.clone(), h);
            }
        }
    };

    for (lineno, raw) in s.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("match ") || lower == "match" {
            warnings.push(format!(
                "line {}: Match directive ignored (ssh process handles)",
                lineno + 1
            ));
            // Match 블록 진입: 직전 Host 블록을 즉시 flush해 누설 차단, 이후 다음 Host까지
            // 모든 directive 건너뜀.
            flush(&mut current, &mut hosts);
            in_match_block = true;
            continue;
        }
        if lower.starts_with("include ") {
            warnings.push(format!(
                "line {}: Include directive not followed by aic",
                lineno + 1
            ));
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            continue;
        };
        let key_lower = key.to_ascii_lowercase();

        if key_lower == "host" {
            flush(&mut current, &mut hosts);
            // Match 블록 종료 — 새 Host가 시작되었으므로 다시 directive 적용.
            in_match_block = false;
            let name = value.split_whitespace().next().unwrap_or("").to_string();
            if contains_wildcard(&name) {
                // wildcard 패턴 — aic는 추적하지 않음(ssh가 매칭)
                current = None;
                continue;
            }
            current = Some(HostEntry {
                name: name.clone(),
                hostname: name,
                user: whoami(),
                port: 22,
                identity_file: None,
                forward_agent: false,
                proxy_jump: None,
                host_key_check: HostKeyCheck::Strict,
                connect_timeout_secs: 10,
                tags: Vec::new(),
                source: HostSource::SshConfig,
            });
            continue;
        }

        // Match 블록 안의 directive는 매칭 평가가 필요하므로 aic는 무시(ssh 프로세스가 처리).
        // flush로 current가 이미 None이지만 명시적으로 가드한다.
        if in_match_block {
            continue;
        }
        let Some(h) = current.as_mut() else {
            continue;
        };
        match key_lower.as_str() {
            "hostname" => h.hostname = value.to_string(),
            "user" => h.user = value.to_string(),
            "port" => {
                if let Ok(p) = value.parse() {
                    h.port = p;
                }
            }
            "proxyjump" => h.proxy_jump = Some(value.to_string()),
            "identityfile" => h.identity_file = Some(PathBuf::from(value)),
            "proxycommand" => warnings.push(format!(
                "line {}: ProxyCommand handled by ssh process (not parsed by aic)",
                lineno + 1
            )),
            "canonicalizehostname" => warnings.push(format!(
                "line {}: CanonicalizeHostname handled by ssh process",
                lineno + 1
            )),
            // 기타 directive는 ssh 프로세스에 위임(조용히 무시)
            _ => {}
        }
    }
    flush(&mut current, &mut hosts);
    Ok((hosts, warnings))
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let sep = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..sep];
    let rest = line[sep..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    Some((key, rest))
}

fn contains_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.starts_with('!')
}

// ── 테스트 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn empty_inventory_when_both_files_missing() {
        let dir = tempdir().unwrap();
        let inv =
            Inventory::load_from(&dir.path().join("none.toml"), &dir.path().join("none.cfg"))
                .unwrap();
        assert!(inv.hosts.is_empty());
        assert!(inv.groups.is_empty());
    }

    #[test]
    fn parses_minimal_hosts_toml() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(
            &h,
            r#"
[[hosts]]
name = "web-01"
hostname = "10.0.1.10"
user = "sre"
port = 22
tags = ["nginx"]
"#,
        );
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        let e = inv.host("web-01").unwrap();
        assert_eq!(e.hostname, "10.0.1.10");
        assert_eq!(e.user, "sre");
        assert_eq!(e.port, 22);
        assert_eq!(e.tags, vec!["nginx".to_string()]);
        assert!(matches!(e.source, HostSource::HostsToml));
    }

    #[test]
    fn imports_ssh_config_host_blocks_only() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        let s = dir.path().join("ssh_config");
        write(&h, "");
        write(
            &s,
            r#"
Host bastion
    HostName 10.0.1.5
    User ops
    Port 2222

Host *.prod
    User prod-user

Host web-01
    HostName 10.0.1.10
    User sre
    ProxyJump bastion
    IdentityFile ~/.ssh/web_prod_ed25519
"#,
        );
        let inv = Inventory::load_from(&h, &s).unwrap();
        // wildcard `*.prod`는 무시
        assert!(inv.host("*.prod").is_none());

        let bastion = inv.host("bastion").unwrap();
        assert_eq!(bastion.hostname, "10.0.1.5");
        assert_eq!(bastion.user, "ops");
        assert_eq!(bastion.port, 2222);

        let web = inv.host("web-01").unwrap();
        assert_eq!(web.hostname, "10.0.1.10");
        assert_eq!(web.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(
            web.identity_file.as_ref().map(|p| p.to_string_lossy().to_string()),
            Some("~/.ssh/web_prod_ed25519".to_string())
        );
        assert!(matches!(web.source, HostSource::SshConfig));
    }

    #[test]
    fn hosts_toml_overlays_ssh_config_field_level() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        let s = dir.path().join("ssh_config");
        write(
            &s,
            r#"
Host web-01
    HostName 10.0.1.10
    User sshconfig-user
    Port 22
"#,
        );
        write(
            &h,
            r#"
[[hosts]]
name = "web-01"
user = "hosts-toml-user"
tags = ["nginx"]
identity_file = "~/.ssh/web_prod_ed25519"
"#,
        );
        let inv = Inventory::load_from(&h, &s).unwrap();
        let e = inv.host("web-01").unwrap();
        // hostname은 ssh_config 유지(overlay 미지정)
        assert_eq!(e.hostname, "10.0.1.10");
        // user는 hosts.toml로 덮어쓰기
        assert_eq!(e.user, "hosts-toml-user");
        // identity_file은 hosts.toml에서 새로 추가
        assert!(e.identity_file.is_some());
        // ssh_config 기반 호스트에 hosts.toml overlay가 적용된 경우 source는 Overlay
        assert!(matches!(e.source, HostSource::Overlay));
    }

    #[test]
    fn resolve_pattern_group_and_single() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(
            &h,
            r#"
[[hosts]]
name = "web-01"
hostname = "10.0.1.10"

[[hosts]]
name = "web-02"
hostname = "10.0.1.11"

[groups.web-tier]
hosts = ["web-01", "web-02"]
tags = ["nginx", "prod"]
"#,
        );
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        let group = inv.resolve_pattern("@web-tier").unwrap();
        assert_eq!(group.len(), 2);
        assert_eq!(group[0].name, "web-01");
        assert_eq!(group[1].name, "web-02");
        let single = inv.resolve_pattern("web-01").unwrap();
        assert_eq!(single.len(), 1);
    }

    #[test]
    fn resolve_unknown_group_or_host_errors_clearly() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(&h, "");
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        let e = inv.resolve_pattern("@nope").unwrap_err();
        assert!(e.to_string().contains("group not found"));
        let e = inv.resolve_pattern("nope").unwrap_err();
        assert!(e.to_string().contains("host not found"));
    }

    #[test]
    fn resolve_group_with_missing_member_errors() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(
            &h,
            r#"
[groups.web-tier]
hosts = ["web-01", "web-99"]
"#,
        );
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        let e = inv.resolve_pattern("@web-tier").unwrap_err();
        assert!(e.to_string().contains("unknown host: web-01") || e.to_string().contains("unknown host: web-99"));
    }

    #[test]
    fn warns_on_match_and_include_and_proxycommand() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        let s = dir.path().join("ssh_config");
        write(&h, "");
        write(
            &s,
            r#"
Match exec "true"
    User matched

Include ~/.ssh/conf.d/*

Host legacy
    HostName 10.0.0.1
    ProxyCommand nc -x socks5proxy:1080 %h %p
"#,
        );
        let inv = Inventory::load_from(&h, &s).unwrap();
        assert!(inv.ssh_config_warnings.iter().any(|w| w.contains("Match")));
        assert!(inv.ssh_config_warnings.iter().any(|w| w.contains("Include")));
        assert!(inv
            .ssh_config_warnings
            .iter()
            .any(|w| w.contains("ProxyCommand")));
        // legacy 호스트는 등록됨(다른 directive는 정상 흡수)
        assert!(inv.host("legacy").is_some());
    }

    #[test]
    fn match_block_directives_do_not_leak_to_previous_host() {
        // RFC-005 §4.1 위임 경계: Match 블록은 ssh 프로세스가 평가해야 하므로 aic는
        // Match 라인 이후 다음 Host 라인까지 모든 directive를 건너뛴다. 그렇지 않으면
        // 직전 Host(web-02)에 `User matched`가 잘못 적용된다(실측 버그 회귀 방지).
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        let s = dir.path().join("ssh_config");
        write(&h, "");
        write(
            &s,
            r#"
Host web-02
    HostName 10.0.1.11
    User sre

Match exec "true"
    User matched

Host web-03
    HostName 10.0.1.12
    User real
"#,
        );
        let inv = Inventory::load_from(&h, &s).unwrap();
        assert_eq!(inv.host("web-02").unwrap().user, "sre", "Match 안 User가 web-02에 누설되면 안 됨");
        assert_eq!(inv.host("web-03").unwrap().user, "real", "다음 Host 블록은 정상 적용되어야 함");
    }

    #[test]
    fn host_keyword_with_equals_separator() {
        // ssh_config은 `Key=Value` 형식도 허용
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        let s = dir.path().join("ssh_config");
        write(&h, "");
        write(
            &s,
            r#"
Host=web-01
    HostName=10.0.1.10
    User=sre
    Port=2222
"#,
        );
        let inv = Inventory::load_from(&h, &s).unwrap();
        let e = inv.host("web-01").unwrap();
        assert_eq!(e.hostname, "10.0.1.10");
        assert_eq!(e.user, "sre");
        assert_eq!(e.port, 2222);
    }

    #[test]
    fn options_defaults_and_concurrency_defaults() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(&h, "");
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        assert!(inv.options.ssh_config_import);
        assert_eq!(inv.options.default_host_key_check, "strict");
        assert!(!inv.options.remote_shell_wrap);
        assert_eq!(inv.concurrency.max_parallel, 8);
        assert_eq!(inv.concurrency.per_host_timeout_secs, 30);
        assert_eq!(inv.concurrency.wall_clock_timeout_secs, 300);
    }

    #[test]
    fn host_key_check_parsing() {
        let dir = tempdir().unwrap();
        let h = dir.path().join("hosts.toml");
        write(
            &h,
            r#"
[[hosts]]
name = "web-01"
hostname = "10.0.1.10"
host_key_check = "accept-new"

[[hosts]]
name = "web-02"
hostname = "10.0.1.11"
host_key_check = "strict"
"#,
        );
        let inv = Inventory::load_from(&h, &dir.path().join("none.cfg")).unwrap();
        assert!(matches!(
            inv.host("web-01").unwrap().host_key_check,
            HostKeyCheck::AcceptNew
        ));
        assert!(matches!(
            inv.host("web-02").unwrap().host_key_check,
            HostKeyCheck::Strict
        ));
    }
}
