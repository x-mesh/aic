//! Probe Catalog — 읽기 전용 SRE probe의 단일 출처(catalog).
//!
//! 각 probe는 **shell chain 없이** 단일 bounded Safe 명령이다(필요 시 `| head`로만 제한).
//! 실행은 항상 `run_command::execute_with_corr` 프리미티브를 거쳐 timeout/cap/redaction/
//! audit/correlation을 동일 적용한다. catalog는 `/local`·`/compare`·`/incident`·`/diagnose`·
//! `/triage`가 공유하며, 명령 문자열은 **고정 상수**라 사용자 입력이 섞이지 않는다(injection 안전).

/// 한 probe의 메타데이터 + OS별 bounded 명령.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProbeSpec {
    /// 안정적 식별자(섹션 이름·triage 후보에서 참조).
    pub id: &'static str,
    /// 분류: `system` | `process` | `git` | `docker` | `filesystem` | `k8s`.
    pub category: &'static str,
    /// 자유 태그(triage 매핑·검색 보조).
    pub tags: &'static [&'static str],
    /// 한 줄 설명.
    pub description: &'static str,
    /// Linux 명령(bounded Safe).
    pub linux_command: &'static str,
    /// macOS(및 기타) 명령(bounded Safe). OS 무관이면 linux와 동일.
    pub macos_command: &'static str,
    /// 출력 줄 상한 힌트(자연 bounded면 None). 문서/검증용 메타.
    pub max_lines: Option<usize>,
}

impl ProbeSpec {
    /// 현재 OS에 맞는 명령 문자열을 반환한다.
    pub fn command(&self) -> String {
        if cfg!(target_os = "linux") {
            self.linux_command
        } else {
            self.macos_command
        }
        .to_string()
    }

    /// (id, 명령) 튜플 — 기존 probe API와 호환.
    pub fn resolved(&self) -> (&'static str, String) {
        (self.id, self.command())
    }
}

/// 전체 probe catalog(고정). 순서는 `/local` 섹션 순서를 보존한다.
static CATALOG: &[ProbeSpec] = &[
    ProbeSpec {
        id: "date",
        category: "system",
        tags: &["time"],
        description: "현재 날짜/시간",
        linux_command: "date",
        macos_command: "date",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "host",
        category: "system",
        tags: &["host"],
        description: "hostname",
        linux_command: "hostname",
        macos_command: "hostname",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "os",
        category: "system",
        tags: &["os", "kernel"],
        description: "uname -a (OS/커널)",
        linux_command: "uname -a",
        macos_command: "uname -a",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "uptime",
        category: "system",
        tags: &["load", "cpu"],
        description: "uptime / load average",
        linux_command: "uptime",
        macos_command: "uptime",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "disk",
        category: "system",
        tags: &["disk", "storage"],
        description: "df -h (디스크 사용량)",
        linux_command: "df -h",
        macos_command: "df -h",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "memory",
        category: "system",
        tags: &["memory"],
        description: "메모리 스냅샷",
        linux_command: "free -h",
        macos_command: "top -l 1 | head -n 12",
        max_lines: Some(12),
    },
    ProbeSpec {
        id: "fd",
        category: "system",
        tags: &["fd", "files", "limits"],
        description: "열린 파일 디스크립터 수(현재/최대)",
        // 양 OS 모두 sysctl 사용(절대 경로 인자는 sandbox validator가 거부).
        // Linux: fs.file-nr = "allocated unused max", fs.file-max = 상한.
        // macOS: kern.num_files = 현재, kern.maxfiles = 상한.
        linux_command: "sysctl fs.file-nr fs.file-max",
        macos_command: "sysctl kern.num_files kern.maxfiles",
        max_lines: Some(2),
    },
    ProbeSpec {
        id: "ip",
        category: "system",
        tags: &["network", "ip"],
        description: "네트워크 인터페이스 주소",
        linux_command: "ip -br addr",
        macos_command: "ifconfig | head -n 80",
        max_lines: Some(80),
    },
    ProbeSpec {
        id: "route",
        category: "system",
        tags: &["network", "route"],
        description: "라우팅 테이블",
        linux_command: "ip route | head -n 20",
        macos_command: "netstat -rn | head -n 30",
        max_lines: Some(30),
    },
    ProbeSpec {
        id: "ports",
        category: "system",
        tags: &["network", "ports"],
        description: "LISTEN 중인 포트",
        linux_command: "ss -tunl | head -n 50",
        macos_command: "lsof -nP -iTCP -sTCP:LISTEN | head -n 50",
        max_lines: Some(50),
    },
    ProbeSpec {
        id: "process",
        category: "process",
        tags: &["cpu", "memory", "process"],
        description: "상위 프로세스(ps)",
        linux_command: "ps aux | head -n 20",
        macos_command: "ps aux | head -n 20",
        max_lines: Some(20),
    },
    ProbeSpec {
        id: "git_status",
        category: "git",
        tags: &["git", "build-fail"],
        description: "git status --short",
        linux_command: "git status --short",
        macos_command: "git status --short",
        max_lines: None,
    },
    ProbeSpec {
        id: "git_branch",
        category: "git",
        tags: &["git"],
        description: "현재 git 브랜치",
        linux_command: "git branch --show-current",
        macos_command: "git branch --show-current",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "git_log",
        category: "git",
        tags: &["git"],
        description: "최근 커밋 10개",
        linux_command: "git log -n 10 --oneline",
        macos_command: "git log -n 10 --oneline",
        max_lines: Some(10),
    },
    ProbeSpec {
        id: "git_diff",
        category: "git",
        tags: &["git", "build-fail"],
        description: "git diff --stat",
        linux_command: "git diff --stat",
        macos_command: "git diff --stat",
        max_lines: None,
    },
    // docker: 데몬/설치 의존이라 `/local` 기본 섹션엔 없고(미설치 호스트 노이즈 방지),
    // docker·disk triage/diagnose에서만 선택된다. 모두 읽기 전용(risk_guard docker.read=Safe).
    ProbeSpec {
        id: "docker_df",
        category: "docker",
        tags: &["docker", "disk", "storage"],
        description: "docker 디스크 사용량 요약(images/containers/volumes/build cache)",
        linux_command: "docker system df",
        macos_command: "docker system df",
        max_lines: None,
    },
    ProbeSpec {
        id: "docker_ps",
        category: "docker",
        tags: &["docker", "process", "disk"],
        description: "컨테이너 상태 + writable layer 크기(ps -s)",
        linux_command: "docker ps -s | head -n 30",
        macos_command: "docker ps -s | head -n 30",
        max_lines: Some(30),
    },
    ProbeSpec {
        id: "docker_images",
        category: "docker",
        tags: &["docker", "disk", "images"],
        description: "이미지별 크기(images)",
        linux_command: "docker images | head -n 40",
        macos_command: "docker images | head -n 40",
        max_lines: Some(40),
    },
    // k8s: kubectl 설치 + cluster context 의존이라 `/local` 기본 섹션엔 없고(미설치 노이즈 방지),
    // k8s triage/diagnose에서만 선택된다. 모두 읽기 전용(risk_guard kubectl.read=Safe).
    // STATUS가 Running이 아닌 pod(Pending/CrashLoopBackOff/OOMKilled/Error/ImagePullBackOff)를
    // grep -v Running으로 한 번에 잡는다(따옴표/alternation은 validator가 막으므로 단일 패턴).
    ProbeSpec {
        id: "k8s_pods_notready",
        category: "k8s",
        tags: &["k8s", "kubernetes", "pods", "process"],
        description: "Running이 아닌 pod(Pending/CrashLoop/OOMKilled/Error 등) + RESTARTS 컬럼",
        linux_command: "kubectl get pods -A | grep -v Running | head -n 40",
        macos_command: "kubectl get pods -A | grep -v Running | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "k8s_events_warning",
        category: "k8s",
        tags: &["k8s", "kubernetes", "events"],
        description: "Warning 타입 cluster 이벤트(OOMKilling/FailedScheduling/BackOff 등)",
        linux_command: "kubectl get events -A --field-selector=type=Warning | head -n 40",
        macos_command: "kubectl get events -A --field-selector=type=Warning | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "k8s_nodes",
        category: "k8s",
        tags: &["k8s", "kubernetes", "nodes"],
        description: "노드 상태(Ready/NotReady) + 버전/age",
        linux_command: "kubectl get nodes | head -n 40",
        macos_command: "kubectl get nodes | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "k8s_node_pressure",
        category: "k8s",
        tags: &["k8s", "kubernetes", "nodes", "cpu", "memory"],
        description: "노드별 CPU/메모리 사용량(kubectl top, metrics-server 필요)",
        linux_command: "kubectl top nodes | head -n 20",
        macos_command: "kubectl top nodes | head -n 20",
        max_lines: Some(20),
    },
    // filesystem: 호스트 read-only 진단(절대경로 허용). /tmp 같은 디렉토리의 비대 파일 추적.
    // `/watch tmp_recent`로 시계열 변화(늘어나는 파일)를 관찰할 수 있다.
    ProbeSpec {
        id: "tmp_big",
        category: "filesystem",
        tags: &["disk", "tmp", "files"],
        description: "/tmp의 큰 파일·디렉토리 top 20(du)",
        linux_command: "du -ah /tmp | sort -rh | head -n 20",
        macos_command: "du -ah /tmp | sort -rh | head -n 20",
        max_lines: Some(20),
    },
    ProbeSpec {
        id: "tmp_recent",
        category: "filesystem",
        tags: &["disk", "tmp", "files"],
        description: "/tmp에서 최근 10분 내 수정된 파일(find -mmin)",
        linux_command: "find /tmp -type f -mmin -10 | head -n 30",
        macos_command: "find /tmp -type f -mmin -10 | head -n 30",
        max_lines: Some(30),
    },
    // inode/log/connection/process-state — 용량과 무관한 disk full·로그 누적·연결 폭주·좀비 등
    // 흔한 장애의 "범인"을 짚는 probe. select_probes가 카테고리별로 붙인다.
    ProbeSpec {
        id: "inodes",
        category: "system",
        tags: &["disk", "inode"],
        description: "inode 사용량(df -i) — 용량 남아도 'No space left'면 inode 고갈 의심",
        linux_command: "df -i",
        macos_command: "df -i",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "log_big",
        category: "filesystem",
        tags: &["disk", "log"],
        description: "/var/log의 큰 파일·디렉토리 top 20(du)",
        linux_command: "du -ah /var/log | sort -rh | head -n 20",
        macos_command: "du -ah /var/log | sort -rh | head -n 20",
        max_lines: Some(20),
    },
    ProbeSpec {
        id: "conn_states",
        category: "system",
        tags: &["network", "conn"],
        description: "TCP 연결 상태 요약(established/time_wait 등)",
        linux_command: "ss -s",
        macos_command: "netstat -an | head -n 60",
        max_lines: Some(60),
    },
    ProbeSpec {
        id: "proc_states",
        category: "process",
        tags: &["process", "zombie"],
        description: "프로세스 상태 분포(좀비 Z/대기 등 카운트)",
        linux_command: "ps -eo stat | sort | uniq -c | sort -rn | head -n 15",
        macos_command: "ps -axo stat | sort | uniq -c | sort -rn | head -n 15",
        max_lines: Some(15),
    },
];

/// 전체 catalog 슬라이스.
pub(crate) fn catalog() -> &'static [ProbeSpec] {
    CATALOG
}

/// id로 probe를 찾는다.
pub(crate) fn probe_by_id(id: &str) -> Option<&'static ProbeSpec> {
    catalog().iter().find(|p| p.id == id)
}

/// 지정한 id들을 catalog 순서가 아닌 **요청 순서**로 (id, 명령)으로 해석한다(없는 id는 skip).
pub(crate) fn resolve_ids(ids: &[&str]) -> Vec<(&'static str, String)> {
    ids.iter()
        .filter_map(|id| probe_by_id(id).map(|p| p.resolved()))
        .collect()
}

/// 카테고리별 (id, 명령) 목록.
pub(crate) fn by_category(category: &str) -> Vec<(&'static str, String)> {
    catalog()
        .iter()
        .filter(|p| p.category == category)
        .map(|p| p.resolved())
        .collect()
}

/// `/triage` 한 토픽의 진단 계획(순수). checklist는 읽기 전용 안내, probe_ids는 catalog 후보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TriagePlan {
    /// 사용자가 입력한 원 토픽(라벨 표시용).
    pub label: String,
    /// 매칭된 정규 토픽(unknown은 "generic").
    pub resolved: &'static str,
    /// 사람이 확인할 read-only 체크리스트.
    pub checklist: &'static [&'static str],
    /// 실행 후보 probe id(catalog 참조). `--run` 시 collect로 실행.
    pub probe_ids: &'static [&'static str],
}

/// `/triage` 지원 토픽(자동완성·도움말).
pub(crate) const TRIAGE_TOPICS: &[&str] = &[
    "mac-slow",
    "web",
    "disk",
    "memory",
    "cpu",
    "network",
    "build-fail",
    "docker",
    "k8s",
    "generic",
];

/// 토픽 → 진단 계획. 알 수 없는 토픽은 generic으로 fallback하되 원 라벨을 보존한다.
pub(crate) fn triage_plan(topic: Option<&str>) -> TriagePlan {
    let raw = topic.map(|t| t.trim()).filter(|t| !t.is_empty());
    let key = raw.map(|t| t.to_lowercase());
    let resolved: &'static str = match key.as_deref() {
        Some("mac-slow") => "mac-slow",
        Some("web") => "web",
        Some("disk") => "disk",
        Some("memory") | Some("mem") => "memory",
        Some("cpu") | Some("load") => "cpu",
        Some("network") | Some("net") => "network",
        Some("build-fail") | Some("build") => "build-fail",
        Some("docker") | Some("container") | Some("containers") => "docker",
        Some("k8s") | Some("kubernetes") | Some("kube") | Some("pods") => "k8s",
        _ => "generic",
    };
    let (checklist, probe_ids): (&'static [&str], &'static [&str]) = match resolved {
        "mac-slow" => (
            &[
                "CPU를 많이 쓰는 프로세스가 있는가 (process)",
                "load average가 코어 수보다 높은가 (uptime)",
                "메모리 압박/스왑 여부 (memory)",
                "디스크가 가득 찼는가 (disk)",
            ],
            &["uptime", "process", "memory", "disk"],
        ),
        "cpu" => (
            &["상위 CPU 프로세스 (process)", "load average 추세 (uptime)"],
            &["uptime", "process"],
        ),
        "memory" => (
            &[
                "메모리/스왑 사용량 (memory)",
                "메모리를 많이 쓰는 프로세스 (process)",
            ],
            &["memory", "process", "uptime"],
        ),
        "disk" => (
            &[
                "파티션별 사용률/여유 공간 (disk)",
                "디스크를 점유하는 프로세스 (process)",
                "docker가 디스크를 점유하는가 — images/containers/volumes (docker_df)",
                "/tmp에 큰 파일이 쌓였는가 (tmp_big)",
            ],
            &["disk", "process", "docker_df", "tmp_big"],
        ),
        "docker" => (
            &[
                "docker 전체 디스크 사용량 — images/containers/volumes/build cache (docker_df)",
                "컨테이너별 writable layer 크기 — 비정상 증가 컨테이너 식별 (docker_ps)",
                "이미지별 크기/중복 누적 (docker_images)",
                "(수동) 비대 컨테이너 내부 경로 확인: docker exec <id> du -xh /tmp | sort -rh | head",
                "(수동) 정리: docker image prune / docker system df 확인 후 prune (삭제는 복구 불가)",
            ],
            &["docker_df", "docker_ps", "docker_images"],
        ),
        "k8s" => (
            &[
                "Running이 아닌 pod이 있는가 — Pending/CrashLoop/OOMKilled/Error (k8s_pods_notready)",
                "Warning 이벤트 — FailedScheduling/OOMKilling/BackOff (k8s_events_warning)",
                "NotReady 노드가 있는가 (k8s_nodes)",
                "노드 CPU/메모리 압박 — metrics-server 필요 (k8s_node_pressure)",
                "(수동) 특정 pod 상세: kubectl describe pod <name> -n <ns>",
                "(수동) 로그: kubectl logs <pod> -n <ns> --tail 100",
            ],
            &[
                "k8s_pods_notready",
                "k8s_events_warning",
                "k8s_nodes",
                "k8s_node_pressure",
            ],
        ),
        "network" | "web" => (
            &[
                "인터페이스 주소/링크 상태 (ip)",
                "라우팅 테이블 (route)",
                "LISTEN 포트/충돌 (ports)",
            ],
            &["ip", "route", "ports"],
        ),
        "build-fail" => (
            &[
                "작업 트리 변경/미스테이지 (git_status)",
                "최근 변경 범위 (git_diff)",
                "toolchain/OS 환경 (os)",
                "(수동) 빌드를 verbose로 재실행하고 첫 에러를 확인",
            ],
            &["git_status", "git_diff", "os"],
        ),
        _ => (
            &[
                "기본 시스템 상태 (date/host/os/uptime)",
                "리소스 사용량 (disk/memory)",
            ],
            &["date", "host", "os", "uptime", "disk", "memory"],
        ),
    };
    TriagePlan {
        label: raw.unwrap_or("generic").to_string(),
        resolved,
        checklist,
        probe_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk_guard::{classify, RiskLevel};

    #[test]
    fn catalog_commands_are_safe_bounded_no_egress() {
        for p in catalog() {
            for cmd in [p.linux_command, p.macos_command] {
                // shell chain/메타문자 금지(파이프 `|`만 허용).
                for bad in [';', '&', '$', '`', '>', '<', '\n'] {
                    assert!(!cmd.contains(bad), "probe {} has '{bad}': {cmd}", p.id);
                }
                // risk_guard Safe(자동 실행 가능)여야 한다 = validator 통과 + egress 아님.
                assert_eq!(
                    classify(cmd).level,
                    RiskLevel::Safe,
                    "probe {} not Safe: {cmd}",
                    p.id
                );
                // 명시적 egress 도구가 catalog에 없어야 한다.
                for egress in ["curl", "wget", "nc ", "ssh ", "scp "] {
                    assert!(!cmd.contains(egress), "probe {} has egress: {cmd}", p.id);
                }
            }
        }
    }

    #[test]
    fn catalog_commands_pass_run_command_validator() {
        // 실제 실행 전 검증 경로(run_command::validate_command)도 통과해야 한다 — Safe 분류만이 아니라
        // 메타문자/샌드박스 정책을 포함한 게이트.
        let dir = tempfile::tempdir().unwrap();
        let sb = crate::agent::sandbox::Sandbox::new(dir.path()).unwrap();
        for p in catalog() {
            for cmd in [p.linux_command, p.macos_command] {
                crate::agent::run_command::validate_command(cmd, &sb).unwrap_or_else(|e| {
                    panic!("probe {} command rejected by validator: {cmd} ({e})", p.id)
                });
            }
        }
    }

    /// 명령에서 standalone `-n <num>` 인자(head -n N / git log -n N)의 값을 추출한다.
    fn explicit_line_bound(cmd: &str) -> Option<usize> {
        let toks: Vec<&str> = cmd.split_whitespace().collect();
        toks.iter()
            .position(|t| *t == "-n")
            .and_then(|i| toks.get(i + 1))
            .and_then(|v| v.parse::<usize>().ok())
    }

    #[test]
    fn max_lines_metadata_matches_command_bound() {
        // 명령에 명시적 `-n N` bound가 있으면 max_lines는 OS별 bound의 **최댓값**과 일치해야 한다
        // (드리프트 방지). OS별 bound가 달라도(예: route linux 20 / macos 30) 단일 max_lines가
        // 상한을 정확히 반영하도록 강제한다.
        for p in catalog() {
            let bounds: Vec<usize> = [p.linux_command, p.macos_command]
                .iter()
                .filter_map(|c| explicit_line_bound(c))
                .collect();
            if let Some(&maxb) = bounds.iter().max() {
                assert_eq!(
                    p.max_lines,
                    Some(maxb),
                    "probe {} max_lines={:?} drifts from command bound(max -n {maxb})",
                    p.id,
                    p.max_lines
                );
            }
        }
    }

    #[test]
    fn probe_by_id_and_resolve() {
        assert!(probe_by_id("disk").is_some());
        assert!(probe_by_id("process").is_some());
        assert!(probe_by_id("git_status").is_some());
        assert!(probe_by_id("nope").is_none());
        let r = resolve_ids(&["disk", "nope", "process"]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, "disk");
        assert_eq!(r[1].0, "process");
    }

    #[test]
    fn triage_plan_mapping_and_fallback() {
        assert_eq!(triage_plan(Some("mac-slow")).resolved, "mac-slow");
        assert_eq!(triage_plan(Some("MEM")).resolved, "memory");
        assert_eq!(triage_plan(Some("net")).resolved, "network");
        assert_eq!(triage_plan(Some("web")).resolved, "web");
        assert_eq!(triage_plan(Some("build")).resolved, "build-fail");
        // unknown → generic, 원 라벨 보존.
        let p = triage_plan(Some("kubernetes-meltdown"));
        assert_eq!(p.resolved, "generic");
        assert_eq!(p.label, "kubernetes-meltdown");
        // no topic → generic.
        assert_eq!(triage_plan(None).resolved, "generic");
        // 모든 plan의 probe_ids는 catalog에 존재해야 한다(실행 가능).
        for t in TRIAGE_TOPICS {
            for id in triage_plan(Some(t)).probe_ids {
                assert!(probe_by_id(id).is_some(), "topic {t} → unknown probe {id}");
            }
            assert!(!triage_plan(Some(t)).checklist.is_empty());
        }
    }

    #[test]
    fn git_category_has_readonly_probes() {
        let git = by_category("git");
        assert!(!git.is_empty());
        for (id, cmd) in git {
            assert!(cmd.starts_with("git "), "{id}: {cmd}");
        }
    }
}
