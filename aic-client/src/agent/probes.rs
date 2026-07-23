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
        id: "proc_fd_top",
        category: "process",
        tags: &["fd", "files", "limits", "leak"],
        description: "프로세스별 열린 fd 상위 N(누수 후보)",
        // 위 `fd` 섹션은 **호스트 전역** 합계라, 프로세스 하나가 수만 개를 쥐고 있어도 머신 전체
        // 대비로는 묻힌다(실측: gk watch가 fd 21019인데 호스트는 7% 사용). 그래서 프로세스 축을
        // 따로 둔다.
        //
        // shell이 아니라 aic 서브커맨드를 부르는 이유: probe는 파이프만 허용해(`$`·`;` 금지)
        // `/proc/*/fd`의 프로세스별 집계를 표현할 수 없고, lsof에 기대면 미설치 Linux 호스트에서
        // 섹션이 통째로 빈다. `agent::proc_fd`가 aicd exporter와 **같은 fd 구현**을 공유한다.
        // 이 명령 문자열은 risk_guard가 exact argv로 Safe 판정하므로 인자를 붙이면 즉시 막힌다.
        linux_command: "aic proc-fd-top",
        macos_command: "aic proc-fd-top",
        max_lines: Some(17),
    },
    ProbeSpec {
        id: "proc_changes",
        category: "process",
        tags: &["process", "lifecycle", "churn", "change"],
        description: "최근 프로세스 생성/소멸(aicd 관측 이력)",
        // 다른 process 섹션이 "지금 무엇이 돌고 있나"를 보여주는 것과 달리, 이건 **무엇이 바뀌었나**다.
        // `ps`로는 얻을 수 없다 — 방금 죽은 프로세스는 이미 목록에 없기 때문이다. 변화 이력을 들고
        // 있는 건 aicd(host metrics tick마다 전수 diff)뿐이라, 이 leaf가 IPC로 물어온다.
        //
        // proc_fd_top과 같이 risk_guard가 exact argv로 Safe 판정하므로 인자를 붙이면 즉시 막힌다.
        linux_command: "aic proc-changes",
        macos_command: "aic proc-changes",
        // 헤더 1 + 최대 15행 + 안내 문구 여유.
        max_lines: Some(17),
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
        description: "상위 프로세스(CPU 내림차순)",
        // 정렬 없으면 PID 순 상위 20줄이 전부 커널 스레드(0%)라 폭주 프로세스를 놓친다.
        linux_command: "ps aux --sort=-%cpu | head -n 20",
        macos_command: "ps aux -r | head -n 20",
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
        id: "docker_stats",
        category: "docker",
        tags: &["docker", "cpu", "memory", "process"],
        description: "컨테이너별 실시간 CPU/메모리/IO 사용률(stats --no-stream)",
        // --no-stream: 1회 스냅샷 후 종료(없으면 무한 스트림 → timeout까지 hang).
        linux_command: "docker stats --no-stream | head -n 30",
        macos_command: "docker stats --no-stream | head -n 30",
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
    ProbeSpec {
        id: "docker_volumes",
        category: "docker",
        tags: &["docker", "disk", "volumes"],
        description: "볼륨별 크기·사용 컨테이너(system df -v) — disk full 범인 볼륨 특정",
        linux_command: "docker system df -v | head -n 40",
        macos_command: "docker system df -v | head -n 40",
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
    ProbeSpec {
        id: "k8s_crashloop_pods",
        category: "k8s",
        tags: &["k8s", "kubernetes", "pods", "crashloop"],
        description: "재시작 루프 pod만(Completed 정상 종료 노이즈 제거)",
        linux_command: "kubectl get pods -A | grep -v Running | grep -v Completed | head -n 30",
        macos_command: "kubectl get pods -A | grep -v Running | grep -v Completed | head -n 30",
        max_lines: Some(30),
    },
    ProbeSpec {
        id: "k8s_resource_quota",
        category: "k8s",
        tags: &["k8s", "kubernetes", "quota", "capacity"],
        description: "namespace별 resource quota used/hard — Pending 지속 원인 판별",
        linux_command: "kubectl get resourcequota -A | head -n 30",
        macos_command: "kubectl get resourcequota -A | head -n 30",
        max_lines: Some(30),
    },
    ProbeSpec {
        id: "k8s_hpa_status",
        category: "k8s",
        tags: &["k8s", "kubernetes", "hpa", "autoscaling"],
        description: "HPA replicas vs min/max — 스케일 아웃 실패·상한 도달 식별",
        linux_command: "kubectl get hpa -A | head -n 30",
        macos_command: "kubectl get hpa -A | head -n 30",
        max_lines: Some(30),
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
    ProbeSpec {
        id: "mem_top_proc",
        category: "process",
        tags: &["memory", "process", "oom"],
        description: "RSS 기준 메모리 상위 프로세스 — OOM 직전 범인 특정",
        linux_command: "ps -eo pid,comm,rss --sort=-rss | head -n 15",
        macos_command: "ps -eo pid,comm,rss -m | head -n 15",
        max_lines: Some(15),
    },
    ProbeSpec {
        id: "mem_pressure",
        category: "system",
        tags: &["memory", "oom"],
        description: "메모리 압박 신호(MemAvailable/페이지 상태) — OOM 전조",
        linux_command: "grep Mem /proc/meminfo | head -n 6",
        macos_command: "vm_stat | head -n 15",
        max_lines: Some(15),
    },
    ProbeSpec {
        id: "swap_usage",
        category: "system",
        tags: &["memory", "swap"],
        description: "swap 사용량(total/used/free) — macOS free 부재 보완",
        linux_command: "free -h | grep Swap",
        macos_command: "sysctl -n vm.swapusage",
        max_lines: Some(2),
    },
    ProbeSpec {
        id: "cpu_throttle",
        category: "system",
        tags: &["cpu", "thermal"],
        description: "코어별 현재 클럭(MHz) — thermal throttling 신호(macOS는 명목 최대치)",
        linux_command: "grep MHz /proc/cpuinfo | head -n 8",
        macos_command: "sysctl -n hw.cpufrequency_max",
        max_lines: Some(8),
    },
    ProbeSpec {
        id: "tcp_retrans",
        category: "system",
        tags: &["network", "retrans"],
        description: "TCP 재전송 카운터 — 패킷 로스/네트워크 품질 1차 체크",
        linux_command: "netstat -s | grep -i retrans | head -n 10",
        macos_command: "netstat -s | grep -i retrans | head -n 10",
        max_lines: Some(10),
    },
    // ── SRE 심층 신호(R8) — risk_guard arg-gate로 read-only 보장된 도구. `/local` 기본엔 없고
    // `/diagnose`(카테고리)·`/triage`·`/watch`에서 선택된다. Linux 전용 도구의 macOS 자리는
    // 동등 Safe 명령 또는 무신호 placeholder(echo)로 채운다(미설치 시 'command not found'는
    // docker/k8s probe와 동일하게 진단정보로 수용).
    ProbeSpec {
        id: "journal_errors",
        category: "process",
        tags: &["log", "journal", "error", "process"],
        description: "systemd journal 오늘 에러 로그 50줄(-p err) — 서비스 크래시/panic/OOM 원인",
        linux_command: "journalctl -p err --since today -n 50 --no-pager",
        macos_command: "dmesg | tail -n 50",
        max_lines: Some(50),
    },
    ProbeSpec {
        id: "dmesg_oom",
        category: "system",
        tags: &["memory", "oom", "kernel", "process"],
        description: "커널 ring buffer의 OOM-killer 라인 — '이미 죽인' OOM 결정(사후 분석)",
        linux_command: "dmesg -T | grep -i oom | head -n 30",
        macos_command: "dmesg | grep -i oom | head -n 30",
        max_lines: Some(30),
    },
    ProbeSpec {
        id: "iostat_devices",
        category: "system",
        tags: &["disk", "io", "iostat", "latency"],
        description: "per-device I/O await/%util(iostat) — 디스크가 '꽉 찬게' 아니라 '느린가'(마지막 샘플=현재값)",
        linux_command: "iostat -x 1 2 | head -n 40",
        macos_command: "iostat -d -w 1 -c 2 | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "vmstat_iowait",
        category: "system",
        tags: &["cpu", "io", "iowait", "memory"],
        description: "iowait/run-queue/blocked 분해(vmstat) — high-load가 CPU냐 I/O냐 판별(마지막 샘플=현재값)",
        linux_command: "vmstat 1 3",
        macos_command: "vm_stat",
        max_lines: None,
    },
    ProbeSpec {
        id: "failed_units",
        category: "process",
        tags: &["systemd", "service", "process", "failed"],
        description: "실패한 systemd 유닛(systemctl --failed) — '앱이 안 뜬다'의 1차 신호",
        linux_command: "systemctl --failed --no-pager --no-legend | head -n 40",
        // macOS는 systemd 부재 — 무신호 placeholder(annotation·LLM 오탐 방지).
        macos_command: "echo",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "conntrack_max",
        category: "system",
        tags: &["network", "conntrack", "nat"],
        description: "conntrack count vs max(sysctl) — NAT/k8s 노드 연결추적 테이블 포화",
        linux_command: "sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max",
        macos_command: "sysctl net.inet.ip.maxfragpackets",
        max_lines: Some(2),
    },
    ProbeSpec {
        id: "listen_backlog",
        category: "system",
        tags: &["network", "backlog", "listen", "drop"],
        description: "listen 소켓 accept-queue(ss -tln Recv-Q/Send-Q) — backlog 포화로 SYN 드롭",
        linux_command: "ss -tln | head -n 50",
        macos_command: "netstat -an | grep LISTEN | head -n 50",
        max_lines: Some(50),
    },
    ProbeSpec {
        id: "time_sync",
        category: "system",
        tags: &["time", "ntp", "clock", "sync"],
        description: "NTP 동기/clock skew(timedatectl) — 인증서/TLS/replication 함정의 숨은 원인",
        linux_command: "timedatectl show",
        macos_command: "sysctl -n kern.boottime",
        max_lines: None,
    },
    ProbeSpec {
        id: "block_topology",
        category: "system",
        tags: &["disk", "block", "mount", "ro"],
        description: "블록디바이스/마운트 토폴로지(lsblk) — ro 리마운트·마운트 소실 식별",
        linux_command: "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,RO | head -n 40",
        macos_command: "df -h | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "reboot_history",
        category: "system",
        tags: &["uptime", "reboot", "boot", "history"],
        description: "재부팅/크래시 이력(last reboot) — '어제까지 됐는데'류에서 호스트 재시작 판별",
        linux_command: "last -x reboot | head -n 15",
        macos_command: "last reboot | head -n 15",
        max_lines: Some(15),
    },
    // P1 #7 batch1 — info-only(scan 규칙 없음). sysctl(read)/grep/systemctl list-timers는 이미 risk_guard
    // Safe라 allowlist 변경 0. macOS는 Linux 전용 OID/도구에 'unknown oid'·placeholder로 무해하게 대응(OS-branched).
    ProbeSpec {
        id: "kernel_limits",
        category: "system",
        tags: &["kernel", "sysctl", "limits", "backlog"],
        description: "커널 한계(accept-queue/매핑/PID/파일) — somaxconn·syn_backlog·max_map_count·pid_max 고갈 상한",
        linux_command:
            "sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog vm.max_map_count kernel.pid_max",
        macos_command: "sysctl kern.ipc.somaxconn kern.maxproc kern.maxfilesperproc",
        max_lines: Some(8),
    },
    ProbeSpec {
        id: "cpu_count",
        category: "system",
        tags: &["cpu", "cores", "load"],
        description: "논리 코어 수 — load average를 코어수 대비로 해석하기 위한 컨텍스트",
        linux_command: "grep -c processor /proc/cpuinfo",
        macos_command: "sysctl -n hw.logicalcpu",
        max_lines: Some(1),
    },
    ProbeSpec {
        id: "timer_schedule",
        category: "system",
        tags: &["systemd", "timer", "cron", "schedule"],
        description: "systemd timer 스케줄 상태(NEXT/LAST/PASSED, 전체) — 미실행 백업/로테이션 잡이 디스크/누적 문제의 숨은 원인",
        linux_command: "systemctl list-timers --all --no-pager | head -n 30",
        // macOS는 systemd 부재 — 무신호 placeholder(bare echo). 따옴표는 validator가 차단하므로
        // 메시지 없이 빈 줄만 출력한다(failed_units:450과 동일 패턴, annotation/LLM 오탐 방지). launchctl은 후속.
        macos_command: "echo",
        max_lines: Some(30),
    },
    // P1 #7 batch2 — info-only(scan 규칙 없음). risk_guard에 read-only carve-out arm(pmset -g / launchctl
    // list / crontab -l / scutil --dns)을 추가해 자동 실행 허용. macOS parity·cron·DNS 진단. OS-branched.
    ProbeSpec {
        id: "mac_thermal",
        category: "system",
        tags: &["cpu", "thermal", "throttle", "power"],
        description: "macOS thermal/전력 throttle(pmset -g therm) — CPU_Speed_Limit<100이면 발열 제한 중",
        linux_command: "echo",
        macos_command: "pmset -g therm",
        max_lines: Some(6),
    },
    ProbeSpec {
        id: "cron_jobs",
        category: "system",
        tags: &["cron", "schedule", "jobs"],
        description: "사용자 cron 작업 목록(crontab -l) — systemd timer의 cross-OS 짝, 백업/로테이션 잡 확인",
        linux_command: "crontab -l",
        macos_command: "crontab -l",
        max_lines: None,
    },
    ProbeSpec {
        id: "dns_resolver",
        category: "system",
        tags: &["network", "dns", "resolver"],
        description: "DNS resolver 설정(nameserver/search) — 이름풀이 실패·간헐 지연의 숨은 원인",
        linux_command: "cat /etc/resolv.conf",
        macos_command: "scutil --dns | head -n 40",
        max_lines: Some(40),
    },
    ProbeSpec {
        id: "launchd_failed",
        category: "process",
        tags: &["launchd", "service", "process"],
        description: "macOS launchd 서비스 목록(launchctl list) — failed_units의 macOS 짝(상태 PID/Status/Label)",
        linux_command: "echo",
        macos_command: "launchctl list | head -n 40",
        max_lines: Some(40),
    },
];

/// follow-up 전용 templated probe — 인자 1개를 받는 read-only 명령 템플릿.
///
/// LLM 자유 명령은 금지(council 합의)이고, 타깃 인자가 필요한 진단(특정 컨테이너 로그 등)은
/// 이 템플릿으로만 허용한다. 인자는 (1) `arg_valid` charset(쉘 메타문자 원천 배제) AND
/// (2) 1차 증거에 실존하는 값 — 두 검증을 모두 통과해야 render된다.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FollowupTemplate {
    /// 안정적 식별자(LLM이 fenced block에서 참조).
    pub id: &'static str,
    /// 한 줄 설명(프롬프트 메뉴에 노출, 인자 의미 포함).
    pub description: &'static str,
    /// Linux 명령 템플릿 — `{arg}` 자리에 검증된 인자가 들어간다(bounded).
    pub linux_template: &'static str,
    /// macOS(및 기타) 명령 템플릿. OS 무관이면 linux와 동일.
    pub macos_template: &'static str,
}

impl FollowupTemplate {
    /// 인자 charset 검증 — 첫 글자 영숫자, 이후 영숫자/`_`/`.`/`-`, 길이 1..=64.
    /// 쉘 메타문자·공백·경로 구분자를 원천 배제해 조작된 이름(`$(rm -rf /)` 등)을 거부한다.
    pub fn arg_valid(arg: &str) -> bool {
        let mut chars = arg.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphanumeric() => {}
            _ => return false,
        }
        arg.len() <= 64
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// 현재 OS의 템플릿 문자열.
    fn template(&self) -> &'static str {
        if cfg!(target_os = "linux") {
            self.linux_template
        } else {
            self.macos_template
        }
    }

    /// 검증된 인자로 명령을 만든다. 인자 검증은 호출자 책임(resolve_followup_line).
    pub fn render(&self, arg: &str) -> String {
        self.template().replace("{arg}", arg)
    }
}

/// follow-up 템플릿 catalog(고정 상수). 전부 read-only·risk_guard Safe·인자 1개.
/// describe류는 핵심 정보(Events)가 출력 끝에 있어 head를 걸지 않는다 —
/// 출력은 run_command 64KB cap + follow-up 합산 16KB 예산이 bound한다.
pub(crate) static FOLLOWUP_TEMPLATES: &[FollowupTemplate] = &[
    FollowupTemplate {
        id: "docker_logs",
        description: "특정 컨테이너의 최근 로그 100줄 — 인자: 컨테이너 이름",
        linux_template: "docker logs --tail 100 {arg}",
        macos_template: "docker logs --tail 100 {arg}",
    },
    FollowupTemplate {
        id: "docker_logs_since",
        description: "특정 컨테이너의 최근 5분 로그(시간 기준 슬라이스) — 인자: 컨테이너 이름",
        linux_template: "docker logs --since 5m {arg} | head -n 120",
        macos_template: "docker logs --since 5m {arg} | head -n 120",
    },
    FollowupTemplate {
        id: "docker_inspect_container",
        description: "컨테이너 상세(RestartPolicy/OOMKilled/HealthCheck/마운트) — 인자: 컨테이너 이름",
        linux_template: "docker inspect {arg} | head -n 120",
        macos_template: "docker inspect {arg} | head -n 120",
    },
    FollowupTemplate {
        id: "docker_health",
        description: "컨테이너 헬스체크 상태/연속 실패 횟수만 추출 — 인자: 컨테이너 이름",
        linux_template: "docker inspect {arg} | grep -A 5 Health",
        macos_template: "docker inspect {arg} | grep -A 5 Health",
    },
    FollowupTemplate {
        id: "k8s_pod_describe",
        description: "pod 상세(Events/exit code/limits) — 인자: pod 이름",
        linux_template: "kubectl describe pod {arg}",
        macos_template: "kubectl describe pod {arg}",
    },
    FollowupTemplate {
        id: "k8s_pod_logs",
        description: "pod 최근 로그 50줄 — 인자: pod 이름",
        linux_template: "kubectl logs {arg} --tail=50",
        macos_template: "kubectl logs {arg} --tail=50",
    },
    FollowupTemplate {
        id: "k8s_node_describe",
        description: "노드 상세(Conditions/Taints/Allocatable) — 인자: 노드 이름",
        linux_template: "kubectl describe node {arg}",
        macos_template: "kubectl describe node {arg}",
    },
    FollowupTemplate {
        id: "proc_fd",
        description: "특정 프로세스의 열린 FD 수(fd leak 범인 특정) — 인자: PID",
        linux_template: "lsof -p {arg} | wc -l",
        macos_template: "lsof -p {arg} | wc -l",
    },
    FollowupTemplate {
        id: "proc_net",
        // 인자 게이트는 whole-token 매칭이라 증거에 공백 토큰으로 나타나는 프로세스명만 실제로 통과한다.
        // 포트는 보통 `*:8500`처럼 콜론에 붙어 나와 bare 숫자가 증거에 없으므로 fail-closed(안전 거부)된다.
        description: "특정 프로세스의 활성 TCP 연결(상대 IP 포함) — 인자: 프로세스명(증거에 토큰으로 등장한 값)",
        linux_template: "ss -tnp | grep {arg} | head -n 30",
        macos_template: "lsof -nP -iTCP -sTCP:ESTABLISHED | grep {arg} | head -n 30",
    },
    FollowupTemplate {
        id: "journal_unit",
        description: "특정 systemd unit의 최근 에러 로그 50줄 — 인자: unit 이름(failed_units→이 체인)",
        linux_template: "journalctl -u {arg} -p err -n 50 --no-pager",
        macos_template: "dmesg | grep {arg} | head -n 50",
    },
];

/// id로 follow-up 템플릿을 찾는다.
pub(crate) fn template_by_id(id: &str) -> Option<&'static FollowupTemplate> {
    FOLLOWUP_TEMPLATES.iter().find(|t| t.id == id)
}

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
            &[
                "상위 CPU 프로세스 (process)",
                "load average 추세 (uptime)",
                "iowait/run-queue 분해 — high-load가 CPU냐 I/O냐 (vmstat_iowait)",
                "thermal throttling — 코어별 클럭 저하 (cpu_throttle)",
            ],
            &["uptime", "process", "vmstat_iowait", "cpu_throttle"],
        ),
        "memory" => (
            &[
                "메모리/스왑 사용량 (memory, swap_usage)",
                "RSS 상위 프로세스 — OOM 범인 (mem_top_proc)",
                "메모리 압박 전조 (mem_pressure)",
                "커널 OOM-killer 발생 이력 — 이미 죽인 결정 (dmesg_oom)",
            ],
            &["memory", "mem_top_proc", "mem_pressure", "dmesg_oom", "swap_usage", "uptime"],
        ),
        "disk" => (
            &[
                "파티션별 사용률/여유 공간 (disk)",
                "per-device I/O await/%util — 꽉 찬게 아니라 느린가 (iostat_devices)",
                "블록디바이스/ro 리마운트·마운트 소실 (block_topology)",
                "디스크를 점유하는 프로세스 (process)",
                "docker가 디스크를 점유하는가 — images/containers/volumes (docker_df)",
                "/tmp에 큰 파일이 쌓였는가 (tmp_big)",
            ],
            &["disk", "iostat_devices", "block_topology", "process", "docker_df", "tmp_big"],
        ),
        "docker" => (
            &[
                "컨테이너별 실시간 CPU/메모리/IO — 폭주 컨테이너 식별 (docker_stats)",
                "docker 전체 디스크 사용량 — images/containers/volumes/build cache (docker_df)",
                "볼륨별 크기·사용 컨테이너 — 범인 볼륨 (docker_volumes)",
                "컨테이너별 writable layer 크기 — 비정상 증가 컨테이너 식별 (docker_ps)",
                "이미지별 크기/중복 누적 (docker_images)",
                "(수동) 비대 컨테이너 내부 경로 확인: docker exec <id> du -xh /tmp | sort -rh | head",
                "(수동) 정리: docker image prune / docker system df 확인 후 prune (삭제는 복구 불가)",
            ],
            &["docker_stats", "docker_df", "docker_volumes", "docker_ps", "docker_images"],
        ),
        "k8s" => (
            &[
                "Running이 아닌 pod이 있는가 — Pending/CrashLoop/OOMKilled/Error (k8s_pods_notready)",
                "재시작 루프 pod — Completed 노이즈 제거 (k8s_crashloop_pods)",
                "Warning 이벤트 — FailedScheduling/OOMKilling/BackOff (k8s_events_warning)",
                "NotReady 노드가 있는가 (k8s_nodes)",
                "노드 CPU/메모리 압박 — metrics-server 필요 (k8s_node_pressure)",
                "quota 한도 초과 — Pending 원인 (k8s_resource_quota)",
                "HPA 스케일 상한 도달 (k8s_hpa_status)",
                "(수동) 특정 pod 상세: kubectl describe pod <name> -n <ns>",
                "(수동) 로그: kubectl logs <pod> -n <ns> --tail 100",
            ],
            &[
                "k8s_pods_notready",
                "k8s_crashloop_pods",
                "k8s_events_warning",
                "k8s_nodes",
                "k8s_node_pressure",
                "k8s_resource_quota",
                "k8s_hpa_status",
            ],
        ),
        "network" | "web" => (
            &[
                "인터페이스 주소/링크 상태 (ip)",
                "라우팅 테이블 (route)",
                "LISTEN 포트/충돌 (ports)",
                "listen accept-queue/backlog 포화 — SYN 드롭 (listen_backlog)",
                "conntrack 테이블 포화 — NAT/k8s 노드 (conntrack_max)",
                "TCP 재전송 — 패킷 로스 신호 (tcp_retrans)",
            ],
            &["ip", "route", "ports", "listen_backlog", "conntrack_max", "tcp_retrans"],
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
                "실패한 systemd 유닛 — 앱이 안 뜨는가 (failed_units)",
                "최근 재부팅/크래시 이력 (reboot_history)",
            ],
            &["date", "host", "os", "uptime", "disk", "memory", "failed_units", "reboot_history"],
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
    fn followup_templates_render_safe_and_reject_malicious_args() {
        // 유효 인자로 render한 명령은 catalog probe와 동일한 불변식(Safe + validator 통과)을 지켜야 한다.
        let dir = tempfile::tempdir().unwrap();
        let sb = crate::agent::sandbox::Sandbox::new(dir.path()).unwrap();
        for t in FOLLOWUP_TEMPLATES {
            let cmd = t.render("lib-mesh-acl-sync");
            assert_eq!(classify(&cmd).level, RiskLevel::Safe, "{}: {cmd}", t.id);
            crate::agent::run_command::validate_command(&cmd, &sb)
                .unwrap_or_else(|e| panic!("{}: validator 거부 {cmd} ({e})", t.id));
        }
        // 조작된 인자는 charset에서 원천 거부(쉘 메타문자·공백·경로·과길이).
        for bad in [
            "$(rm -rf /)",
            "a;b",
            "a b",
            "../etc",
            "/etc/shadow",
            "-rf",
            "",
            "name`id`",
            &"x".repeat(65),
        ] {
            assert!(!FollowupTemplate::arg_valid(bad), "통과되면 안 됨: {bad:?}");
        }
        for good in ["web1", "lib-mesh-acl-sync", "app_2.prod"] {
            assert!(FollowupTemplate::arg_valid(good), "거부되면 안 됨: {good}");
        }
        assert!(template_by_id("docker_logs").is_some());
        assert!(template_by_id("nope").is_none());
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
