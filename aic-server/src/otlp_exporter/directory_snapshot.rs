use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use super::{logs_proto, ExporterConfig, SignalKind};

const INTERVAL: Duration = Duration::from_secs(30 * 60);
const TIME_LIMIT: Duration = Duration::from_secs(5);
const REAP_LIMIT: Duration = Duration::from_secs(1);
const TOP_COUNT: usize = 20;
const REPORT_DEPTH: usize = 3;
const TRAVERSAL_DEPTH: usize = 64;
const MAX_ENTRIES: usize = 100_000;
const MAX_MOUNTS: usize = 32;
const MAX_PATH_BYTES: usize = 1024;
const MAX_FRAME_BYTES: u64 = 256 * 1024;
const PROGRESS_ENTRIES: usize = 256;
const BLOCK_BYTES: u64 = 512;

#[derive(Deserialize, Serialize)]
struct MountInventory {
    mounts: Vec<(PathBuf, bool)>,
    truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryUsage {
    path: String,
    depth: usize,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Snapshot {
    version: u32,
    snapshot_id: String,
    mount: String,
    entries: Vec<DirectoryUsage>,
    truncated: bool,
    reasons: BTreeSet<String>,
    visited_entries: usize,
    duration_ms: u64,
}

impl Snapshot {
    fn empty(mount: &Path) -> Self {
        Self {
            version: 1,
            snapshot_id: String::new(),
            mount: mount.to_string_lossy().into_owned(),
            entries: Vec::new(),
            truncated: false,
            reasons: BTreeSet::new(),
            visited_entries: 0,
            duration_ms: 0,
        }
    }

    fn incomplete(&mut self, reason: &str) {
        self.truncated = true;
        self.reasons.insert(reason.to_string());
    }
}

struct Scan {
    snapshot: Snapshot,
    usage: BTreeMap<PathBuf, u64>,
    inodes: HashSet<(u64, u64)>,
    mounts: HashSet<PathBuf>,
    root: PathBuf,
    device: u64,
    started: Instant,
    entry_limit: usize,
    time_limit: Duration,
}

impl Scan {
    fn new(root: &Path, mounts: HashSet<PathBuf>) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            snapshot: Snapshot::empty(root),
            usage: BTreeMap::new(),
            inodes: HashSet::new(),
            mounts,
            root: root.to_path_buf(),
            device: metadata.dev(),
            started: Instant::now(),
            entry_limit: MAX_ENTRIES,
            time_limit: TIME_LIMIT,
        })
    }

    fn limited(&mut self) -> bool {
        if self.snapshot.visited_entries >= self.entry_limit {
            self.snapshot.incomplete("entry_limit");
            return true;
        }
        if self.started.elapsed() >= self.time_limit {
            self.snapshot.incomplete("timeout");
            return true;
        }
        false
    }

    fn walk(&mut self, path: &Path, depth: usize, output: &mut impl Write) -> io::Result<()> {
        if self.limited() {
            return Ok(());
        }
        self.snapshot.visited_entries += 1;
        if path.as_os_str().len() > MAX_PATH_BYTES {
            self.snapshot.incomplete("path_limit");
            return Ok(());
        }
        if depth > 0 && excluded(path) {
            self.snapshot.incomplete("excluded_path");
            return Ok(());
        }
        if depth > 0 && self.mounts.contains(path) {
            return Ok(());
        }
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.snapshot.incomplete(io_reason(&error));
                return Ok(());
            }
        };
        if metadata.dev() != self.device || !self.inodes.insert((metadata.dev(), metadata.ino())) {
            return Ok(());
        }
        let is_dir = metadata.is_dir();
        if is_dir && depth > 0 && depth <= REPORT_DEPTH {
            self.usage.entry(path.to_path_buf()).or_default();
        }
        let bytes = metadata.blocks().saturating_mul(BLOCK_BYTES);
        for ancestor in path.ancestors() {
            if let Some(total) = self.usage.get_mut(ancestor) {
                *total = total.saturating_add(bytes);
            }
            if ancestor == self.root {
                break;
            }
        }
        if self
            .snapshot
            .visited_entries
            .is_multiple_of(PROGRESS_ENTRIES)
        {
            self.emit(output)?;
        }
        if !is_dir {
            return Ok(());
        }
        if depth >= TRAVERSAL_DEPTH {
            self.snapshot.incomplete("depth_limit");
            return Ok(());
        }
        let children = match std::fs::read_dir(path) {
            Ok(children) => children,
            Err(error) => {
                self.snapshot.incomplete(io_reason(&error));
                return Ok(());
            }
        };
        for child in children {
            if self.limited() {
                break;
            }
            match child {
                Ok(child) => self.walk(&child.path(), depth + 1, output)?,
                Err(error) => self.snapshot.incomplete(io_reason(&error)),
            }
        }
        Ok(())
    }

    fn emit(&mut self, output: &mut impl Write) -> io::Result<()> {
        let mut entries: Vec<_> = self
            .usage
            .iter()
            .map(|(path, &bytes)| DirectoryUsage {
                path: path.to_string_lossy().into_owned(),
                depth: path
                    .strip_prefix(&self.root)
                    .map_or(0, |path| path.components().count()),
                bytes,
            })
            .collect();
        entries.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
        entries.truncate(TOP_COUNT);
        self.snapshot.entries = entries;
        self.snapshot.duration_ms = self.started.elapsed().as_millis() as u64;
        serde_json::to_writer(&mut *output, &self.snapshot)?;
        output.write_all(b"\n")?;
        output.flush()
    }
}

fn excluded(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".ssh" | ".aws" | ".gnupg" | ".kube" | "credentials" | "secrets"
            ) || name == ".env"
                || name.starts_with(".env.")
                || name.ends_with(".pem")
                || name.ends_with(".key")
        })
}

fn io_reason(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NotFound => "disappeared",
        _ => "io_error",
    }
}

pub fn worker_main(mount: &Path) -> anyhow::Result<()> {
    let mut output = io::stdout().lock();
    if excluded(mount) {
        let mut snapshot = Snapshot::empty(mount);
        snapshot.incomplete("excluded_path");
        serde_json::to_writer(&mut output, &snapshot)?;
        output.write_all(b"\n")?;
        return Ok(());
    }
    serde_json::to_writer(&mut output, &Snapshot::empty(mount))?;
    output.write_all(b"\n")?;
    output.flush()?;
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mounts = disks
        .iter()
        .map(|disk| disk.mount_point().to_path_buf())
        .collect();
    scan_mount(mount, mounts, &mut output)?;
    Ok(())
}

fn scan_mount(mount: &Path, mounts: HashSet<PathBuf>, output: &mut impl Write) -> io::Result<()> {
    let mut scan = match Scan::new(mount, mounts) {
        Ok(scan) => scan,
        Err(error) => {
            let mut snapshot = Snapshot::empty(mount);
            snapshot.incomplete(io_reason(&error));
            serde_json::to_writer(&mut *output, &snapshot)?;
            output.write_all(b"\n")?;
            return output.flush();
        }
    };
    scan.emit(output)?;
    scan.walk(mount, 0, output)?;
    scan.emit(output)?;
    Ok(())
}

async fn collect_worker(
    mut command: Command,
    mount: &Path,
    limit: Duration,
) -> anyhow::Result<Snapshot> {
    let started = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("snapshot worker stdout missing"))?;
    let mut reader = BufReader::new(stdout);
    let mut snapshot = Snapshot::empty(mount);
    let read = async {
        loop {
            let mut frame = Vec::new();
            let count = (&mut reader)
                .take(MAX_FRAME_BYTES)
                .read_until(b'\n', &mut frame)
                .await?;
            if count == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            anyhow::ensure!(
                count < MAX_FRAME_BYTES as usize && frame.last() == Some(&b'\n'),
                "snapshot worker frame exceeds limit"
            );
            let progress: Snapshot = serde_json::from_slice(&frame)?;
            anyhow::ensure!(
                progress.mount == snapshot.mount && progress.entries.len() <= TOP_COUNT,
                "invalid snapshot worker result"
            );
            snapshot = progress;
        }
    };
    let mut timeout_kill_requested = false;
    match tokio::time::timeout(limit, read).await {
        Err(_) => {
            snapshot.incomplete("timeout");
            if child.try_wait()?.is_none() {
                child.start_kill()?;
                timeout_kill_requested = true;
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "snapshot worker output failed");
            snapshot.incomplete("worker_error");
            child.start_kill()?;
        }
        Ok(Ok(())) => {}
    }
    match tokio::time::timeout(REAP_LIMIT, child.wait()).await {
        Ok(Ok(status)) if status.success() => {}
        Ok(Ok(status)) if timeout_kill_requested && status.signal() == Some(libc::SIGKILL) => {}
        Ok(Ok(_)) => snapshot.incomplete("worker_error"),
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            snapshot.incomplete("reap_timeout");
            child.start_kill()?;
        }
    }
    snapshot.duration_ms = started.elapsed().as_millis() as u64;
    snapshot.snapshot_id = format!("{}-{}", std::process::id(), super::unix_nanos_now());
    Ok(snapshot)
}

fn encode_snapshot(
    snapshot: &Snapshot,
    resource: &logs_proto::ResourceAttrs<'_>,
    version: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut snapshot = snapshot.clone();
    // Redact labels before JSON serialization so replacements cannot consume JSON delimiters.
    snapshot.mount = aic_common::redaction::redact(&snapshot.mount).0;
    for entry in &mut snapshot.entries {
        entry.path = aic_common::redaction::redact(&entry.path).0;
    }
    let state = serde_json::to_string(&snapshot)?;
    let record_id = format!("fs_snapshot:{}:{}", snapshot.snapshot_id, snapshot.mount);
    let summary = format!(
        "Directory usage snapshot: {} entries, truncated={}",
        snapshot.entries.len(),
        snapshot.truncated
    );
    let change = logs_proto::ChangeEntry {
        change_type: "filesystem",
        subject: &snapshot.mount,
        action: "fs_snapshot",
        prev_state: None,
        new_state: Some(&state),
        confidence: if snapshot.truncated {
            "degraded"
        } else {
            "observed"
        },
        source: "collector:directory_snapshot",
        record_id: &record_id,
        summary: &summary,
    };
    let body = logs_proto::encode_changes(&[change], resource, version, super::unix_nanos_now());
    Ok(body)
}

fn local_filesystem(fs: &str) -> bool {
    matches!(
        fs,
        "apfs"
            | "hfs"
            | "hfs+"
            | "ext2"
            | "ext3"
            | "ext4"
            | "xfs"
            | "btrfs"
            | "zfs"
            | "tmpfs"
            | "overlay"
            | "ufs"
    )
}

pub fn mounts_worker_main() -> anyhow::Result<()> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mounts: BTreeMap<_, _> = disks
        .iter()
        .map(|disk| {
            (
                disk.mount_point().to_path_buf(),
                local_filesystem(&disk.file_system().to_string_lossy().to_ascii_lowercase()),
            )
        })
        .collect();
    let inventory = MountInventory {
        truncated: mounts.len() > MAX_MOUNTS,
        mounts: mounts.into_iter().take(MAX_MOUNTS).collect(),
    };
    serde_json::to_writer(io::stdout().lock(), &inventory)?;
    Ok(())
}

pub async fn serve(cfg: ExporterConfig, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let executable = std::env::current_exe()?;
    serve_with_executable(cfg, shutdown, &executable).await
}

async fn serve_with_executable(
    cfg: ExporterConfig,
    mut shutdown: watch::Receiver<bool>,
    executable: &Path,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(super::HTTP_TIMEOUT)
        .build()?;
    let mut ticker = tokio::time::interval(INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = ticker.tick() => {}
        }
        let mut discovery = Command::new(executable);
        discovery
            .arg("--directory-snapshot-mounts-worker")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            result = tokio::time::timeout(TIME_LIMIT, discovery.output()) => result??,
        };
        anyhow::ensure!(output.status.success(), "snapshot mount discovery failed");
        let inventory: MountInventory = serde_json::from_slice(&output.stdout)?;
        anyhow::ensure!(
            inventory.mounts.len() <= MAX_MOUNTS,
            "snapshot mount inventory exceeds limit"
        );
        let host_name = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
        let host_id = super::host_metrics::host_id(&host_name);
        let resource = logs_proto::ResourceAttrs {
            host_name: &host_name,
            host_id: &host_id,
            os_type: std::env::consts::OS,
            host_ip: None,
        };
        for (mount, eligible) in inventory.mounts {
            let mut command = Command::new(executable);
            command.arg("--directory-snapshot-worker").arg(&mount);
            let collected = if eligible {
                tokio::select! {
                    _ = shutdown.changed() => return Ok(()),
                    result = collect_worker(command, &mount, TIME_LIMIT) => result,
                }
            } else {
                let mut snapshot = Snapshot::empty(&mount);
                snapshot.incomplete("excluded_filesystem");
                snapshot.snapshot_id =
                    format!("{}-{}", std::process::id(), super::unix_nanos_now());
                Ok(snapshot)
            };
            let mut snapshot = match collected {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(%error, mount = %mount.display(), "directory snapshot worker failed");
                    let mut snapshot = Snapshot::empty(&mount);
                    snapshot.incomplete("worker_error");
                    snapshot.snapshot_id =
                        format!("{}-{}", std::process::id(), super::unix_nanos_now());
                    snapshot
                }
            };
            if inventory.truncated {
                snapshot.incomplete("mount_limit");
            }
            let body = encode_snapshot(&snapshot, &resource, &cfg.service_version)?;
            let token = cfg
                .live
                .as_ref()
                .map_or_else(|| cfg.token.clone(), |live| live.token());
            match super::push_logs(
                &client,
                &super::logs_url(&cfg.endpoint),
                token.as_deref(),
                body.clone(),
            )
            .await
            {
                Ok(rejected) => {
                    cfg.drop_counters
                        .by_collector_dropped
                        .fetch_add(rejected, std::sync::atomic::Ordering::Relaxed);
                    if rejected > 0 {
                        tracing::warn!(rejected, "collector rejected directory snapshot");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "directory snapshot push failed; spooling");
                    cfg.spool.append(SignalKind::Logs, &body)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn scan_counts_allocated_bytes_and_does_not_follow_links_or_mounts() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("a");
        std::fs::create_dir(&child).unwrap();
        let file = child.join("data");
        std::fs::write(&file, vec![1; 8192]).unwrap();
        std::fs::hard_link(&file, child.join("hardlink")).unwrap();
        std::os::unix::fs::symlink(&child, root.path().join("link")).unwrap();
        let mount = root.path().join("other_mount");
        std::fs::create_dir(&mount).unwrap();
        std::fs::write(mount.join("other"), vec![2; 8192]).unwrap();
        let mut scan = Scan::new(root.path(), [mount].into()).unwrap();
        scan.walk(root.path(), 0, &mut Vec::new()).unwrap();
        scan.emit(&mut Vec::new()).unwrap();
        assert!(!scan.snapshot.truncated);
        assert_eq!(scan.snapshot.entries.len(), 1);
        let expected = std::fs::metadata(&child).unwrap().blocks() * BLOCK_BYTES
            + std::fs::metadata(file).unwrap().blocks() * BLOCK_BYTES;
        assert_eq!(scan.snapshot.entries[0].bytes, expected);
    }

    #[test]
    fn report_depth_and_top_count_are_bounded() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..25 {
            std::fs::create_dir_all(root.path().join(i.to_string()).join("b/c/d")).unwrap();
        }
        let mut scan = Scan::new(root.path(), HashSet::new()).unwrap();
        scan.walk(root.path(), 0, &mut Vec::new()).unwrap();
        scan.emit(&mut Vec::new()).unwrap();
        assert_eq!(scan.snapshot.entries.len(), TOP_COUNT);
        assert!(scan
            .snapshot
            .entries
            .iter()
            .all(|entry| entry.depth <= REPORT_DEPTH));
    }

    #[test]
    fn limits_and_exclusions_are_visible() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".ssh")).unwrap();
        let mut scan = Scan::new(root.path(), HashSet::new()).unwrap();
        scan.walk(root.path(), 0, &mut Vec::new()).unwrap();
        assert!(scan.snapshot.reasons.contains("excluded_path"));
        let mut scan = Scan::new(root.path(), HashSet::new()).unwrap();
        scan.entry_limit = 1;
        scan.walk(root.path(), 0, &mut Vec::new()).unwrap();
        assert!(scan.snapshot.reasons.contains("entry_limit"));
        let mut scan = Scan::new(root.path(), HashSet::new()).unwrap();
        scan.time_limit = Duration::ZERO;
        scan.walk(root.path(), 0, &mut Vec::new()).unwrap();
        assert!(scan.snapshot.reasons.contains("timeout"));
        assert_eq!(
            io_reason(&io::ErrorKind::PermissionDenied.into()),
            "permission_denied"
        );
    }

    #[tokio::test]
    async fn timeout_retains_progress_and_kills_worker() {
        let mount = Path::new("/test");
        let mut snapshot = Snapshot::empty(mount);
        snapshot.entries.push(DirectoryUsage {
            path: "/test/a".to_string(),
            depth: 1,
            bytes: 123,
        });
        let frame = serde_json::to_string(&snapshot).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '%s\\n' \"$1\"; exec sleep 30", "test", &frame]);
        let result = collect_worker(command, mount, Duration::from_millis(100))
            .await
            .unwrap();
        assert!(result.truncated);
        assert!(result.reasons.contains("timeout"));
        assert!(!result.reasons.contains("worker_error"));
        assert_eq!(result.entries[0].bytes, 123);
        assert!(result.duration_ms < 2000);
    }

    #[test]
    fn snapshot_contract_roundtrips_through_existing_changes_scope() {
        let mut snapshot = Snapshot::empty(Path::new("/data"));
        snapshot.snapshot_id = "fixture-1".to_string();
        snapshot.entries.push(DirectoryUsage {
            path: "/data/logs".to_string(),
            depth: 1,
            bytes: 4096,
        });
        snapshot.entries.push(DirectoryUsage {
            path: "/data/postgres://user:pass@host".to_string(),
            depth: 1,
            bytes: 1024,
        });
        snapshot.incomplete("permission_denied");
        let resource = logs_proto::ResourceAttrs {
            host_name: "test",
            host_id: "test",
            os_type: "linux",
            host_ip: None,
        };
        let bytes = encode_snapshot(&snapshot, &resource, "test").unwrap();
        let request = logs_proto::ExportLogsServiceRequest::decode(bytes.as_slice()).unwrap();
        let scope = &request.resource_logs[0].scope_logs[0];
        assert_eq!(scope.scope.as_ref().unwrap().name, "aic.changes");
        let attrs = &scope.log_records[0].attributes;
        let string = |key| {
            attrs
                .iter()
                .find(|attr| attr.key == key)
                .and_then(|attr| attr.value.as_ref())
                .and_then(|value| match value.value.as_ref() {
                    Some(logs_proto::AnyValueOneof::StringValue(value)) => Some(value.as_str()),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(string("aic.change.action"), "fs_snapshot");
        assert_eq!(string("aic.change.type"), "filesystem");
        assert_eq!(string("aic.change.confidence"), "degraded");
        let decoded: Snapshot = serde_json::from_str(string("aic.change.new_state")).unwrap();
        assert_eq!(decoded.entries[0].bytes, 4096);
        assert!(decoded.entries[1].path.contains("[REDACTED:conn_string]"));
        assert!(!string("aic.change.new_state").contains("user:pass"));
        assert!(decoded.truncated);
        assert!(decoded.reasons.contains("permission_denied"));
    }

    #[tokio::test]
    async fn malformed_worker_output_is_visible() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'invalid\\n'"]);
        let result = collect_worker(command, Path::new("/test"), TIME_LIMIT)
            .await
            .unwrap();
        assert!(result.truncated);
        assert!(result.reasons.contains("worker_error"));
        assert!(result.entries.is_empty());
    }

    #[test]
    fn startup_errors_have_structured_reasons() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"fixture").unwrap();
        for (path, reason) in [
            (root.path().join("missing"), "disappeared"),
            (file, "io_error"),
        ] {
            let mut output = Vec::new();
            scan_mount(&path, HashSet::new(), &mut output).unwrap();
            let snapshot: Snapshot = serde_json::from_slice(
                output
                    .split(|&byte| byte == b'\n')
                    .rfind(|frame| !frame.is_empty())
                    .unwrap(),
            )
            .unwrap();
            assert!(snapshot.truncated);
            assert!(snapshot.reasons.contains(reason));
            assert!(!snapshot.reasons.contains("worker_error"));
            assert!(snapshot.entries.is_empty());
        }
    }

    #[test]
    fn startup_permission_failure_is_structured() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid only reads the caller identity.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("blocked");
        let mount = parent.join("mount");
        std::fs::create_dir_all(&mount).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o0)).unwrap();
        let mut output = Vec::new();
        let result = scan_mount(&mount, HashSet::new(), &mut output);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        let snapshot: Snapshot = serde_json::from_slice(&output).unwrap();
        assert!(snapshot.truncated);
        assert!(snapshot.reasons.contains("permission_denied"));
        assert!(!snapshot.reasons.contains("worker_error"));
    }

    #[tokio::test]
    async fn actual_worker_failure_and_external_signals_remain_errors() {
        for script in ["exit 7", "kill -TERM $$", "kill -KILL $$"] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let snapshot = collect_worker(command, Path::new("/test"), TIME_LIMIT)
                .await
                .unwrap();
            assert!(snapshot.reasons.contains("worker_error"), "{script}");
            assert!(!snapshot.reasons.contains("timeout"), "{script}");
        }
    }

    #[tokio::test]
    async fn timeout_does_not_hide_prior_worker_failure_or_external_sigkill() {
        for script in ["sleep 0.3 & exit 7", "sleep 0.3 & kill -KILL $$"] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let snapshot = collect_worker(command, Path::new("/test"), Duration::from_millis(100))
                .await
                .unwrap();
            assert!(snapshot.reasons.contains("timeout"), "{script}");
            assert!(snapshot.reasons.contains("worker_error"), "{script}");
        }
    }

    #[test]
    fn denied_directory_marks_partial_result() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let denied = root.path().join("denied");
        std::fs::create_dir(&denied).unwrap();
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o0)).unwrap();
        let mut scan = Scan::new(root.path(), HashSet::new()).unwrap();
        let result = scan.walk(root.path(), 0, &mut Vec::new());
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        // SAFETY: geteuid reads the caller identity without pointer arguments or side effects.
        if unsafe { libc::geteuid() } != 0 {
            assert!(scan.snapshot.truncated);
            assert!(scan.snapshot.reasons.contains("permission_denied"));
        }
    }

    #[tokio::test]
    async fn snapshot_exporter_posts_logs_and_spools_http_failure() {
        use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        use tokio::sync::mpsc;

        for reject in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("worker");
            std::fs::write(&executable, concat!(
                "#!/bin/sh\ncase \"$1\" in\n",
                "--directory-snapshot-mounts-worker) printf '%s\\n' '{\"mounts\":[[\"/test\",true]],\"truncated\":false}' ;;\n",
                "--directory-snapshot-worker) printf '%s\\n' '{\"version\":1,\"snapshot_id\":\"\",\"mount\":\"/test\",\"entries\":[{\"path\":\"/test/logs\",\"depth\":1,\"bytes\":4096}],\"truncated\":false,\"reasons\":[],\"visited_entries\":2,\"duration_ms\":1}' ;;\n",
                "*) exit 64 ;;\nesac\n",
            )).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
            let app =
                Router::new()
                    .route(
                        "/v1/logs",
                        post(
                            |State((tx, reject)): State<(mpsc::Sender<Vec<u8>>, bool)>,
                             body: Bytes| async move {
                                tx.send(body.to_vec()).await.unwrap();
                                if reject {
                                    StatusCode::SERVICE_UNAVAILABLE
                                } else {
                                    StatusCode::OK
                                }
                            },
                        ),
                    )
                    .with_state((tx, reject));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let quotas =
                aic_common::SpoolQuotas::from_spool_max_bytes(1024 * 1024, None, None, None);
            let spool = Arc::new(
                super::super::Spool::open(directory.path().join("spool"), quotas).unwrap(),
            );
            let cfg = ExporterConfig {
                endpoint: format!("http://{address}"),
                token: None,
                interval: Duration::from_secs(60),
                service_version: "test".to_string(),
                spool: spool.clone(),
                drain_batch_limit: 1,
                spool_max_age: None,
                health: Arc::new(super::super::ExporterHealth::new(
                    format!("http://{address}"),
                    spool.clone(),
                )),
                drop_counters: Arc::new(super::super::DropCounters::new()),
                process_enabled: false,
                directory_snapshot_enabled: true,
                process_io_diagnostics_enabled: false,
                process_inventory_enabled: false,
                process_inventory_store: None,
                live: None,
            };
            let (shutdown, receiver) = watch::channel(false);
            let exporter =
                tokio::spawn(
                    async move { serve_with_executable(cfg, receiver, &executable).await },
                );
            let body = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let request = logs_proto::ExportLogsServiceRequest::decode(body.as_slice()).unwrap();
            assert_eq!(
                request.resource_logs[0].scope_logs[0]
                    .scope
                    .as_ref()
                    .unwrap()
                    .name,
                "aic.changes"
            );
            let attrs = &request.resource_logs[0].scope_logs[0].log_records[0].attributes;
            assert!(attrs.iter().any(|attr| attr.key == "aic.change.action"
                && attr.value.as_ref().unwrap().value
                    == Some(logs_proto::AnyValueOneof::StringValue(
                        "fs_snapshot".to_string()
                    ))));
            if reject {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while spool.batch_count() == 0 {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(spool.batch_count(), 1);
            }
            shutdown.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(5), exporter)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if !reject {
                assert_eq!(spool.batch_count(), 0);
            }
            server.abort();
        }
    }
}
