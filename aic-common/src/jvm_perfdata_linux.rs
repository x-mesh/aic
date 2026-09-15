//! Linux-only trusted capture for HotSpot PerfData.

use crate::jvm_perfdata::{
    decode_prologue, parse, PerfDataPrologue, WorkerFailure, WorkerRequest, WorkerResponse,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const PROC_STATUS_LIMIT: usize = 64 * 1024;
const PROC_STAT_LIMIT: usize = 4 * 1024;
const CMDLINE_LIMIT: usize = 64 * 1024;
const EXE_LIMIT: usize = 4_096;
const PERFDATA_LIMIT: usize = 1024 * 1024;
const PROLOGUE_LEN: usize = 32;
const DIRENT_BUFFER_LEN: usize = 16 * 1024;
const DIRENT_HEADER_LEN: usize = 19;
const MAX_ROOT_ENTRIES: usize = 4_096;
const MAX_PREFIX_ENTRIES: usize = 256;
const MAX_MAIN_TOKEN_BYTES: usize = 256;
const MAX_COMMAND_TOKENS: usize = 16;
const SELECTOR_DIGEST_V1: u8 = 1;
const HS_PREFIX: &[u8] = b"hsperfdata_";
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureError {
    Unreachable,
    Rejected,
    Malformed,
}

impl From<CaptureError> for WorkerResponse {
    fn from(error: CaptureError) -> Self {
        let failure = match error {
            CaptureError::Unreachable => WorkerFailure::Unreachable,
            CaptureError::Rejected => WorkerFailure::Rejected,
            CaptureError::Malformed => WorkerFailure::Malformed,
        };
        WorkerResponse::Failure(failure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

#[derive(Debug, Clone, Copy)]
struct ObjectPolicy {
    identity: ObjectIdentity,
    mode: libc::mode_t,
    uid: libc::uid_t,
    links: libc::nlink_t,
    size: libc::off_t,
}

impl ObjectPolicy {
    fn from_fd(fd: RawFd) -> Result<Self, CaptureError> {
        let mut value = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
            return Err(CaptureError::Unreachable);
        }
        let value = unsafe { value.assume_init() };
        Ok(Self {
            identity: ObjectIdentity {
                device: value.st_dev,
                inode: value.st_ino,
            },
            mode: value.st_mode,
            uid: value.st_uid,
            links: value.st_nlink,
            size: value.st_size,
        })
    }
}

struct NamespaceSet {
    descriptors: [OwnedFd; 3],
    identities: [ObjectIdentity; 3],
}

struct ProcessSnapshot {
    _proc_dir: OwnedFd,
    proc_identity: ObjectIdentity,
    effective_uid: libc::uid_t,
    start_ticks: u64,
    executable: Vec<u8>,
    selector_digest: [u8; 32],
    namespaces: NamespaceSet,
}

struct SelectedDirectory {
    locator: Vec<u8>,
    descriptor: OwnedFd,
    policy: ObjectPolicy,
}

#[derive(Default)]
struct DirectoryAccumulator {
    total: usize,
    prefixed: Vec<Vec<u8>>,
}

impl DirectoryAccumulator {
    fn push(&mut self, name: &[u8]) -> Result<(), CaptureError> {
        self.total = self.total.checked_add(1).ok_or(CaptureError::Malformed)?;
        if self.total > MAX_ROOT_ENTRIES {
            return Err(CaptureError::Malformed);
        }
        if name.starts_with(HS_PREFIX) {
            if self.prefixed.len() == MAX_PREFIX_ENTRIES {
                return Err(CaptureError::Malformed);
            }
            self.prefixed.push(name.to_vec());
        }
        Ok(())
    }
}

/// Capture one trusted local HotSpot PerfData snapshot on Linux.
pub fn capture_linux(request: &WorkerRequest) -> WorkerResponse {
    match capture_with_roots(request, b"/proc", b"/tmp", unsafe { libc::geteuid() }) {
        Ok(metrics) => WorkerResponse::Metrics(metrics),
        Err(error) => error.into(),
    }
}

fn capture_with_roots(
    request: &WorkerRequest,
    proc_path: &[u8],
    temporary_path: &[u8],
    effective_uid: libc::uid_t,
) -> Result<crate::jvm_perfdata::JvmPerfDataMetrics, CaptureError> {
    if effective_uid == 0 || request.selector_digest_version != SELECTOR_DIGEST_V1 {
        return Err(CaptureError::Rejected);
    }
    let proc_root = open_absolute_directory(proc_path, false)?;
    let initial = read_process_snapshot(proc_root.as_raw_fd(), request.pid)?;
    validate_process_snapshot(&initial, request, effective_uid)?;
    let self_dir = open_relative_directory(proc_root.as_raw_fd(), b"self")?;
    let self_namespaces = open_namespaces(self_dir.as_raw_fd())?;
    compare_namespace_peers(&self_namespaces, &initial.namespaces)?;

    let root = open_absolute_directory(temporary_path, true)?;
    let root_policy = validate_root(root.as_raw_fd())?;
    let selected = select_directory(root.as_raw_fd(), root_policy, effective_uid)?;
    validate_directory(
        selected.descriptor.as_raw_fd(),
        root_policy,
        effective_uid,
        selected.policy,
    )?;

    let pid_locator = request.pid.to_string().into_bytes();
    let file = open_beneath(
        selected.descriptor.as_raw_fd(),
        &pid_locator,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )?;
    let file_policy = validate_file(file.as_raw_fd(), selected.policy, effective_uid, None)?;

    // Recheck every trusted descriptor immediately before reading untrusted bytes.
    validate_root(root.as_raw_fd()).and_then(|now| same_policy(now, root_policy))?;
    validate_directory(
        selected.descriptor.as_raw_fd(),
        root_policy,
        effective_uid,
        selected.policy,
    )?;
    let metrics = capture_snapshot(file.as_raw_fd(), file_policy)?;
    validate_file(
        file.as_raw_fd(),
        selected.policy,
        effective_uid,
        Some(file_policy),
    )?;

    validate_root(root.as_raw_fd()).and_then(|now| same_policy(now, root_policy))?;
    validate_directory(
        selected.descriptor.as_raw_fd(),
        root_policy,
        effective_uid,
        selected.policy,
    )?;
    reopen_identity(
        root.as_raw_fd(),
        &selected.locator,
        true,
        selected.policy.identity,
    )?;
    reopen_identity(
        selected.descriptor.as_raw_fd(),
        &pid_locator,
        false,
        file_policy.identity,
    )?;

    let final_snapshot = read_process_snapshot(proc_root.as_raw_fd(), request.pid)?;
    compare_process_snapshots(&initial, &final_snapshot)?;
    validate_process_snapshot(&final_snapshot, request, effective_uid)?;
    let final_self = open_relative_directory(proc_root.as_raw_fd(), b"self")?;
    let final_self_namespaces = open_namespaces(final_self.as_raw_fd())?;
    compare_namespace_stability(&self_namespaces, &final_self_namespaces)?;
    compare_namespace_peers(&final_self_namespaces, &final_snapshot.namespaces)?;
    Ok(metrics)
}

fn read_process_snapshot(proc_root: RawFd, pid: u32) -> Result<ProcessSnapshot, CaptureError> {
    let locator = pid.to_string().into_bytes();
    let proc_dir = open_relative_directory(proc_root, &locator)?;
    let proc_identity = ObjectPolicy::from_fd(proc_dir.as_raw_fd())?.identity;
    let status = read_relative_file(proc_dir.as_raw_fd(), b"status", PROC_STATUS_LIMIT)?;
    let effective_uid = parse_effective_uid(&status)?;
    let stat = read_relative_file(proc_dir.as_raw_fd(), b"stat", PROC_STAT_LIMIT)?;
    let start_ticks = parse_start_ticks(&stat)?;
    let executable = read_link(proc_dir.as_raw_fd(), b"exe")?;
    let cmdline = read_relative_file(proc_dir.as_raw_fd(), b"cmdline", CMDLINE_LIMIT)?;
    if cmdline.len() == CMDLINE_LIMIT {
        return Err(CaptureError::Malformed);
    }
    let main_token = select_main_token(&cmdline)?;
    let selector_digest = selector_digest_v1(&executable, main_token)?;
    let namespaces = open_namespaces(proc_dir.as_raw_fd())?;
    Ok(ProcessSnapshot {
        _proc_dir: proc_dir,
        proc_identity,
        effective_uid,
        start_ticks,
        executable,
        selector_digest,
        namespaces,
    })
}

fn validate_process_snapshot(
    snapshot: &ProcessSnapshot,
    request: &WorkerRequest,
    effective_uid: libc::uid_t,
) -> Result<(), CaptureError> {
    if snapshot.effective_uid == 0
        || snapshot.effective_uid != effective_uid
        || snapshot.start_ticks != request.start_ticks
        || snapshot.selector_digest != request.selector_digest
    {
        return Err(CaptureError::Rejected);
    }
    Ok(())
}

fn compare_process_snapshots(
    initial: &ProcessSnapshot,
    final_snapshot: &ProcessSnapshot,
) -> Result<(), CaptureError> {
    if initial.proc_identity != final_snapshot.proc_identity
        || initial.effective_uid != final_snapshot.effective_uid
        || initial.start_ticks != final_snapshot.start_ticks
        || initial.executable != final_snapshot.executable
        || initial.selector_digest != final_snapshot.selector_digest
    {
        return Err(CaptureError::Rejected);
    }
    compare_namespace_stability(&initial.namespaces, &final_snapshot.namespaces)
}

fn open_namespaces(proc_dir: RawFd) -> Result<NamespaceSet, CaptureError> {
    let descriptors = [
        open_relative(proc_dir, b"ns/user", libc::O_RDONLY | libc::O_CLOEXEC)?,
        open_relative(proc_dir, b"ns/pid", libc::O_RDONLY | libc::O_CLOEXEC)?,
        open_relative(proc_dir, b"ns/mnt", libc::O_RDONLY | libc::O_CLOEXEC)?,
    ];
    let identities = [
        ObjectPolicy::from_fd(descriptors[0].as_raw_fd())?.identity,
        ObjectPolicy::from_fd(descriptors[1].as_raw_fd())?.identity,
        ObjectPolicy::from_fd(descriptors[2].as_raw_fd())?.identity,
    ];
    Ok(NamespaceSet {
        descriptors,
        identities,
    })
}

fn compare_namespace_peers(left: &NamespaceSet, right: &NamespaceSet) -> Result<(), CaptureError> {
    if left.identities != right.identities {
        return Err(CaptureError::Rejected);
    }
    Ok(())
}

fn compare_namespace_stability(
    initial: &NamespaceSet,
    final_set: &NamespaceSet,
) -> Result<(), CaptureError> {
    for index in 0..initial.descriptors.len() {
        let live = ObjectPolicy::from_fd(initial.descriptors[index].as_raw_fd())?.identity;
        if live != initial.identities[index]
            || final_set.identities[index] != initial.identities[index]
        {
            return Err(CaptureError::Rejected);
        }
    }
    Ok(())
}

fn parse_effective_uid(input: &[u8]) -> Result<libc::uid_t, CaptureError> {
    if input.is_empty() || input.contains(&0) || input.last() != Some(&b'\n') {
        return Err(CaptureError::Malformed);
    }
    let mut found = None;
    for line in input.split(|byte| *byte == b'\n') {
        let Some(fields) = line.strip_prefix(b"Uid:") else {
            continue;
        };
        if found.is_some() {
            return Err(CaptureError::Malformed);
        }
        let values: Vec<&[u8]> = fields
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect();
        if values.len() != 4 {
            return Err(CaptureError::Malformed);
        }
        let effective = parse_decimal(values[1])?;
        found = Some(libc::uid_t::try_from(effective).map_err(|_| CaptureError::Malformed)?);
    }
    found.ok_or(CaptureError::Malformed)
}

fn parse_start_ticks(input: &[u8]) -> Result<u64, CaptureError> {
    if input.is_empty() || input.contains(&0) || input.last() != Some(&b'\n') {
        return Err(CaptureError::Malformed);
    }
    let close = input
        .windows(2)
        .rposition(|window| window == b") ")
        .ok_or(CaptureError::Malformed)?;
    let tail = &input[close + 2..input.len() - 1];
    let field = tail
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(19)
        .ok_or(CaptureError::Malformed)?;
    parse_decimal(field)
}

fn parse_decimal(input: &[u8]) -> Result<u64, CaptureError> {
    if input.is_empty() || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(CaptureError::Malformed);
    }
    input.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(CaptureError::Malformed)
    })
}

fn select_main_token(cmdline: &[u8]) -> Result<&[u8], CaptureError> {
    if cmdline.is_empty() || cmdline.last() != Some(&0) {
        return Err(CaptureError::Malformed);
    }
    let mut tokens = cmdline
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty());
    let mut main = None;
    for (index, value) in tokens.by_ref().enumerate() {
        if index >= MAX_COMMAND_TOKENS {
            return Err(CaptureError::Malformed);
        }
        if main.is_none() && !value.starts_with(b"-") && !value.ends_with(b"java") {
            main = Some(&value[..value.len().min(MAX_MAIN_TOKEN_BYTES)]);
        }
    }
    main.ok_or(CaptureError::Rejected)
}

fn selector_digest_v1(executable: &[u8], main_token: &[u8]) -> Result<[u8; 32], CaptureError> {
    let executable_len = u16::try_from(executable.len()).map_err(|_| CaptureError::Malformed)?;
    let main_len = u16::try_from(main_token.len()).map_err(|_| CaptureError::Malformed)?;
    let mut hasher = Sha256::new();
    hasher.update([SELECTOR_DIGEST_V1]);
    hasher.update(executable_len.to_le_bytes());
    hasher.update(executable);
    hasher.update(main_len.to_le_bytes());
    hasher.update(main_token);
    Ok(hasher.finalize().into())
}

fn validate_root(fd: RawFd) -> Result<ObjectPolicy, CaptureError> {
    let policy = ObjectPolicy::from_fd(fd)?;
    if policy.mode & libc::S_IFMT != libc::S_IFDIR
        || policy.uid != 0
        || policy.mode & 0o7777 != 0o1777
        || policy.links == 0
    {
        return Err(CaptureError::Rejected);
    }
    Ok(policy)
}

fn validate_directory(
    fd: RawFd,
    root: ObjectPolicy,
    uid: libc::uid_t,
    expected: ObjectPolicy,
) -> Result<ObjectPolicy, CaptureError> {
    let policy = ObjectPolicy::from_fd(fd)?;
    if policy.mode & libc::S_IFMT != libc::S_IFDIR
        || policy.uid != uid
        || policy.mode & 0o022 != 0
        || policy.links == 0
        || policy.identity.device != root.identity.device
    {
        return Err(CaptureError::Rejected);
    }
    same_policy(policy, expected)?;
    Ok(policy)
}

fn validate_file(
    fd: RawFd,
    directory: ObjectPolicy,
    uid: libc::uid_t,
    expected: Option<ObjectPolicy>,
) -> Result<ObjectPolicy, CaptureError> {
    let policy = ObjectPolicy::from_fd(fd)?;
    if policy.mode & libc::S_IFMT != libc::S_IFREG
        || policy.uid != uid
        || policy.links != 1
        || policy.mode & 0o022 != 0
        || policy.size <= PROLOGUE_LEN as libc::off_t
        || policy.size > PERFDATA_LIMIT as libc::off_t
        || policy.identity.device != directory.identity.device
    {
        return Err(CaptureError::Rejected);
    }
    if let Some(expected) = expected {
        same_policy(policy, expected)?;
    }
    Ok(policy)
}

fn same_policy(current: ObjectPolicy, expected: ObjectPolicy) -> Result<(), CaptureError> {
    if current.identity != expected.identity
        || current.mode != expected.mode
        || current.uid != expected.uid
        || current.links != expected.links
        || current.size != expected.size
    {
        return Err(CaptureError::Rejected);
    }
    Ok(())
}

fn select_directory(
    root_fd: RawFd,
    root: ObjectPolicy,
    uid: libc::uid_t,
) -> Result<SelectedDirectory, CaptureError> {
    let entries = enumerate_root(root_fd)?;
    let mut selected = None;
    for locator in entries {
        let Ok(descriptor) = open_beneath(
            root_fd,
            &locator,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ) else {
            continue;
        };
        let Ok(policy) = ObjectPolicy::from_fd(descriptor.as_raw_fd()) else {
            continue;
        };
        if policy.mode & libc::S_IFMT != libc::S_IFDIR
            || policy.uid != uid
            || policy.mode & 0o022 != 0
            || policy.links == 0
            || policy.identity.device != root.identity.device
        {
            continue;
        }
        if selected.is_some() {
            return Err(CaptureError::Rejected);
        }
        selected = Some(SelectedDirectory {
            locator,
            descriptor,
            policy,
        });
    }
    selected.ok_or(CaptureError::Rejected)
}

fn enumerate_root(root_fd: RawFd) -> Result<Vec<Vec<u8>>, CaptureError> {
    if unsafe { libc::lseek(root_fd, 0, libc::SEEK_SET) } < 0 {
        return Err(CaptureError::Unreachable);
    }
    let mut accumulator = DirectoryAccumulator::default();
    let mut buffer = [0_u8; DIRENT_BUFFER_LEN];
    loop {
        let count = loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    root_fd,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count >= 0 {
                break count as usize;
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(CaptureError::Unreachable);
            }
        };
        if count == 0 {
            return Ok(accumulator.prefixed);
        }
        let records = parse_dirent_buffer(&buffer[..count])?;
        for name in records {
            accumulator.push(name)?;
        }
    }
}

fn parse_dirent_buffer(buffer: &[u8]) -> Result<Vec<&[u8]>, CaptureError> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < buffer.len() {
        let remaining = buffer.len() - offset;
        if remaining < DIRENT_HEADER_LEN + 1 {
            return Err(CaptureError::Malformed);
        }
        let reclen = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
        if reclen < DIRENT_HEADER_LEN + 1 || reclen > remaining {
            return Err(CaptureError::Malformed);
        }
        let name_area = &buffer[offset + DIRENT_HEADER_LEN..offset + reclen];
        let nul = name_area
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(CaptureError::Malformed)?;
        if nul != 0 {
            records.push(&name_area[..nul]);
        }
        offset += reclen;
    }
    Ok(records)
}

fn capture_snapshot(
    fd: RawFd,
    file_policy: ObjectPolicy,
) -> Result<crate::jvm_perfdata::JvmPerfDataMetrics, CaptureError> {
    let mut p1 = [0_u8; PROLOGUE_LEN];
    pread_exact(fd, &mut p1, 0)?;
    let first = decode_prologue(&p1).map_err(|_| CaptureError::Malformed)?;
    validate_prologue(first, file_policy.size)?;
    let mut snapshot = vec![0_u8; first.used];
    pread_exact(fd, &mut snapshot, 0)?;
    let copied = decode_prologue(&snapshot).map_err(|_| CaptureError::Malformed)?;
    let metrics = parse(&snapshot).map_err(|_| CaptureError::Malformed)?;
    let mut p2 = [0_u8; PROLOGUE_LEN];
    pread_exact(fd, &mut p2, 0)?;
    let second = decode_prologue(&p2).map_err(|_| CaptureError::Malformed)?;
    if first != copied || first != second {
        return Err(CaptureError::Malformed);
    }
    Ok(metrics)
}

fn validate_prologue(
    prologue: PerfDataPrologue,
    file_size: libc::off_t,
) -> Result<(), CaptureError> {
    if prologue.overflow != 0
        || prologue.used < PROLOGUE_LEN
        || prologue.used > file_size as usize
        || prologue.entry_offset < PROLOGUE_LEN
        || prologue.entry_offset > prologue.used
        || prologue.entry_count > 4_096
    {
        return Err(CaptureError::Malformed);
    }
    Ok(())
}

fn pread_exact(fd: RawFd, output: &mut [u8], offset: usize) -> Result<(), CaptureError> {
    let mut read = 0_usize;
    while read < output.len() {
        let count = unsafe {
            libc::pread(
                fd,
                output[read..].as_mut_ptr().cast(),
                output.len() - read,
                (offset + read) as libc::off_t,
            )
        };
        if count == 0 {
            return Err(CaptureError::Malformed);
        }
        if count < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(CaptureError::Unreachable);
        }
        read += count as usize;
    }
    Ok(())
}

fn reopen_identity(
    parent: RawFd,
    locator: &[u8],
    directory: bool,
    expected: ObjectIdentity,
) -> Result<(), CaptureError> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC;
    if directory {
        flags |= libc::O_DIRECTORY;
    } else {
        flags |= libc::O_NONBLOCK;
    }
    let reopened = open_beneath(parent, locator, flags)?;
    if ObjectPolicy::from_fd(reopened.as_raw_fd())?.identity != expected {
        return Err(CaptureError::Rejected);
    }
    Ok(())
}

fn open_absolute_directory(path: &[u8], no_follow: bool) -> Result<OwnedFd, CaptureError> {
    let path = cstring(path)?;
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if no_follow {
        flags |= libc::O_NOFOLLOW;
    }
    owned_fd(unsafe { libc::open(path.as_ptr(), flags) })
}

fn open_relative_directory(parent: RawFd, path: &[u8]) -> Result<OwnedFd, CaptureError> {
    open_relative(
        parent,
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

fn open_relative(parent: RawFd, path: &[u8], flags: i32) -> Result<OwnedFd, CaptureError> {
    let path = cstring(path)?;
    owned_fd(unsafe { libc::openat(parent, path.as_ptr(), flags) })
}

fn open_beneath(parent: RawFd, path: &[u8], flags: i32) -> Result<OwnedFd, CaptureError> {
    let path = cstring(path)?;
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as RawFd
    };
    owned_fd(fd)
}

fn read_relative_file(parent: RawFd, path: &[u8], limit: usize) -> Result<Vec<u8>, CaptureError> {
    let file = open_relative(parent, path, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let mut result = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = unsafe { libc::read(file.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if count == 0 {
            return Ok(result);
        }
        if count < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(CaptureError::Unreachable);
        }
        let count = count as usize;
        if result.len().saturating_add(count) > limit {
            return Err(CaptureError::Malformed);
        }
        result.extend_from_slice(&chunk[..count]);
    }
}

fn read_link(parent: RawFd, path: &[u8]) -> Result<Vec<u8>, CaptureError> {
    let path = cstring(path)?;
    let mut result = vec![0_u8; EXE_LIMIT + 1];
    let count = unsafe {
        libc::readlinkat(
            parent,
            path.as_ptr(),
            result.as_mut_ptr().cast(),
            result.len(),
        )
    };
    if count <= 0 || count as usize == result.len() {
        return Err(if count < 0 {
            CaptureError::Unreachable
        } else {
            CaptureError::Malformed
        });
    }
    result.truncate(count as usize);
    Ok(result)
}

fn cstring(bytes: &[u8]) -> Result<CString, CaptureError> {
    CString::new(bytes).map_err(|_| CaptureError::Rejected)
}

fn owned_fd(fd: RawFd) -> Result<OwnedFd, CaptureError> {
    if fd < 0 {
        return Err(CaptureError::Unreachable);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("aic-jvm-perfdata-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_test_directory(path: &std::path::Path) -> OwnedFd {
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
        open_absolute_directory(bytes, true).unwrap()
    }

    fn directory_policy(fd: RawFd) -> ObjectPolicy {
        ObjectPolicy::from_fd(fd).unwrap()
    }

    fn open_test_file(directory: RawFd, locator: &[u8]) -> OwnedFd {
        open_beneath(
            directory,
            locator,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
        .unwrap()
    }

    #[test]
    fn parses_status_with_exactly_four_uid_fields() {
        assert_eq!(
            parse_effective_uid(b"Name:\tjava\nUid:\t10 20 30 40\n"),
            Ok(20)
        );
        assert!(parse_effective_uid(b"Uid: 1 2 3\n").is_err());
        assert!(parse_effective_uid(b"Uid: 1 2 3 4 5\n").is_err());
        assert!(parse_effective_uid(b"Uid: 1 2 3 4\nUid: 1 2 3 4\n").is_err());
        assert!(parse_effective_uid(b"Uid: 1 2 3 4\0\n").is_err());
    }

    #[test]
    fn parses_stat_with_spaces_and_closing_parenthesis_in_comm() {
        let mut stat = b"42 (a strange ) name) S".to_vec();
        for field in 4_u64..=21 {
            stat.extend_from_slice(format!(" {field}").as_bytes());
        }
        stat.extend_from_slice(b" 987654 23\n");
        assert_eq!(parse_start_ticks(&stat), Ok(987654));
        assert!(parse_start_ticks(&stat[..stat.len() - 1]).is_err());
    }

    #[test]
    fn command_line_requires_a_complete_bounded_main_token() {
        assert_eq!(
            select_main_token(b"/usr/bin/java\0-Xmx1g\0example.Main\0"),
            Ok(&b"example.Main"[..])
        );
        assert!(select_main_token(b"/usr/bin/java\0-Xmx1g").is_err());
        assert!(select_main_token(b"/usr/bin/java\0-Xmx1g\0").is_err());
        let long = vec![b'x'; MAX_MAIN_TOKEN_BYTES + 3];
        let mut command = b"java\0".to_vec();
        command.extend_from_slice(&long);
        command.push(0);
        assert_eq!(
            select_main_token(&command).unwrap().len(),
            MAX_MAIN_TOKEN_BYTES
        );
    }

    #[test]
    fn selector_digest_has_the_v1_canonical_layout() {
        let actual = selector_digest_v1(b"/java", b"Main").unwrap();
        let mut expected = Sha256::new();
        expected.update([1]);
        expected.update(5_u16.to_le_bytes());
        expected.update(b"/java");
        expected.update(4_u16.to_le_bytes());
        expected.update(b"Main");
        assert_eq!(actual, <[u8; 32]>::from(expected.finalize()));
    }

    #[test]
    fn dirent_parser_rejects_malformed_records() {
        let mut valid = vec![0_u8; 24];
        valid[16..18].copy_from_slice(&24_u16.to_ne_bytes());
        valid[19..22].copy_from_slice(b"abc");
        assert_eq!(parse_dirent_buffer(&valid).unwrap(), vec![&b"abc"[..]]);
        let mut short = valid.clone();
        short[16..18].copy_from_slice(&19_u16.to_ne_bytes());
        assert!(parse_dirent_buffer(&short).is_err());
        let mut over = valid.clone();
        over[16..18].copy_from_slice(&25_u16.to_ne_bytes());
        assert!(parse_dirent_buffer(&over).is_err());
        let mut no_nul = valid;
        no_nul[19..].fill(b'x');
        assert!(parse_dirent_buffer(&no_nul).is_err());
    }

    #[test]
    fn directory_caps_accept_exact_limits_and_reject_one_more() {
        let mut total = DirectoryAccumulator::default();
        for _ in 0..MAX_ROOT_ENTRIES {
            total.push(b"ordinary").unwrap();
        }
        assert_eq!(total.total, MAX_ROOT_ENTRIES);
        assert_eq!(total.push(b"ordinary"), Err(CaptureError::Malformed));

        let mut prefixes = DirectoryAccumulator::default();
        for _ in 0..MAX_PREFIX_ENTRIES {
            prefixes.push(b"hsperfdata_candidate").unwrap();
        }
        assert_eq!(prefixes.prefixed.len(), MAX_PREFIX_ENTRIES);
        assert_eq!(
            prefixes.push(b"hsperfdata_extra"),
            Err(CaptureError::Malformed)
        );
    }

    #[test]
    fn openat2_accepts_safe_entries_and_rejects_symlinks() {
        let fixture = TestDirectory::create();
        fs::create_dir(fixture.0.join("safe")).unwrap();
        symlink("safe", fixture.0.join("linked")).unwrap();
        let root = open_test_directory(&fixture.0);
        assert!(open_beneath(
            root.as_raw_fd(),
            b"safe",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
        )
        .is_ok());
        assert!(open_beneath(
            root.as_raw_fd(),
            b"linked",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
        )
        .is_err());
    }

    #[test]
    fn file_policy_rejects_hardlinks_fifo_bad_mode_zero_and_sparse_files() {
        let fixture = TestDirectory::create();
        let root = open_test_directory(&fixture.0);
        let directory = directory_policy(root.as_raw_fd());
        let uid = unsafe { libc::geteuid() };

        fs::write(fixture.0.join("valid"), vec![1_u8; PROLOGUE_LEN + 1]).unwrap();
        let valid = open_test_file(root.as_raw_fd(), b"valid");
        assert!(validate_file(valid.as_raw_fd(), directory, uid, None).is_ok());

        fs::hard_link(fixture.0.join("valid"), fixture.0.join("hardlink")).unwrap();
        assert!(validate_file(valid.as_raw_fd(), directory, uid, None).is_err());

        let fifo = CString::new("fifo").unwrap();
        assert_eq!(
            unsafe { libc::mkfifoat(root.as_raw_fd(), fifo.as_ptr(), 0o600) },
            0
        );
        let fifo = open_test_file(root.as_raw_fd(), b"fifo");
        assert!(validate_file(fifo.as_raw_fd(), directory, uid, None).is_err());

        fs::write(fixture.0.join("bad-mode"), vec![1_u8; PROLOGUE_LEN + 1]).unwrap();
        fs::set_permissions(
            fixture.0.join("bad-mode"),
            fs::Permissions::from_mode(0o622),
        )
        .unwrap();
        let bad_mode = open_test_file(root.as_raw_fd(), b"bad-mode");
        assert!(validate_file(bad_mode.as_raw_fd(), directory, uid, None).is_err());

        File::create(fixture.0.join("zero")).unwrap();
        let zero = open_test_file(root.as_raw_fd(), b"zero");
        assert!(validate_file(zero.as_raw_fd(), directory, uid, None).is_err());

        let sparse = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(fixture.0.join("sparse"))
            .unwrap();
        sparse.set_len((PERFDATA_LIMIT + 1) as u64).unwrap();
        let sparse = open_test_file(root.as_raw_fd(), b"sparse");
        assert!(validate_file(sparse.as_raw_fd(), directory, uid, None).is_err());
    }

    #[test]
    fn locator_reopen_rejects_replacement() {
        let fixture = TestDirectory::create();
        fs::write(fixture.0.join("42"), vec![1_u8; PROLOGUE_LEN + 1]).unwrap();
        let root = open_test_directory(&fixture.0);
        let initial = open_test_file(root.as_raw_fd(), b"42");
        let identity = ObjectPolicy::from_fd(initial.as_raw_fd()).unwrap().identity;
        fs::rename(fixture.0.join("42"), fixture.0.join("old")).unwrap();
        fs::write(fixture.0.join("42"), vec![2_u8; PROLOGUE_LEN + 1]).unwrap();
        assert!(reopen_identity(root.as_raw_fd(), b"42", false, identity).is_err());
    }

    #[test]
    fn snapshot_rejects_short_prologue_and_short_used_region() {
        let fixture = TestDirectory::create();
        fs::write(fixture.0.join("short"), vec![0_u8; PROLOGUE_LEN - 1]).unwrap();
        let root = open_test_directory(&fixture.0);
        let short = open_test_file(root.as_raw_fd(), b"short");
        let policy = ObjectPolicy::from_fd(short.as_raw_fd()).unwrap();
        assert!(capture_snapshot(short.as_raw_fd(), policy).is_err());

        let mut prologue = vec![0_u8; PROLOGUE_LEN + 1];
        prologue[..4].copy_from_slice(&[0xca, 0xfe, 0xc0, 0xc0]);
        prologue[4..8].copy_from_slice(&[1, 2, 0, 1]);
        prologue[8..12].copy_from_slice(&64_i32.to_le_bytes());
        prologue[24..28].copy_from_slice(&32_i32.to_le_bytes());
        fs::write(fixture.0.join("truncated"), prologue).unwrap();
        let truncated = open_test_file(root.as_raw_fd(), b"truncated");
        let policy = ObjectPolicy::from_fd(truncated.as_raw_fd()).unwrap();
        assert!(capture_snapshot(truncated.as_raw_fd(), policy).is_err());
    }

    #[test]
    fn root_capture_rejects_privileged_execution() {
        let request = WorkerRequest {
            pid: 1,
            start_ticks: 1,
            selector_digest_version: 1,
            selector_digest: [0; 32],
            opaque_workload_id: [0; 16],
        };
        assert!(matches!(
            capture_with_roots(&request, b"/proc", b"/tmp", 0),
            Err(CaptureError::Rejected)
        ));
    }

    #[test]
    fn capture_rejects_non_v1_selector_before_io() {
        let request = WorkerRequest {
            pid: 1,
            start_ticks: 1,
            selector_digest_version: 2,
            selector_digest: [0; 32],
            opaque_workload_id: [0; 16],
        };
        assert!(matches!(
            capture_with_roots(&request, b"/absent", b"/absent", 1000),
            Err(CaptureError::Rejected)
        ));
    }

    #[test]
    fn cstring_rejects_embedded_nul() {
        assert!(cstring(b"bad\0name").is_err());
        assert_eq!(cstring(b"ok").unwrap().as_bytes(), b"ok");
    }
}
