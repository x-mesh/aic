//! Isolated Linux worker lifecycle for trusted HotSpot PerfData capture.

use aic_common::jvm_perfdata::{
    decode_request, decode_response, encode_request, encode_response, WorkerRequest, WorkerResponse,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const READY: &[u8] = b"AIC-JVM-PERFDATA/1 READY\n";
const PROBE_DEADLINE: Duration = Duration::from_millis(200);
const REAP_WARNING_AFTER: Duration = Duration::from_secs(1);
const MAX_RESPONSE_FRAME: usize = 64 * 1024 + 4;
const MAX_REQUEST_FRAME: usize = 1024 * 1024 + 4;
const CHILD_FD_BASE: libc::c_int = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChildToken([u8; 16]);

impl ChildToken {
    #[cfg(target_os = "linux")]
    fn generate(simulate_failure: bool) -> Result<Self, WorkerError> {
        if simulate_failure {
            return Err(WorkerError::Setup);
        }
        let mut bytes = [0_u8; 16];
        let mut filled = 0;
        while filled < bytes.len() {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    bytes[filled..].as_mut_ptr(),
                    bytes.len() - filled,
                    0_u32,
                )
            };
            if result > 0 {
                filled += result as usize;
            } else if result < 0 && last_errno() == libc::EINTR {
                continue;
            } else {
                return Err(WorkerError::Setup);
            }
        }
        if bytes == [0; 16] {
            return Err(WorkerError::Setup);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerError {
    Unsupported,
    Busy,
    Setup,
    Exec,
    InvalidReady,
    Group,
    Timeout,
    Crash,
    Protocol,
    Shutdown,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "JVM PerfData worker is unsupported on this platform",
            Self::Busy => "JVM PerfData worker is draining",
            Self::Setup => "JVM PerfData worker setup failed",
            Self::Exec => "JVM PerfData worker exec failed",
            Self::InvalidReady => "JVM PerfData worker READY failed",
            Self::Group => "JVM PerfData worker process group failed",
            Self::Timeout => "JVM PerfData worker timed out",
            Self::Crash => "JVM PerfData worker exited abnormally",
            Self::Protocol => "JVM PerfData worker protocol failed",
            Self::Shutdown => "JVM PerfData worker supervisor is shut down",
        })
    }
}

impl std::error::Error for WorkerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTestHook {
    Normal,
    CloseRangeFailure,
    InvalidReady,
    PreReadyHang,
    PostReadyHang,
    Crash,
    TrailingOutput,
    OversizeOutput,
    RandomFailure,
    PartialSetupFailure,
    ForkFailure,
    DescendantAttempt,
    #[cfg(target_arch = "x86_64")]
    X32SyscallAttempt,
}

impl WorkerTestHook {
    pub fn cli_value(self) -> &'static str {
        match self {
            Self::Normal
            | Self::CloseRangeFailure
            | Self::RandomFailure
            | Self::PartialSetupFailure
            | Self::ForkFailure => "normal",
            Self::InvalidReady => "invalid-ready",
            Self::PreReadyHang => "pre-ready-hang",
            Self::PostReadyHang => "post-ready-hang",
            Self::Crash => "crash",
            Self::TrailingOutput => "trailing-output",
            Self::OversizeOutput => "oversize-output",
            Self::DescendantAttempt => "descendant-attempt",
            #[cfg(target_arch = "x86_64")]
            Self::X32SyscallAttempt => "x32-syscall-attempt",
        }
    }

    pub fn from_cli(value: &str) -> Option<Self> {
        Some(match value {
            "normal" => Self::Normal,
            "invalid-ready" => Self::InvalidReady,
            "pre-ready-hang" => Self::PreReadyHang,
            "post-ready-hang" => Self::PostReadyHang,
            "crash" => Self::Crash,
            "trailing-output" => Self::TrailingOutput,
            "oversize-output" => Self::OversizeOutput,
            "descendant-attempt" => Self::DescendantAttempt,
            #[cfg(target_arch = "x86_64")]
            "x32-syscall-attempt" => Self::X32SyscallAttempt,
            _ => return None,
        })
    }
}

#[derive(Debug)]
enum ActorCommand {
    Reserve {
        token: ChildToken,
        events: mpsc::Sender<ActorEvent>,
        reply: mpsc::Sender<Option<Arc<Registration>>>,
    },
    Release {
        token: ChildToken,
    },
    VerifyGroup {
        token: ChildToken,
        pid: libc::pid_t,
    },
    KillLeader {
        token: ChildToken,
        pid: libc::pid_t,
    },
    KillGroup {
        token: ChildToken,
        pid: libc::pid_t,
    },
}

#[derive(Debug, Clone, Copy)]
enum ActorEventKind {
    Group(bool),
    Wait(libc::c_int),
}

#[derive(Debug, Clone, Copy)]
struct ActorEvent {
    token: ChildToken,
    pid: libc::pid_t,
    kind: ActorEventKind,
}

#[derive(Debug)]
struct ActorChild {
    token: ChildToken,
    pid: libc::pid_t,
    group_verified: bool,
    kill_started: Option<Instant>,
    warned: bool,
    events: mpsc::Sender<ActorEvent>,
    registration: Arc<Registration>,
}

#[derive(Debug)]
struct Registration {
    pid: AtomicI32,
    cancelled: AtomicBool,
}

impl Registration {
    fn new() -> Self {
        Self {
            pid: AtomicI32::new(0),
            cancelled: AtomicBool::new(false),
        }
    }
}

fn lifecycle_actor() -> &'static mpsc::Sender<ActorCommand> {
    static ACTOR: OnceLock<mpsc::Sender<ActorCommand>> = OnceLock::new();
    ACTOR.get_or_init(|| {
        let (command_tx, command_rx) = mpsc::channel();
        thread::Builder::new()
            .name("aic-jvm-worker-lifecycle".into())
            .spawn(move || actor_loop(command_rx))
            .expect("lifecycle actor thread creation must succeed");
        command_tx
    })
}

#[derive(Debug)]
struct ActiveChild {
    token: ChildToken,
    pid: libc::pid_t,
    stdin_fd: libc::c_int,
    stdout_fd: libc::c_int,
    exec_fd: libc::c_int,
    exec_error: Vec<u8>,
    output: Vec<u8>,
    stdout_eof: bool,
    exec_eof: bool,
    wait_status: Option<libc::c_int>,
    group_verified: bool,
    group_requested: bool,
    ready_seen: bool,
}

impl Drop for ActiveChild {
    fn drop(&mut self) {
        close_fd(&mut self.stdin_fd);
        close_fd(&mut self.stdout_fd);
        close_fd(&mut self.exec_fd);
    }
}

enum SupervisorState {
    Idle,
    Running(ActiveChild),
    Draining(ActiveChild),
    Shutdown,
}

pub struct JvmWorkerSupervisor {
    executable: PathBuf,
    actor: mpsc::Sender<ActorCommand>,
    events: mpsc::Receiver<ActorEvent>,
    event_sender: mpsc::Sender<ActorEvent>,
    state: SupervisorState,
    test_hook: WorkerTestHook,
}

impl JvmWorkerSupervisor {
    pub fn new() -> Result<Self, WorkerError> {
        let executable = std::env::current_exe().map_err(|_| WorkerError::Setup)?;
        Ok(Self::with_executable_and_hook(
            executable,
            WorkerTestHook::Normal,
        ))
    }

    #[doc(hidden)]
    pub fn with_executable_and_hook(executable: PathBuf, test_hook: WorkerTestHook) -> Self {
        let (event_sender, events) = mpsc::channel();
        Self {
            executable,
            actor: lifecycle_actor().clone(),
            events,
            event_sender,
            state: SupervisorState::Idle,
            test_hook,
        }
    }

    pub fn capture(&mut self, request: WorkerRequest) -> Result<WorkerResponse, WorkerError> {
        self.refresh_draining();
        if !matches!(self.state, SupervisorState::Idle) {
            return Err(if matches!(self.state, SupervisorState::Shutdown) {
                WorkerError::Shutdown
            } else {
                WorkerError::Busy
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            return Err(WorkerError::Unsupported);
        }

        #[cfg(target_os = "linux")]
        {
            let prepared = PreparedChild::new(&self.executable, self.test_hook)?;
            let token = prepared.token;
            let (reply_tx, reply_rx) = mpsc::channel();
            self.actor
                .send(ActorCommand::Reserve {
                    token,
                    events: self.event_sender.clone(),
                    reply: reply_tx,
                })
                .map_err(|_| WorkerError::Setup)?;
            let registration = reply_rx.recv_timeout(PROBE_DEADLINE).ok().flatten();
            let Some(registration) = registration else {
                // Reserve and Release use one FIFO channel. A late Reserve cannot outlive this release.
                let _ = self.actor.send(ActorCommand::Release { token });
                return Err(WorkerError::Busy);
            };
            let deadline = Instant::now() + PROBE_DEADLINE;
            let child = match prepared.fork_exec(self.test_hook) {
                Ok(child) => child,
                Err(error) => {
                    registration.cancelled.store(true, Ordering::Release);
                    let _ = self.actor.send(ActorCommand::Release { token });
                    return Err(error);
                }
            };
            // The process-lifetime actor owns this registration before fork. Publishing the PID
            // transfers kill and reap ownership without another fallible channel operation.
            registration.pid.store(child.pid, Ordering::Release);
            self.state = SupervisorState::Running(child);
            let result = self.drive(request, deadline);
            if result.is_err() {
                if let SupervisorState::Running(child) = &mut self.state {
                    child.output.clear();
                    child.exec_error.clear();
                }
                self.begin_kill();
            }
            self.finish_or_drain(result)
        }
    }

    pub fn shutdown(&mut self) {
        self.refresh_draining();
        if matches!(
            self.state,
            SupervisorState::Running(_) | SupervisorState::Draining(_)
        ) {
            self.begin_kill();
        }
        self.state = match std::mem::replace(&mut self.state, SupervisorState::Shutdown) {
            SupervisorState::Running(child) | SupervisorState::Draining(child)
                if child.wait_status.is_none() =>
            {
                SupervisorState::Draining(child)
            }
            _ => SupervisorState::Shutdown,
        };
    }

    pub fn is_draining(&mut self) -> bool {
        self.refresh_draining();
        matches!(self.state, SupervisorState::Draining(_))
    }

    fn drive(
        &mut self,
        request: WorkerRequest,
        deadline: Instant,
    ) -> Result<WorkerResponse, WorkerError> {
        let mut request_sent = false;
        loop {
            self.read_child_pipes()?;
            self.receive_events();
            let child = match &mut self.state {
                SupervisorState::Running(child) => child,
                _ => return Err(WorkerError::Protocol),
            };

            if child.exec_eof && !child.exec_error.is_empty() {
                return Err(WorkerError::Exec);
            }
            if child.exec_eof && !child.ready_seen && child.output.len() >= READY.len() {
                if &child.output[..READY.len()] != READY {
                    return Err(WorkerError::InvalidReady);
                }
                child.output.drain(..READY.len());
                self.actor
                    .send(ActorCommand::VerifyGroup {
                        token: child.token,
                        pid: child.pid,
                    })
                    .map_err(|_| WorkerError::Setup)?;
                child.ready_seen = true;
                child.group_requested = true;
            }

            if child.group_verified && !request_sent && child.output.is_empty() {
                write_all_fd(child.stdin_fd, &encode_request(&request))?;
                close_fd(&mut child.stdin_fd);
                request_sent = true;
            }

            let child = match &self.state {
                SupervisorState::Running(child) => child,
                _ => return Err(WorkerError::Protocol),
            };
            if let Some(result) = joined_response(
                &child.output,
                child.stdout_eof,
                child.wait_status,
                request_sent,
            ) {
                return result;
            }
            if Instant::now() >= deadline {
                return Err(WorkerError::Timeout);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn read_child_pipes(&mut self) -> Result<(), WorkerError> {
        let child = match &mut self.state {
            SupervisorState::Running(child) | SupervisorState::Draining(child) => child,
            _ => return Ok(()),
        };
        read_nonblocking(child.exec_fd, &mut child.exec_error, &mut child.exec_eof, 4)
            .map_err(|_| WorkerError::Exec)?;
        if !child.exec_eof {
            return Ok(());
        }
        let output_cap = if child.ready_seen {
            MAX_RESPONSE_FRAME
        } else {
            MAX_RESPONSE_FRAME + READY.len()
        };
        read_nonblocking(
            child.stdout_fd,
            &mut child.output,
            &mut child.stdout_eof,
            output_cap,
        )
    }

    fn receive_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            self.apply_event(event);
        }
    }

    fn apply_event(&mut self, event: ActorEvent) {
        let child = match &mut self.state {
            SupervisorState::Running(child) | SupervisorState::Draining(child) => child,
            _ => return,
        };
        if child.token != event.token || child.pid != event.pid {
            return;
        }
        match event.kind {
            ActorEventKind::Group(ok) => {
                child.group_requested = false;
                child.group_verified = ok;
            }
            ActorEventKind::Wait(status) => child.wait_status = Some(status),
        }
    }

    fn begin_kill(&mut self) {
        let child = match &self.state {
            SupervisorState::Running(child) | SupervisorState::Draining(child) => child,
            _ => return,
        };
        let command = if child.group_verified {
            ActorCommand::KillGroup {
                token: child.token,
                pid: child.pid,
            }
        } else {
            ActorCommand::KillLeader {
                token: child.token,
                pid: child.pid,
            }
        };
        let _ = self.actor.send(command);
    }

    fn finish_or_drain(
        &mut self,
        result: Result<WorkerResponse, WorkerError>,
    ) -> Result<WorkerResponse, WorkerError> {
        self.receive_events();
        let state = std::mem::replace(&mut self.state, SupervisorState::Idle);
        self.state = match state {
            SupervisorState::Running(child) if child.wait_status.is_none() => {
                SupervisorState::Draining(child)
            }
            SupervisorState::Running(_) => SupervisorState::Idle,
            other => other,
        };
        result
    }

    fn refresh_draining(&mut self) {
        self.receive_events();
        let reaped =
            matches!(&self.state, SupervisorState::Draining(child) if child.wait_status.is_some());
        if reaped {
            self.state = SupervisorState::Idle;
        }
    }
}

impl Drop for JvmWorkerSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn worker_main(test_hook: WorkerTestHook) -> i32 {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = test_hook;
        return 70;
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getpgrp() } != unsafe { libc::getpid() } {
            return 71;
        }
        if install_descendant_filter().is_err() {
            return 79;
        }
        match test_hook {
            WorkerTestHook::PreReadyHang => loop {
                unsafe {
                    libc::pause();
                }
            },
            WorkerTestHook::InvalidReady => {
                let _ = std::io::stdout().write_all(b"INVALID READY\n");
                let _ = std::io::stdout().flush();
                return 72;
            }
            _ => {}
        }
        if std::io::stdout().write_all(READY).is_err() || std::io::stdout().flush().is_err() {
            return 73;
        }
        match test_hook {
            WorkerTestHook::PostReadyHang => loop {
                unsafe {
                    libc::pause();
                }
            },
            WorkerTestHook::Crash => {
                std::io::stdout().flush().ok();
                return 80;
            }
            WorkerTestHook::OversizeOutput => {
                let bytes = vec![0_u8; MAX_RESPONSE_FRAME + 1];
                if std::io::stdout().write_all(&bytes).is_err()
                    || std::io::stdout().flush().is_err()
                {
                    return 74;
                }
                loop {
                    unsafe { libc::pause() };
                }
            }
            _ => {}
        }
        let frame = match read_one_frame(&mut std::io::stdin(), MAX_REQUEST_FRAME) {
            Ok(frame) => frame,
            Err(()) => return 75,
        };
        let request = match decode_request(&frame) {
            Ok(request) => request,
            Err(_) => return 76,
        };
        match test_hook {
            WorkerTestHook::DescendantAttempt => {
                let result = unsafe { libc::syscall(libc::SYS_fork) };
                if result != -1 || last_errno() != libc::EPERM {
                    return 81;
                }
            }
            #[cfg(target_arch = "x86_64")]
            WorkerTestHook::X32SyscallAttempt => unsafe {
                libc::syscall(0x4000_0000_i64 | libc::SYS_getpid);
                return 82;
            },
            _ => {}
        }
        let response = aic_common::jvm_perfdata::capture_linux(&request);
        if std::io::stdout()
            .write_all(&encode_response(&response))
            .is_err()
        {
            return 77;
        }
        if test_hook == WorkerTestHook::TrailingOutput {
            let _ = std::io::stdout().write_all(b"x");
        }
        if std::io::stdout().flush().is_err() {
            return 78;
        }
        0
    }
}

fn read_one_frame(reader: &mut impl Read, cap: usize) -> Result<Vec<u8>, ()> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(|_| ())?;
    let body_len = u32::from_be_bytes(prefix) as usize;
    let total = body_len.checked_add(4).ok_or(())?;
    if total > cap {
        return Err(());
    }
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&prefix);
    frame.resize(total, 0);
    reader.read_exact(&mut frame[4..]).map_err(|_| ())?;
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(frame),
        _ => Err(()),
    }
}

fn actor_loop(commands: mpsc::Receiver<ActorCommand>) {
    let mut children = HashMap::<ChildToken, ActorChild>::new();
    loop {
        match commands.recv_timeout(Duration::from_millis(5)) {
            Ok(ActorCommand::Reserve {
                token,
                events,
                reply,
            }) => {
                let admitted = children.is_empty();
                if admitted {
                    let registration = Arc::new(Registration::new());
                    children.insert(
                        token,
                        ActorChild {
                            token,
                            pid: 0,
                            group_verified: false,
                            kill_started: None,
                            warned: false,
                            events,
                            registration: registration.clone(),
                        },
                    );
                    let _ = reply.send(Some(registration));
                } else {
                    let _ = reply.send(None);
                }
            }
            Ok(ActorCommand::Release { token }) => {
                if children.get(&token).is_some_and(|child| child.pid == 0) {
                    children.remove(&token);
                }
            }
            Ok(ActorCommand::VerifyGroup { token, pid }) => {
                if let Some(active) = children.get_mut(&token) {
                    if active.pid == 0 {
                        active.pid = active.registration.pid.load(Ordering::Acquire);
                    }
                }
                if let Some(active) = children.get_mut(&token).filter(|c| c.pid == pid) {
                    let ok = unsafe { libc::getpgid(pid) } == pid;
                    active.group_verified = ok;
                    let _ = active.events.send(ActorEvent {
                        token,
                        pid,
                        kind: ActorEventKind::Group(ok),
                    });
                }
            }
            Ok(ActorCommand::KillLeader { token, pid }) => {
                signal_child(&mut children, token, pid, false)
            }
            Ok(ActorCommand::KillGroup { token, pid }) => {
                signal_child(&mut children, token, pid, true)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            _ => {}
        }
        let tokens = children.keys().copied().collect::<Vec<_>>();
        for token in tokens {
            let Some(active) = children.get_mut(&token) else {
                continue;
            };
            if active.registration.cancelled.load(Ordering::Acquire) && active.pid == 0 {
                children.remove(&token);
                continue;
            }
            if active.pid == 0 {
                active.pid = active.registration.pid.load(Ordering::Acquire);
            }
            if active.pid == 0 {
                continue;
            }
            let mut status = 0;
            let result = unsafe { libc::waitpid(active.pid, &mut status, libc::WNOHANG) };
            if result == active.pid {
                let event = ActorEvent {
                    token: active.token,
                    pid: active.pid,
                    kind: ActorEventKind::Wait(status),
                };
                let _ = active.events.send(event);
                children.remove(&token);
            } else if let Some(started) = active.kill_started {
                if !active.warned && started.elapsed() >= REAP_WARNING_AFTER {
                    eprintln!("aicd: JVM PerfData worker did not exit within the reap grace");
                    active.warned = true;
                }
            }
        }
    }
}

fn signal_child(
    children: &mut HashMap<ChildToken, ActorChild>,
    token: ChildToken,
    pid: libc::pid_t,
    group: bool,
) {
    if let Some(active) = children.get_mut(&token) {
        if active.pid == 0 {
            active.pid = active.registration.pid.load(Ordering::Acquire);
        }
    }
    let Some(active) = children.get_mut(&token).filter(|c| c.pid == pid) else {
        return;
    };
    if group && !active.group_verified {
        return;
    }
    let target = if group { -pid } else { pid };
    let result = unsafe { libc::kill(target, libc::SIGKILL) };
    if result == 0 || last_errno() == libc::ESRCH {
        active.kill_started.get_or_insert_with(Instant::now);
    }
}

#[cfg(target_os = "linux")]
struct PreparedChild {
    token: ChildToken,
    executable: CString,
    arg0: CString,
    arg_worker: CString,
    arg_hook: CString,
    request_read: libc::c_int,
    request_write: libc::c_int,
    response_read: libc::c_int,
    response_write: libc::c_int,
    stderr_source: libc::c_int,
    exec_read: libc::c_int,
    exec_write: libc::c_int,
}

#[cfg(target_os = "linux")]
impl PreparedChild {
    fn new(path: &Path, hook: WorkerTestHook) -> Result<Self, WorkerError> {
        let token = ChildToken::generate(hook == WorkerTestHook::RandomFailure)?;
        let executable =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| WorkerError::Setup)?;
        let arg0 = executable.clone();
        let arg_worker = CString::new("--jvm-perfdata-worker").unwrap();
        let arg_hook =
            CString::new(format!("--jvm-perfdata-worker-test={}", hook.cli_value())).unwrap();
        let mut fds = SetupFds::default();
        let (request_read_raw, request_write_raw) = pipe_cloexec()?;
        fds.add(request_read_raw);
        fds.add(request_write_raw);
        let (response_read, response_write_raw) = pipe_cloexec()?;
        fds.add(response_read);
        fds.add(response_write_raw);
        let (exec_read, exec_write_raw) = pipe_cloexec()?;
        fds.add(exec_read);
        fds.add(exec_write_raw);
        let null = CString::new("/dev/null").unwrap();
        let stderr_raw = unsafe { libc::open(null.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if stderr_raw < 0 {
            return Err(WorkerError::Setup);
        }
        fds.add(stderr_raw);
        let request_read = fds.normalize(request_read_raw)?;
        let request_write = fds.normalize(request_write_raw)?;
        let response_read = fds.normalize(response_read)?;
        let response_write = fds.normalize(response_write_raw)?;
        let exec_read = fds.normalize(exec_read)?;
        let exec_write = fds.normalize(exec_write_raw)?;
        let stderr_source = fds.normalize(stderr_raw)?;
        if hook == WorkerTestHook::PartialSetupFailure {
            return Err(WorkerError::Setup);
        }
        set_nonblocking(response_read)?;
        set_nonblocking(exec_read)?;
        Ok(Self {
            token,
            executable,
            arg0,
            arg_worker,
            arg_hook,
            request_read: fds.take(request_read),
            request_write: fds.take(request_write),
            response_read: fds.take(response_read),
            response_write: fds.take(response_write),
            stderr_source: fds.take(stderr_source),
            exec_read: fds.take(exec_read),
            exec_write: fds.take(exec_write),
        })
    }

    fn retained_fds(&self) -> [libc::c_int; 7] {
        [
            self.request_read,
            self.request_write,
            self.response_read,
            self.response_write,
            self.stderr_source,
            self.exec_read,
            self.exec_write,
        ]
    }

    fn fork_exec(mut self, hook: WorkerTestHook) -> Result<ActiveChild, WorkerError> {
        if hook == WorkerTestHook::ForkFailure {
            return Err(WorkerError::Setup);
        }
        let token = self.token;
        let argv = [
            self.arg0.as_ptr(),
            self.arg_worker.as_ptr(),
            self.arg_hook.as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null()];
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(WorkerError::Setup);
        }
        if pid == 0 {
            unsafe {
                if libc::setpgid(0, 0) != 0 {
                    child_errno_exit(self.exec_write);
                }
                if libc::dup2(self.request_read, 0) < 0
                    || libc::dup2(self.response_write, 1) < 0
                    || libc::dup2(self.stderr_source, 2) < 0
                {
                    child_errno_exit(self.exec_write);
                }
                if libc::dup3(self.exec_write, 3, libc::O_CLOEXEC) < 0 {
                    child_errno_exit(self.exec_write);
                }
                if hook == WorkerTestHook::CloseRangeFailure {
                    child_errno_exit(3);
                }
                if libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) != 0 {
                    child_errno_exit(3);
                }
                libc::execve(self.executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
                child_errno_exit(3);
            }
        }
        for fd in [
            &mut self.request_read,
            &mut self.response_write,
            &mut self.stderr_source,
            &mut self.exec_write,
        ] {
            close_fd(fd);
        }
        let child = ActiveChild {
            token,
            pid,
            stdin_fd: self.request_write,
            stdout_fd: self.response_read,
            exec_fd: self.exec_read,
            exec_error: Vec::new(),
            output: Vec::new(),
            stdout_eof: false,
            exec_eof: false,
            wait_status: None,
            group_verified: false,
            group_requested: false,
            ready_seen: false,
        };
        self.request_write = -1;
        self.response_read = -1;
        self.exec_read = -1;
        Ok(child)
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct SetupFds(Vec<libc::c_int>);

#[cfg(target_os = "linux")]
impl SetupFds {
    fn add(&mut self, fd: libc::c_int) {
        self.0.push(fd);
    }

    fn close(&mut self, fd: libc::c_int) {
        if let Some(index) = self.0.iter().position(|candidate| *candidate == fd) {
            unsafe { libc::close(fd) };
            self.0.swap_remove(index);
        }
    }

    fn normalize(&mut self, raw: libc::c_int) -> Result<libc::c_int, WorkerError> {
        let high = duplicate_high(raw)?;
        self.add(high);
        self.close(raw);
        Ok(high)
    }

    fn take(&mut self, fd: libc::c_int) -> libc::c_int {
        let index = self
            .0
            .iter()
            .position(|candidate| *candidate == fd)
            .expect("setup descriptor must be owned");
        self.0.swap_remove(index)
    }
}

#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn fd_setup_test_main() -> i32 {
    let open_standard_flags = [1, 2].map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) });
    let originally_closed = [0, 3]
        .map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 && last_errno() == libc::EBADF);
    if !originally_closed.into_iter().all(|closed| closed) {
        return 90;
    }
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return 91,
    };
    let prepared = match PreparedChild::new(&executable, WorkerTestHook::Normal) {
        Ok(prepared) => prepared,
        Err(_) => return 92,
    };
    let fds = prepared.retained_fds();
    if fds.iter().any(|fd| *fd < CHILD_FD_BASE) {
        return 93;
    }
    let mut unique = fds.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != fds.len() {
        return 94;
    }
    drop(prepared);
    if [0, 3]
        .into_iter()
        .any(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1 || last_errno() != libc::EBADF)
    {
        return 95;
    }
    if [1, 2]
        .into_iter()
        .map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) })
        .ne(open_standard_flags)
    {
        return 96;
    }
    0
}

#[cfg(target_os = "linux")]
impl Drop for SetupFds {
    fn drop(&mut self) {
        for fd in self.0.drain(..) {
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PreparedChild {
    fn drop(&mut self) {
        for fd in [
            &mut self.request_read,
            &mut self.request_write,
            &mut self.response_read,
            &mut self.response_write,
            &mut self.stderr_source,
            &mut self.exec_read,
            &mut self.exec_write,
        ] {
            close_fd(fd);
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn child_errno_exit(fd: libc::c_int) -> ! {
    let errno = *libc::__errno_location();
    let bytes = errno.to_ne_bytes();
    libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    libc::_exit(127);
}

fn pipe_cloexec() -> Result<(libc::c_int, libc::c_int), WorkerError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(WorkerError::Setup);
    }
    Ok((fds[0], fds[1]))
}

fn duplicate_high(fd: libc::c_int) -> Result<libc::c_int, WorkerError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, CHILD_FD_BASE) };
    if duplicated < CHILD_FD_BASE {
        Err(WorkerError::Setup)
    } else {
        Ok(duplicated)
    }
}

fn set_nonblocking(fd: libc::c_int) -> Result<(), WorkerError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        Err(WorkerError::Setup)
    } else {
        Ok(())
    }
}

fn read_nonblocking(
    fd: libc::c_int,
    buffer: &mut Vec<u8>,
    eof: &mut bool,
    cap: usize,
) -> Result<(), WorkerError> {
    if fd < 0 || *eof {
        return Ok(());
    }
    let mut scratch = [0_u8; 4096];
    loop {
        let read = unsafe { libc::read(fd, scratch.as_mut_ptr().cast(), scratch.len()) };
        if read > 0 {
            let count = read as usize;
            if buffer.len().saturating_add(count) > cap {
                return Err(WorkerError::Protocol);
            }
            buffer.extend_from_slice(&scratch[..count]);
        } else if read == 0 {
            *eof = true;
            return Ok(());
        } else {
            let errno = last_errno();
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Ok(());
            }
            if errno == libc::EINTR {
                continue;
            }
            return Err(WorkerError::Protocol);
        }
    }
}

fn write_all_fd(fd: libc::c_int, bytes: &[u8]) -> Result<(), WorkerError> {
    let mut written = 0;
    while written < bytes.len() {
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count > 0 {
            written += count as usize;
        } else if count < 0 && last_errno() == libc::EINTR {
            continue;
        } else {
            return Err(WorkerError::Protocol);
        }
    }
    Ok(())
}

fn close_fd(fd: &mut libc::c_int) {
    if *fd >= 0 {
        unsafe {
            libc::close(*fd);
        }
        *fd = -1;
    }
}
fn last_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}
fn wifexited_zero(status: libc::c_int) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn joined_response(
    output: &[u8],
    stdout_eof: bool,
    wait_status: Option<libc::c_int>,
    request_sent: bool,
) -> Option<Result<WorkerResponse, WorkerError>> {
    if !stdout_eof {
        return None;
    }
    let status = wait_status?;
    if !wifexited_zero(status) {
        return Some(Err(WorkerError::Crash));
    }
    if !request_sent {
        return Some(Err(WorkerError::Protocol));
    }
    Some(decode_response(output).map_err(|_| WorkerError::Protocol))
}

#[cfg(target_os = "linux")]
fn install_descendant_filter() -> Result<(), ()> {
    const LOAD_WORD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const LOAD_ARCH: libc::sock_filter = libc::sock_filter {
        code: LOAD_WORD,
        jt: 0,
        jf: 0,
        k: 4,
    };
    const LOAD_SYSCALL: libc::sock_filter = libc::sock_filter {
        code: LOAD_WORD,
        jt: 0,
        jf: 0,
        k: 0,
    };
    const ALLOW: libc::sock_filter = libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    };
    const DENY: libc::sock_filter = libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    };
    const KILL: libc::sock_filter = libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_KILL_PROCESS,
    };
    #[cfg(target_arch = "x86_64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "x86")]
    const NATIVE_AUDIT_ARCH: u32 = 0x4000_0003;
    #[cfg(target_arch = "arm")]
    const NATIVE_AUDIT_ARCH: u32 = 0x4000_0028;

    let mut filters = Vec::with_capacity(16);
    filters.push(LOAD_ARCH);
    filters.push(libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: 1,
        jf: 0,
        k: NATIVE_AUDIT_ARCH,
    });
    filters.push(KILL);
    filters.push(LOAD_SYSCALL);
    #[cfg(target_arch = "x86_64")]
    {
        filters.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        });
        filters.push(KILL);
    }
    for syscall in [
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_fork,
        libc::SYS_vfork,
    ] {
        filters.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filters.push(DENY);
    }
    filters.push(ALLOW);
    let mut program = libc::sock_fprog {
        len: u16::try_from(filters.len()).map_err(|_| ())?,
        filter: filters.as_mut_ptr(),
    };
    let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privileges != 0 {
        return Err(());
    }
    let seccomp = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            (&mut program as *mut libc::sock_fprog) as libc::c_ulong,
            0,
            0,
        )
    };
    if seccomp != 0 {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{joined_response, ChildToken};
    use aic_common::jvm_perfdata::{encode_response, WorkerFailure, WorkerResponse};

    #[test]
    fn child_tokens_are_nonzero_and_distinct() {
        let first = ChildToken::generate(false).unwrap();
        let second = ChildToken::generate(false).unwrap();
        assert_ne!(first.0, [0; 16]);
        assert_ne!(first, second);
    }

    #[test]
    fn child_token_generation_failure_is_closed() {
        assert!(ChildToken::generate(true).is_err());
    }

    #[test]
    fn response_join_is_order_independent() {
        let output = encode_response(&WorkerResponse::Failure(WorkerFailure::Rejected));
        assert!(joined_response(&output, true, None, true).is_none());
        assert!(joined_response(&output, false, Some(0), true).is_none());
        assert_eq!(
            joined_response(&output, true, Some(0), true)
                .unwrap()
                .unwrap(),
            WorkerResponse::Failure(WorkerFailure::Rejected)
        );
    }
}
