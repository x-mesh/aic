#![cfg(target_os = "linux")]

use aic_common::jvm_perfdata::WorkerRequest;
use aic_server::jvm_perfdata_worker::{JvmWorkerSupervisor, WorkerError, WorkerTestHook};
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

fn request() -> WorkerRequest {
    WorkerRequest {
        pid: std::process::id(),
        start_ticks: 0,
        selector_digest_version: 1,
        selector_digest: [0; 32],
        opaque_workload_id: [0; 16],
    }
}

fn supervisor(hook: WorkerTestHook) -> JvmWorkerSupervisor {
    JvmWorkerSupervisor::with_executable_and_hook(PathBuf::from(env!("CARGO_BIN_EXE_aicd")), hook)
}

fn test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // The daemon-wide actor reaps a prior test after its supervisor returns.
    thread::sleep(Duration::from_millis(20));
    guard
}

#[test]
fn invalid_ready_fails_closed() {
    let _guard = test_guard();
    let error = supervisor(WorkerTestHook::InvalidReady)
        .capture(request())
        .unwrap_err();
    assert!(matches!(
        error,
        WorkerError::InvalidReady | WorkerError::Crash
    ));
}

#[test]
fn pre_ready_hang_times_out_and_drains() {
    let _guard = test_guard();
    let mut supervisor = supervisor(WorkerTestHook::PreReadyHang);
    assert_eq!(
        supervisor.capture(request()).unwrap_err(),
        WorkerError::Timeout
    );
    assert_eq!(
        supervisor.capture(request()).unwrap_err(),
        WorkerError::Busy
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.is_draining() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!supervisor.is_draining());
}

#[test]
fn post_ready_hang_uses_the_same_deadline() {
    let _guard = test_guard();
    let started = Instant::now();
    let error = supervisor(WorkerTestHook::PostReadyHang)
        .capture(request())
        .unwrap_err();
    assert_eq!(error, WorkerError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn close_range_failure_is_reported_through_exec_pipe() {
    let _guard = test_guard();
    let error = supervisor(WorkerTestHook::CloseRangeFailure)
        .capture(request())
        .unwrap_err();
    assert_eq!(error, WorkerError::Exec);
}

#[test]
fn crash_and_oversize_output_fail_closed() {
    let _guard = test_guard();
    let crash = supervisor(WorkerTestHook::Crash)
        .capture(request())
        .unwrap_err();
    assert!(matches!(crash, WorkerError::Crash | WorkerError::Protocol));

    let oversize = supervisor(WorkerTestHook::OversizeOutput)
        .capture(request())
        .unwrap_err();
    assert_eq!(oversize, WorkerError::Protocol);
}

#[test]
fn trailing_output_is_rejected() {
    let _guard = test_guard();
    let error = supervisor(WorkerTestHook::TrailingOutput)
        .capture(request())
        .unwrap_err();
    assert!(matches!(error, WorkerError::Protocol | WorkerError::Crash));
}

#[test]
fn shutdown_reaps_an_active_worker() {
    let _guard = test_guard();
    let mut supervisor = supervisor(WorkerTestHook::PreReadyHang);
    let _ = supervisor.capture(request());
    supervisor.shutdown();
    drop(supervisor);
}

#[test]
fn dropping_a_hung_supervisor_never_waits_for_reap() {
    let _guard = test_guard();
    let started = Instant::now();
    let mut supervisor = supervisor(WorkerTestHook::PreReadyHang);
    let _ = supervisor.capture(request());
    drop(supervisor);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn global_reservation_blocks_a_second_supervisor_before_fork() {
    let _guard = test_guard();
    let first = thread::spawn(|| {
        let mut first = supervisor(WorkerTestHook::PreReadyHang);
        first.capture(request())
    });
    thread::sleep(Duration::from_millis(30));

    let mut second = supervisor(WorkerTestHook::InvalidReady);
    assert_eq!(second.capture(request()).unwrap_err(), WorkerError::Busy);
    assert_eq!(first.join().unwrap().unwrap_err(), WorkerError::Timeout);

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let result = second.capture(request());
        if !matches!(result, Err(WorkerError::Busy)) {
            assert!(matches!(
                result,
                Err(WorkerError::InvalidReady | WorkerError::Crash)
            ));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "global actor did not release the reaped slot"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn installed_seccomp_filter_denies_a_descendant() {
    let _guard = test_guard();
    let result = supervisor(WorkerTestHook::DescendantAttempt).capture(request());
    assert!(
        result.is_ok(),
        "descendant syscall escaped the installed filter: {result:?}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn installed_seccomp_filter_kills_an_x32_syscall() {
    let _guard = test_guard();
    let error = supervisor(WorkerTestHook::X32SyscallAttempt)
        .capture(request())
        .unwrap_err();
    assert_eq!(error, WorkerError::Crash);
}

#[test]
fn partial_setup_failures_do_not_leak_descriptors() {
    let _guard = test_guard();
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    for _ in 0..32 {
        assert_eq!(
            supervisor(WorkerTestHook::PartialSetupFailure)
                .capture(request())
                .unwrap_err(),
            WorkerError::Setup
        );
    }
    let after = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert_eq!(before, after);
}

#[test]
fn preparation_preserves_closed_standard_descriptors_in_a_subprocess() {
    let _guard = test_guard();
    let executable = CString::new(env!("CARGO_BIN_EXE_aicd")).unwrap();
    let argument = CString::new("--jvm-perfdata-fd-setup-test").unwrap();
    let argv = [executable.as_ptr(), argument.as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null()];
    let pid = unsafe { libc::fork() };
    assert!(pid > 0);
    if pid == 0 {
        unsafe {
            libc::close(0);
            libc::close(3);
            libc::execve(executable.as_ptr(), argv.as_ptr(), environment.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            break;
        }
        assert!(waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR));
    }
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "FD setup helper failed with wait status {status}"
    );
}
