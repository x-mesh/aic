# RFC-007: JVM HotSpot PerfData Monitor

- Status: Proposed
- Security review: Required
- Platform: Linux only
- Scope: Opt-in local HotSpot PerfData MVP
- Implementation gate: Closed until every approval gate in this RFC passes

## 1. Current State

AIC can discover JVM processes. The JVM adapter has `detect_only` mode.

AIC does not read JVM service metrics. It records `not_collected` for saved JVM definitions.

This RFC defines the contract for a local HotSpot PerfData monitor. Implementation requires a separate security review.

## 2. Goals

The MVP will read bounded numeric metrics from a local HotSpot PerfData file.

The monitor will support Linux hosts. It will require explicit user opt-in for each JVM definition.

The monitor will bind each definition to one process identity. It will reject stale identities and PID reuse.

The monitor will use the existing one-shot, daemon, status, and history interfaces.

The monitor will expose a small stable metric set. Optional capabilities can add bounded metric groups.

## 3. Non-goals

The MVP will not use Attach API, JMX, JVMTI, or a Java agent.

The MVP will not open a network connection. It will not send a signal to the JVM.

The MVP will not change privileges, namespaces, process state, or JVM state.

The MVP will not read environment variables, system properties, class names, or arbitrary raw strings.

The identity worker can read bounded command arguments only for selector verification. It must not return or persist those bytes.

The MVP will not support arbitrary `TMPDIR` values or unrestricted filesystem searches.

The MVP will not support macOS. It will not infer a macOS PerfData path.

The MVP will not map PerfData into the daemon address space. It will not parse untrusted bytes inside `aicd`.

## 4. User Contract

### 4.1 Explicit opt-in

Discovery will remain read-only. Discovery will not enable the JVM monitor.

The user must enable one discovered JVM candidate with exactly one runtime binding.

Enablement must reread raw start ticks from procfs. The saved JVM monitor configuration stores those raw ticks and the PID.

The CLI must state that the monitor reads a same-UID local JVM PerfData file.

The daemon must not create JVM definitions. It must not enable new JVM candidates.

### 4.2 Same UID

The AIC process must not run as root. The AIC process and JVM process must have the same effective UID.

Read `/proc/<pid>/status` with a 64 KiB cap and one extra byte for EOF proof. Reject truncation, NUL, or incomplete data.

Parse one `Uid:` line with four unsigned decimal fields. Use the second field as the effective UID.

Reject duplicate lines or extra fields.

The monitor must compare the effective UID with `geteuid()`. It must reject any mismatch.

The monitor must reject an effective UID of zero. It must not use root access to bypass this rule.

The monitor must compare the user, PID, and mount namespace identities for AIC and the JVM.

Open `/proc/self` and `/proc/<pid>` as directory descriptors. Keep both descriptors for the complete capture.

Open `ns/user`, `ns/pid`, and `ns/mnt` relative to each proc descriptor with `O_RDONLY | O_CLOEXEC`.

These opens follow procfs namespace magic links to the namespace objects. Do not apply `O_NOFOLLOW` to namespace entries.

Compare each self and target namespace object by device and inode. Reject missing, inaccessible, or different objects.

After capture, open all six namespace objects again. Compare each new object with its original descriptor and matching peer.

Container and cross-namespace collection require a separate privileged design. V1 must not fall back to host paths.

### 4.3 Process identity

The saved identity must contain `pid` and raw Linux process start ticks.

Read raw start ticks from field 22 of `/proc/<pid>/stat` during enablement. Do not store `sysinfo::Process::start_time()` for authorization.

Enablement requires exactly one current, unambiguous runtime binding for the saved selector.

Each probe verifies only the saved PID and saved identity. A later process with the same selector does not change that binding.

Read at most 4 KiB from `/proc/<pid>/stat` and prove EOF with one extra byte. Reject NUL, truncation, and incomplete data.

Find the last `) ` delimiter. Tokenize from field 3. Parse zero-based tail token 19 as field 22.

Accept only unsigned ASCII decimal raw ticks that fit `u64`. Use the same parser during enablement and capture.

Compare the current start time with the saved start time. Reject a mismatch as `identity_changed`.

Open `/proc/<pid>` once as a directory descriptor. Resolve `exe` with `readlinkat` into a 4,097-byte buffer.

Reject empty output or a 4,097-byte result. Treat executable bytes as an opaque byte string, not UTF-8.

Read `/proc/<pid>/cmdline` repeatedly until EOF or 64 KiB. Reject a read that fills the 64 KiB cap before EOF.

Split the complete NUL-delimited arguments and apply the current bounded main-token rules.

Require a NUL-terminated complete stream below the cap. Reject a cap hit, missing terminator, or partial argument as `limit_exceeded`.

Canonicalize the selector digest with this byte format:

- One protocol version byte. V1 uses `0x01`.
- One little-endian `u16` executable length, then the executable bytes.
- One little-endian `u16` main-token length, then the main-token bytes.

Reject a component that exceeds `u16::MAX` before hashing.

Hash the canonical bytes with SHA-256. Compare the result with the saved selector digest. Reject a mismatch.

This selector digest is the only executable identity field. It authenticates both executable bytes and the bounded main token.

Never emit, log, or persist the bytes read from `cmdline` or the resolved executable path.

Repeat the binding, start time, executable, selector, UID, and namespace checks after capture. Reject any change.

These checks prevent a reused PID from inheriting an old JVM definition.

## 5. Trusted Path Contract

### 5.1 Candidate roots

Use a fixed candidate set. Do not read `TMPDIR` from the target process.

The initial Linux candidate root is `/tmp`. A later PR can add a root only after a separate security review.

Read `/proc/<pid>/status` and obtain the effective UID. Enumerate the opened `/tmp` descriptor to EOF within fixed caps.

Read direct entries with repeated bounded `getdents64` calls and a fixed 16 KiB buffer. Retry `EINTR` within the probe deadline.

Parse each record as bytes with a 19-byte Linux `linux_dirent64` header. Do not cast unaligned records to a struct.

Validate remaining bytes, `reclen >= 20`, `reclen <= remaining`, progress, and a NUL inside the record name area.

Do not use `d_type` as trust evidence. Continue until `getdents64` returns zero.

Inspect at most 4,096 total entries and at most 256 entries with the exact `hsperfdata_` prefix.

After processing exactly 4,096 total entries, continue the current buffer only to prove that it has no additional record.

Then make one additional `getdents64` call that must return EOF. Reject any record beyond the total cap.

Reject a 257th prefix entry immediately. Uniqueness is valid only after proven EOF.

Use each bounded prefix entry name as a locator. Do not derive or trust a username.

Open each candidate directory by descriptor. Keep only the unique directory whose owner matches the effective UID and trust checks.

Reject zero or multiple trusted directories. This bounded scan does not use NSS, LDAP, SSSD, or process environment data.

Treat the entry name only as a locator. Never use its text as authorization evidence.

Do not use glob expansion, recursive scans, account lookup, or a first-match winner.

Validate every bounded direct candidate before uniqueness selection.

Do not scan other users, arbitrary directories, or recursive paths. Do not accept a user-supplied PerfData path.

### 5.2 Directory checks

Open `/tmp` with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. Verify that it is a directory owned by UID zero.

Require mode `01777`. Reject another owner, missing sticky bit, or group and other permissions that differ from `01777`.

Open the root by file descriptor. Record its device and inode for the complete capture.

Open each candidate with Linux `openat2` and `O_RDONLY | O_DIRECTORY | O_CLOEXEC`.

Use `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`. Reject unavailable `openat2` or unsupported resolve flags.

This policy forbids candidate mountpoints and requires the candidate directory to remain on the `/tmp` filesystem.

After open, use `fstat` on the directory descriptor. Apply these checks:

- The object must be a directory.
- The owner UID must equal the JVM UID.
- Group-write and other-write bits must be clear.
- The link count must not be zero.
- The object must not be a symbolic link.
- The device must equal the trusted root device.
Reject the directory if any check fails. Do not fall back to a less trusted path.

Before capture, call `fstat` again on the root and selected directory descriptors. Repeat every original type, UID, mode, link, device, and inode check.

After capture, repeat the complete descriptor policy checks. Then reopen the same entry locator relative to the root descriptor.

Compare the reopened directory device and inode with the selected directory descriptor. Never read data from the reopened descriptor.

### 5.3 File checks

Open the decimal PID file with `openat2` relative to the verified directory.

Use `O_RDONLY | O_NONBLOCK | O_CLOEXEC` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`.

After open, use `fstat` on the file descriptor. Apply these checks:

- The object must be a regular file.
- The owner UID must equal the JVM UID.
- The link count must equal one.
- Group-write and other-write bits must be clear.
- The file size must be greater than the prologue size.
- The file size must not exceed 1 MiB.
- The file device must match the verified directory filesystem.

Do not use path metadata as the final authority. The post-open `fstat` result is authoritative.

Read only from the verified descriptor. Never reopen a locator to read PerfData.

The later locator reopen is an identity check only. It must not replace the captured descriptor.

Read with bounded `pread` calls. Do not use `mmap`, pathname reads, or a shared offset.

Read exactly 32 bytes as prologue `P1` with bounded `pread`. Reject short reads and EOF.

Validate `P1` and require `used <= initial fstat size <= 1 MiB`. The opened file size is the external capacity bound.

Read exactly `used` bytes as snapshot `S` with bounded `pread`. Reject short reads and EOF.

Parse `S`, then read exactly 32 bytes as prologue `P2` from the same descriptor.

Compare required structural fields for `P1`, the copied prologue in `S`, and `P2`.

Compare magic, accessibility, version, byte order, `used`, overflow, modification timestamp, entry offset, and entry count.

Call `fstat` after `P2`. Reject a changed device, inode, file type, owner, link count, mode policy, or file size.

This check provides structural consistency. It does not claim an atomic snapshot of counters that change during collection.

After capture, reopen the decimal PID locator relative to the selected directory descriptor with the same safe flags.

Compare the reopened file device and inode with the captured file descriptor. Never read data from the reopened descriptor.

### 5.4 Capture and parser isolation

The complete production capture must run in a separate worker process. The parent must not open or read PerfData.

The worker receives only an opaque request with PID, expected raw start ticks, selector digest, opaque workload ID, and protocol version.

The worker must clear inherited environment values. It must close unrelated file descriptors before capture.

The worker must perform namespace, identity, path, descriptor, `pread`, consistency, and parser checks.

The worker must not accept a path, username, raw selector, environment value, or PerfData descriptor from the parent.

The parent must cap worker input at 1 MiB and typed output at 64 KiB. It must reject trailing output.

The parent prepares the executable path, fixed arguments, fixed empty environment, pipes, and all C strings before the deadline.

The parent creates every pipe with `O_CLOEXEC`. It does not change descriptors `0`, `1`, `2`, or `3` before `fork`.

Use `F_DUPFD_CLOEXEC` before `fork` to place each child-side source descriptor at a unique number of at least 64.

Reject duplicate source descriptors or a source descriptor below 64. Prepare all mappings before the deadline.

The parent starts the 200 ms deadline immediately before Linux `fork`.

The child calls only async-signal-safe syscalls before `execve`.

Allowed calls are `setpgid`, `dup2`, `dup3`, `close_range`, `write`, `execve`, and `_exit`.

The child must not allocate, lock, log, unwind, or call Rust library code before `execve`.

The child calls `setpgid(0, 0)`. It maps the prepared stdin, stdout, and stderr sources with `dup2`.

The child maps the exec-error source to descriptor `3` with `dup3` and `O_CLOEXEC`.

The child calls raw `close_range(4, UINT_MAX, 0)`, then calls `execve`.

If `close_range` fails, write its fixed errno to descriptor `3` and call `_exit`.

Reject kernels without `close_range`. Do not fall back to descriptor enumeration or `/proc/self/fd`.

The fixed `execve` environment is empty. An exec-error pipe reports a fixed numeric errno and then calls `_exit`.

Successful `execve` closes the exec-error descriptor through `FD_CLOEXEC`. The parent requires EOF on that pipe before READY acceptance.

The parent receives the PID directly from `fork`. It does not wait for an exec handshake inside worker creation.

Generate a random 128-bit `ChildToken` before the deadline. A successful `fork` activates the prepared token.

The singleton lifecycle actor receives the token and PID immediately. It alone calls `getpgid`, `kill`, and `waitpid`.

The actor serializes `VerifyGroup`, `KillLeader`, `KillGroup`, and `PollExit` commands for each token.

The supervisor never sends a signal or calls `waitpid`. It sends token-scoped commands to the actor.

The actor never signals a PID after it has reaped that token. It never reuses a token.

The supervisor state is `Idle`, `Running`, or `Draining`. Every non-idle state contains the token and PID.

Each state stores `candidate_frame`, `stdout_eof`, and `wait_status` as independent optional values.

The actor returns `LifecycleEvent { token, pid, group_state, wait_status }` through a typed channel.

The supervisor accepts an event only when its token and PID match the current state. It ignores stale events.

After successful `execve`, the worker verifies `getpgrp() == getpid()` and sends one fixed `READY` frame.

The supervisor sends `VerifyGroup` after READY. The actor verifies `getpgid(pid) == pid`.

The actor then emits a verified-group `LifecycleEvent`. The supervisor sends the request only after that event.

The worker must not call `fork`, `clone`, or spawn a process.

The descendant prohibition applies before READY and for the complete worker lifetime.

Before group verification, timeout, invalid READY, exec failure, or group failure triggers actor command `KillLeader`.

The actor implements `KillLeader` with `kill(pid, SIGKILL)`. It never signals `-pid` before verified group state.

After group verification, timeout triggers actor command `KillGroup`. Discard all candidate output before the command.

The actor implements `KillGroup` with `kill(-pid, SIGKILL)`. Treat `ESRCH` as an exit-poll condition.

The 200 ms deadline does not include process reaping. The lifecycle actor uses a one-second observation grace.

The JVM worker slot remains `Draining` until a matching lifecycle event contains final wait status.

No new JVM worker can start while the slot drains.

Other workload adapters continue while the JVM worker drains. Daemon shutdown sends a token-scoped kill command to the actor.

If the child remains after the grace, emit one fixed warning.

Keep JVM collection disabled until the lifecycle actor confirms final wait status.

The worker must use a fixed internal protocol version. It must return typed numeric metrics or one fixed failure category.

Read stdout into one bounded candidate frame while the child runs. Record the frame and EOF independently.

Record matching wait status independently of stdout order. Preserve a completion that arrives before EOF.

Accept output only when frame, EOF, and wait status exist for the same token and PID.

Require normal exit status zero. A timeout discards the frame and moves the state to `Draining`.

Require exactly one frame and no trailing data. Reject signal exits, nonzero exits, missing EOF, or mismatched completion.

The daemon must enforce one active JVM worker. It must not start an unbounded worker thread or process per interval.

## 6. Resource Limits

Apply all limits before metric conversion. Reject data that exceeds any limit.

| Resource | Limit |
| --- | ---: |
| PerfData file | 1 MiB |
| Parsed entries | 4,096 |
| Entry name | 256 bytes |
| String value | 4 KiB |
| Worker setup and probe execution | 200 ms |
| Reap observation grace | 1 second |

The parser must use checked arithmetic for every offset, length, count, and alignment operation.

The probe deadline includes handshake, identity checks, filesystem checks, `pread`, parsing, conversion, and output validation.

If the deadline expires before group verification, kill only the leader. Otherwise, kill the verified group.

The lifecycle actor is the only `waitpid` owner. It prevents another JVM worker until it confirms child exit.

## 7. PerfData Validation

### 7.1 Prologue

Use bounded `pread` calls to copy the validated `used` region after the post-open checks.

Validate the PerfData magic value. Derive byte order only from the valid prologue byte-order field.

Accept only explicitly supported major and minor versions. The first implementation must list these versions in tests.

Validate `used` and `capacity` with these rules:

- `used` must include the complete prologue.
- `used` must not exceed `capacity`.
- `capacity` must not exceed the opened file size.
- The opened file size must not exceed 1 MiB.

Reject an inaccessible prologue. Accept only the documented accessible value.

The worker reads the live prologue before the snapshot. It reads it again after parsing and before it emits typed output.

The worker accepts the snapshot only if all structural prologue fields remain consistent.

### 7.2 Entries

Start at the prologue entry offset. Stop only at the validated `used` boundary.

Validate each entry length, data offset, vector length, type, units, variability, and flags.

Each entry must remain inside the `used` boundary. Each next entry must advance the cursor.

Validate every required alignment boundary. Reject misaligned entry headers or values.

Each entry name must contain a NUL byte within 256 bytes. Reject embedded trailing data after the first NUL.

Each accepted string must contain a NUL byte within 4 KiB. The MVP will not persist string values.

Reject duplicate names for required metrics. Ignore unknown entries only after full structural validation.

Stop after 4,096 entries. Reject a buffer that requires more entries.

### 7.3 Snapshot consistency

The parser must not accept structurally unstable data from an active writer.

Compare the live prologue before `pread`, the copied prologue, and the live prologue after worker completion.

Reject changes to accessibility, version, byte order, `used`, capacity, entry offset, or modification timestamp.

The worker can retry one unstable snapshot if the complete 200 ms deadline still permits it.

Do not retry path trust, identity, namespace, format, or limit failures.

Counter values can change while `pread` copies the file. The MVP reports a bounded observational sample, not a transactionally atomic JVM snapshot.

## 8. Metric Contract

### 8.1 Required metrics

The fixture spike must prove a stable semantic mapping before PR 1 receives approval.

Each mapping records JDK vendor, major version, counter aliases, raw type, units, variability, scale, and typed output field.

The fixture spike removed `uptime_millis`. JDK 25 does not expose `sun.os.hrt.ticks`.

Do not derive uptime from `sun.rt.applicationTime`. That counter excludes JVM activity outside application execution.

The required outputs are:

| Output | Type and unit | Semantic rule |
| --- | --- | --- |
| `threads_started_total` | Nonnegative `u64` count | Use cumulative `java.threads.started`. |
| `threads_live` | Nonnegative `u64` count | Current live Java threads. Do not include an alias with different thread semantics. |
| `threads_peak` | Nonnegative `u64` count | Highest live Java thread count since JVM start. Require `threads_peak >= threads_live`. |
| `threads_daemon` | Nonnegative `u64` count | Current live daemon threads. Require `threads_daemon <= threads_live`. |
| `classes_loaded` | Nonnegative `u64` count | Sum loaded and shared-loaded totals, then subtract both unloaded totals. |
| `classes_unloaded_total` | Nonnegative `u64` count | Sum unloaded and shared-unloaded totals. |

Raw PerfData integer widths can be signed. Reject negative values and checked-conversion overflow.

The implementation must define an explicit versioned counter-name alias map for every supported fixture.

V1 supports Eclipse Temurin OpenJDK builds only. Other vendors require separate fixture and live evidence.

Do not approve a required output until Temurin 17, 21, and 25 sanitized captures prove the same meaning and unit.

The raw required allowlist contains four thread counters and four class counters. All are scalar signed 64-bit values.

The thread counters are `java.threads.started`, `live`, `livePeak`, and `daemon`.

The class counters are `java.cls.loadedClasses`, `sharedLoadedClasses`, `unloadedClasses`, and `sharedUnloadedClasses`.

If the spike cannot prove one required output, remove it or stop implementation. Do not infer aliases from name similarity.

All required metrics must exist and have valid numeric types. Otherwise, classify the snapshot as `malformed`.

Convert values with checked conversions. Reject negative values for unsigned metric fields.

### 8.2 Optional capabilities

Optional capabilities can expose these numeric groups:

- Garbage collection counts and elapsed times.
- Heap capacity and used bytes.
- Metaspace capacity and used bytes.
- Compilation count and elapsed time.

Each capability must have an explicit allowlist and a typed schema. Unknown collectors must not create dynamic metric names.

Absence of an optional capability must not fail the required metric probe.

Malformed structural data always fails the complete probe. A structurally valid optional value with an invalid numeric type omits that capability and records no zero.

The history schema must identify each available capability. It must not infer zero for an absent capability.

### 8.3 Data exclusion

Do not persist raw filesystem paths. Do not persist PerfData entry names.

Do not persist string values, process arguments, JVM arguments, environment data, or system properties.

Do not put excluded data in errors, logs, status output, audit records, or history.

Use fixed error messages. A diagnostic can include a bounded failure category and the workload identifier.

JVM history must use a random opaque 128-bit identifier encoded as 32 lowercase hexadecimal characters.

Generate the identifier with the operating-system CSPRNG during enablement. Store it in the `0600` workload definition.

Reject an identifier collision with any saved definition. Do not regenerate an identifier during update, restart, or PID revalidation.

Disabling and enabling a definition creates a new opaque identifier. V1 has no legacy JVM monitor definition to migrate.

History must use only this opaque identifier. It must not use the executable path or main class.

The configured selector remains in the `0600` definition file. `list`, `inspect`, and discovery output can show it during explicit local queries.

Status, history, logs, errors, audit events, and samples must not show the selector, executable, PID, username, or path.

### 8.4 Schema and compatibility

Keep `WorkloadDefinition.id` as the selector-derived lookup ID. Existing `enable`, `list`, `status`, and `history` commands keep this argument.

Add optional JVM-only fields under a new `monitor_identity` object. Old definitions deserialize with no object and remain discovery-only.

The object contains PID, raw start ticks, selector digest version, selector digest, and opaque monitor ID.

JVM samples set `workload_id` to the opaque monitor ID. They never copy `WorkloadDefinition.id` into JSONL.

`aic workload history <definition-id>` resolves the configured definition first. It then filters JVM samples by the stored opaque monitor ID.

Status performs the same mapping. `list`, `inspect`, and `enable` continue to use the selector-derived definition ID.

Public JVM status and history identify samples only by the opaque monitor ID.

Increment `WORKLOAD_SAMPLE_SCHEMA_VERSION` for the new `Jvm` metric variant. Preserve legacy sample deserialization without new fields.

Add `WorkloadMetrics::Jvm` with a tagged, typed metric object. Reject adapter and metric-variant mismatches.

Collected JVM outcomes use endpoint label `local-hotspot-perfdata`. They never store a filesystem path.

Map JVM worker failure codes to the existing wire categories:

- `unreachable`: process or verified file disappeared, or bounded local I/O failed.
- `rejected`: opt-in, root, UID, namespace, identity, or path policy failed.
- `malformed`: format, snapshot, metric, protocol, or resource limit validation failed.

Keep detailed internal codes only in fixed local debug counters. Do not add them to sample details or raw errors.

## 9. Failure Taxonomy

Each failed probe must produce one stable category. It must not expose raw paths or PerfData content.

| Category | Meaning |
| --- | --- |
| `not_enabled` | The JVM definition lacks explicit opt-in. This state does not create a sample. |
| `unsupported_platform` | The host is not Linux. This state remains `not_collected`. |
| `process_missing` | The bound PID no longer exists. |
| `identity_changed` | The current raw procfs start ticks differ from the saved raw ticks. |
| `uid_mismatch` | AIC and the JVM have different effective UIDs. |
| `path_untrusted` | A root, directory, or file fails a trust check. |
| `perfdata_missing` | No file exists at the bounded trusted candidate path. |
| `unreachable` | A verified local file cannot be opened or read. |
| `rejected` | Policy rejects the candidate before parsing. |
| `unsupported_format` | The PerfData version or byte order lacks support. |
| `malformed` | The prologue, entry table, required metrics, or snapshot consistency is invalid. |
| `limit_exceeded` | A size, count, name, string, or time cap is exceeded. |

The daemon must isolate a JVM probe failure from other workload adapters.

Repeated `malformed`, `path_untrusted`, `unsupported_format`, or `limit_exceeded` failures use bounded backoff.

Backoff skips 1, 2, 4, then at most 8 collection intervals. A definition change or successful probe resets it.

Each attempted probe creates at most one fixed failure sample. Skipped intervals do not create samples or workers.

The table above defines internal fixed codes. Section 8.4 defines their existing wire-category mapping.

## 10. Product Integration

### 10.1 One-shot probe

`aic workload monitor <id> --json` will execute one bounded probe. It will not write history.

A successful probe will return `monitor_ready` with required metrics and available optional capabilities.

A failed probe will return one failure category. It will not return partial metrics.

### 10.2 Daemon probe

`aicd` will probe each enabled JVM definition on the existing workload interval.

The worker will revalidate binding, PID, start time, executable, selector, UID, namespaces, directory, and file for every probe.

The daemon will not cache a file descriptor across intervals. It will not retain a stale process identity.

### 10.3 Status and history

Successful daemon probes will use the existing workload history file and retention policy.

History will contain typed numeric metrics, capability flags, outcome, timestamp, and an opaque workload identifier.

History will not contain a PID, username, raw path, PerfData name, or string value.

Failed probes will use the stable failure taxonomy. Existing `fresh`, `stale`, and `no_samples` rules will remain.

## 11. Test Plan

### 11.1 Static fixtures

Add valid and invalid PerfData fixtures for Linux OpenJDK 17, 21, and 25.

Include little-endian and supported alternate-endian fixtures when the supported JDKs can produce them.

Add G1 and ZGC fixtures. Each fixture must state its JDK build and collector.

Strip all raw strings that the metric contract does not require. Use synthetic replacements where structure requires bytes.

### 11.2 Parser tests

Add unit tests for each prologue field, entry field, bound, alignment rule, and NUL rule.

Add tests for integer overflow, overlapping entries, zero progress, duplicate names, and truncated data.

Add property tests for cursor monotonicity, bounded allocation, and deterministic rejection.

Add a fuzz target for the complete bounded parser. Seed it with all supported fixtures.

The dependency-free parser PR uses property tests and a checked-in corpus. A separate PR1b adds `cargo-fuzz` after dependency approval.

Run production parser tests through the worker protocol. Verify input, output, and trailing-byte caps.

### 11.3 Security tests

Add tests for symlink roots, symlink directories, symlink files, hard links, owner mismatch, and unsafe mode bits.

Add tests that replace a path between metadata checks and open. Verify that descriptor checks reject the replacement.

Add parent replacement, mount replacement, FIFO, device, socket, sparse file, and zero-length file tests.

Add directory scans that reach EOF before each cap. Add scans that hit each cap before EOF.

Only the EOF cases can prove uniqueness.

Add tests for PID reuse and start-time changes before and after file open.

Add tests for zero or multiple bindings, executable changes, selector changes, root, UID mismatch, and namespace mismatch.

Verify that errors, logs, status output, and history contain no raw path, argument, or string value.

Add a worker hang fixture. Verify timeout, process-group kill, actor-owned reap, and daemon continuation.

Verify that parent descriptors `0` through `3` do not change. Reject duplicate or below-64 child source descriptors.

Verify child descriptors `0` through `3` after mapping. Verify that descriptor `3` keeps `FD_CLOEXEC`.

Verify fail-closed behavior for `close_range` and `execve` errors through descriptor `3`.

Test stdout EOF before wait status and wait status before stdout EOF. Both orders must produce the same result.

Test timeout against concurrent exit. Test stale token and PID events. The actor must ignore stale commands and events.

Verify that the actor never signals a token after reap. Verify one-second grace, `Draining`, and final slot release.

Verify that the worker cannot access the PerfData descriptor or inherited JVM-related environment values.

Add CPU-burning, crash, signal, rapid churn, and repeated malformed worker fixtures. Verify bounded backoff.

### 11.4 Live smoke tests

Run live Linux smoke tests with OpenJDK 17, 21, and 25.

Run G1 and ZGC where each supported JDK provides the collector.

Verify same-UID success. Verify different-UID rejection without privilege changes.

Verify daemon shutdown during a probe. Verify one-shot output and bounded history output.

Run non-Linux compile tests. Verify that JVM stays discovery-only and starts no capture worker.

## 12. macOS Deferral

macOS support is deferred. The Linux trusted-path and `/proc` identity contracts do not apply to macOS.

A macOS proposal must define process identity, trusted paths, ownership checks, and race controls before implementation.

Do not reuse this Linux contract by substituting macOS temporary directories.

## 13. Kill Criteria

Stop implementation if any criterion applies:

- Supported JDKs do not provide a stable required metric set.
- An identity, namespace, path, inode, owner, or link substitution can pass the required checks without detection.
- V1 requires root, cross-UID access, or different user, PID, or mount namespaces.
- The implementation requires Attach API, JMX, network access, signals, or privilege changes.
- The parser cannot enforce the 1 MiB, 4,096-entry, 256-byte, 4 KiB, and 200 ms limits.
- Production parsing requires `mmap`, in-daemon parsing, an inherited PerfData descriptor, or an unbounded worker protocol.
- The lifecycle actor cannot retain child ownership from successful `fork` through matching final wait status.
- The actor cannot issue the required leader or group kill at probe deadline.
- The actor cannot verify the worker process group before the supervisor sends untrusted capture input.
- A killed worker can leave the JVM slot reusable before `waitpid` confirms exit.
- Required structural prologue changes can occur during capture without detection.
- The implementation treats ordinary numeric counter changes as a structural failure or an atomicity guarantee.
- Valid JDK 17, 21, and 25 fixtures require incompatible unbounded parsing rules.
- Errors or history require raw paths, raw strings, arguments, or dynamic metric names.
- History exposes a JVM executable path, main class, username, or raw selector as its identifier.
- Live tests cannot distinguish PID reuse with the saved raw procfs start ticks.
- The fixture spike cannot prove the required output semantics, units, widths, and aliases across supported JDKs.
- The sample schema cannot preserve old JSONL input and selector-based CLI lookup while redacting JVM public output.

If a kill criterion applies, keep the JVM adapter in `detect_only` mode. Record the evidence in the security review.

### 13.1 Threat-model limit

V1 treats the same effective UID and same namespaces as one trusted principal. It does not guarantee metric authenticity against that principal.

The file trust checks prevent cross-UID access, path substitution, symlink traversal, hard-link substitution, and accidental attachment.

A malicious same-principal process can modify accessible PerfData numeric values without changing inode or prologue fields.

Do not claim tamper resistance against the same principal. Use an authenticated JVM channel if that guarantee becomes necessary.

The same-UID kill criterion applies only to undetected path, inode, owner, namespace, or process-identity substitution.

## 14. Phased Implementation

### PR 1: Parser and fixtures

Add the bounded PerfData parser and versioned worker protocol. Add sanitized capture fixtures and property tests.

Do not connect the parser to discovery, CLI, daemon, filesystem access, or history.

### PR 1b: Fuzz harness

Add the `cargo-fuzz` harness and seed corpus after exact dependency approval.

Do not start PR 2 until the fuzz harness completes its bounded CI smoke run.

### PR 2: Trusted local reader

Add the isolated capture worker, Linux namespace and identity checks, FD-relative checks, and bounded `pread`.

Add worker lifecycle, replacement, namespace, and path attack tests.

Keep the JVM adapter in `detect_only` mode. Require security review before the next PR.

### PR 3: One-shot integration

Add explicit opt-in and one-shot probe support. Add the required metric schema and optional capability schemas.

Do not enable daemon history in this PR.

### PR 4: Daemon and history integration

Add periodic probes, failure isolation, status output, and bounded history records.

Run all live smoke tests before merge. Keep macOS in `unsupported_platform` state.

## 15. Approval Gates

The security review must approve the parser contract, trusted path contract, identity checks, and data exclusion rules.

Each implementation PR must pass the limits and tests from this RFC.

The JVM adapter must remain discovery-only until PR 3 passes its security gate.
