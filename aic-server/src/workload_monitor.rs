use aic_common::workload::{
    workload_history_path, workloads_file_path, WorkloadAdapter, WorkloadDefinition,
    WorkloadMetrics, WorkloadProbeError, WorkloadSample, WorkloadSampleFailure,
    WorkloadSampleOutcome, WorkloadStore, MAX_WORKLOAD_HISTORY_SAMPLES, WORKLOAD_SAMPLE_INTERVAL,
    WORKLOAD_SAMPLE_SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;

#[derive(Debug, Clone)]
pub struct WorkloadMonitorConfig {
    pub workloads_path: PathBuf,
    pub history_path: PathBuf,
    pub interval: Duration,
}

pub fn default_config() -> WorkloadMonitorConfig {
    WorkloadMonitorConfig {
        workloads_path: workloads_file_path(),
        history_path: workload_history_path(),
        interval: WORKLOAD_SAMPLE_INTERVAL,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionsState {
    Missing,
    Malformed(String),
    Idle,
    Ambiguous(usize),
    One(WorkloadDefinition),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    Skipped(DefinitionsState),
    Appended(WorkloadSample),
}

pub fn load_redis_definition(path: &Path) -> DefinitionsState {
    load_adapter_definition(path, WorkloadAdapter::Redis)
}

pub fn load_memcached_definition(path: &Path) -> DefinitionsState {
    load_adapter_definition(path, WorkloadAdapter::Memcached)
}

pub fn load_adapter_definition(path: &Path, adapter: WorkloadAdapter) -> DefinitionsState {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DefinitionsState::Missing
        }
        Err(error) => return DefinitionsState::Malformed(error.to_string()),
    };
    let store = match toml::from_str::<WorkloadStore>(&content) {
        Ok(store) => store,
        Err(error) => return DefinitionsState::Malformed(error.to_string()),
    };
    if let Some(error) = store.workloads.iter().find_map(|definition| {
        definition
            .connection
            .as_ref()
            .and_then(|connection| connection.validate_for(definition.adapter).err())
    }) {
        return DefinitionsState::Malformed(error.to_string());
    }
    let mut definitions = store
        .workloads
        .into_iter()
        .filter(|definition| definition.adapter == adapter);
    let first = match definitions.next() {
        Some(definition) => definition,
        None => return DefinitionsState::Idle,
    };
    let count = 1 + definitions.count();
    if count == 1 {
        DefinitionsState::One(first)
    } else {
        DefinitionsState::Ambiguous(count)
    }
}

pub fn collect_once(
    cfg: &WorkloadMonitorConfig,
    definition: &WorkloadDefinition,
    probe: impl FnOnce() -> std::result::Result<(String, WorkloadMetrics), WorkloadProbeError>,
    now: DateTime<Utc>,
) -> Result<TickOutcome> {
    let outcome = match probe() {
        Ok((endpoint, metrics)) => WorkloadSampleOutcome::Collected { endpoint, metrics },
        Err(error) => {
            let (reason, detail) = match error {
                WorkloadProbeError::Unreachable(_) => (
                    WorkloadSampleFailure::Unreachable,
                    unavailable_detail(definition.adapter),
                ),
                WorkloadProbeError::Rejected(_) => (
                    WorkloadSampleFailure::Rejected,
                    rejected_detail(definition.adapter),
                ),
                WorkloadProbeError::Malformed(_) => (
                    WorkloadSampleFailure::Malformed,
                    malformed_detail(definition.adapter),
                ),
            };
            WorkloadSampleOutcome::Failed {
                reason,
                detail: detail.to_string(),
            }
        }
    };
    let sample = WorkloadSample {
        schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
        workload_id: definition.id.clone(),
        captured_at: now,
        adapter: definition.adapter,
        outcome,
    };
    append_sample(&cfg.history_path, &sample)?;
    Ok(TickOutcome::Appended(sample))
}

fn unavailable_detail(adapter: WorkloadAdapter) -> &'static str {
    match adapter {
        WorkloadAdapter::Redis => "Redis endpoint is unavailable",
        WorkloadAdapter::Memcached => "Memcached endpoint is unavailable",
        _ => "Workload endpoint is unavailable",
    }
}

fn rejected_detail(adapter: WorkloadAdapter) -> &'static str {
    match adapter {
        WorkloadAdapter::Redis => "Redis rejected the INFO request",
        WorkloadAdapter::Memcached => "Memcached rejected the stats request",
        _ => "Workload rejected the monitor request",
    }
}

fn malformed_detail(adapter: WorkloadAdapter) -> &'static str {
    match adapter {
        WorkloadAdapter::Redis => "Redis returned an invalid INFO response",
        WorkloadAdapter::Memcached => "Memcached returned an invalid stats response",
        _ => "Workload returned an invalid monitor response",
    }
}

pub fn append_sample(path: &Path, sample: &WorkloadSample) -> Result<()> {
    append_sample_with_limit(path, sample, MAX_WORKLOAD_HISTORY_SAMPLES)
}

fn append_sample_with_limit(
    path: &Path,
    sample: &WorkloadSample,
    max_samples: usize,
) -> Result<()> {
    let parent = path
        .parent()
        .context("workload history path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let needs_newline = match OpenOptions::new().read(true).open(path) {
        Ok(mut existing) => {
            let len = existing.metadata()?.len();
            if len == 0 {
                false
            } else {
                existing.seek(SeekFrom::End(-1))?;
                let mut byte = [0];
                existing.read_exact(&mut byte)?;
                byte[0] != b'\n'
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if needs_newline {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{}", serde_json::to_string(sample)?)?;
    file.sync_data()?;
    trim_to_max(path, max_samples)
}

fn trim_to_max(path: &Path, max: usize) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let valid = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<WorkloadSample>(line).ok())
        .collect::<Vec<_>>();
    let non_blank = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    if non_blank <= max && valid.len() == non_blank {
        return Ok(());
    }
    let skip = valid.len().saturating_sub(max);
    let kept = valid.into_iter().skip(skip).collect::<Vec<_>>();
    let temporary = path.with_extension("jsonl.tmp");
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    for sample in kept {
        writeln!(file, "{}", serde_json::to_string(&sample)?)?;
    }
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub async fn serve(cfg: WorkloadMonitorConfig, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut interval = tokio::time::interval(cfg.interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous = Vec::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = interval.tick() => {
                for adapter in [WorkloadAdapter::Redis, WorkloadAdapter::Memcached] {
                    let state = load_adapter_definition(&cfg.workloads_path, adapter);
                    let tag = state_tag(&state);
                    let changed = previous
                        .iter()
                        .find(|(known_adapter, _)| *known_adapter == adapter)
                        .is_none_or(|(_, previous_tag)| *previous_tag != tag);
                    if changed {
                        if let Some((_, previous_tag)) = previous
                            .iter_mut()
                            .find(|(known_adapter, _)| *known_adapter == adapter)
                        {
                            *previous_tag = tag;
                        } else {
                            previous.push((adapter, tag));
                        }
                        match &state {
                            DefinitionsState::Malformed(error) => tracing::warn!(?adapter, error, "workload definitions are malformed"),
                            DefinitionsState::Ambiguous(count) => tracing::warn!(?adapter, count, "workload adapter definitions are ambiguous"),
                            _ => tracing::info!(?adapter, state = tag, "workload definition state changed"),
                        }
                    }
                    if let DefinitionsState::One(definition) = state {
                        let result = match start_collection_thread(cfg.clone(), definition) {
                            Ok(result) => result,
                            Err(error) => {
                                tracing::warn!(?adapter, error = %error, "workload collector thread failed to start");
                                continue;
                            }
                        };
                        match wait_for_collection(result, &mut shutdown).await {
                            Some(Ok(Ok(_))) => {},
                            Some(Ok(Err(error))) => tracing::warn!(?adapter, error = %error, "workload sample append failed"),
                            Some(Err(error)) => tracing::warn!(?adapter, error = %error, "workload collector thread ended without a result"),
                            None => return Ok(()),
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    Ok(())
}

fn state_tag(state: &DefinitionsState) -> &'static str {
    match state {
        DefinitionsState::Missing => "missing",
        DefinitionsState::Malformed(_) => "malformed",
        DefinitionsState::Idle => "idle",
        DefinitionsState::Ambiguous(_) => "ambiguous",
        DefinitionsState::One(_) => "one",
    }
}

fn start_collection_thread(
    cfg: WorkloadMonitorConfig,
    definition: WorkloadDefinition,
) -> std::io::Result<oneshot::Receiver<Result<TickOutcome>>> {
    let (sender, receiver) = oneshot::channel();
    std::thread::Builder::new()
        .name("aic-workload-monitor".to_string())
        .spawn(move || {
            let result = match definition.adapter {
                WorkloadAdapter::Redis => collect_once(
                    &cfg,
                    &definition,
                    || {
                        aic_common::workload::monitor_redis_with_connection(
                            definition.connection.as_ref(),
                        )
                        .map(|(endpoint, metrics)| (endpoint, WorkloadMetrics::Redis(metrics)))
                    },
                    Utc::now(),
                ),
                WorkloadAdapter::Memcached => collect_once(
                    &cfg,
                    &definition,
                    || {
                        aic_common::workload::monitor_memcached_with_connection(
                            definition.connection.as_ref(),
                        )
                        .map(|(endpoint, metrics)| (endpoint, WorkloadMetrics::Memcached(metrics)))
                    },
                    Utc::now(),
                ),
                _ => unreachable!("only supported monitor adapters start collection threads"),
            };
            let _ = sender.send(result);
        })?;
    Ok(receiver)
}

async fn wait_for_collection(
    mut result: oneshot::Receiver<Result<TickOutcome>>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<std::result::Result<Result<TickOutcome>, oneshot::error::RecvError>> {
    tokio::select! {
        result = &mut result => Some(result),
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                None
            } else {
                Some(result.await)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::workload::{RedisMetrics, WorkloadDriverMode, WorkloadSelector};

    fn definition() -> WorkloadDefinition {
        WorkloadDefinition {
            id: "redis".into(),
            selector: WorkloadSelector::Executable {
                path: "/usr/bin/redis-server".into(),
            },
            adapter: WorkloadAdapter::Redis,
            driver_mode: WorkloadDriverMode::MonitorReady,
            connection: None,
        }
    }

    fn memcached_definition() -> WorkloadDefinition {
        WorkloadDefinition {
            id: "memcached".into(),
            selector: WorkloadSelector::Executable {
                path: "/usr/bin/memcached".into(),
            },
            adapter: WorkloadAdapter::Memcached,
            driver_mode: WorkloadDriverMode::MonitorReady,
            connection: None,
        }
    }

    #[test]
    fn missing_and_ambiguous_definitions_do_not_collect() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("workloads.toml");
        assert_eq!(load_redis_definition(&path), DefinitionsState::Missing);
        assert!(!temp.path().join("workload-history.jsonl").exists());
        fs::write(&path, "not = [valid").unwrap();
        assert!(matches!(
            load_redis_definition(&path),
            DefinitionsState::Malformed(_)
        ));
        let store = WorkloadStore {
            workloads: vec![definition(), definition()],
        };
        fs::write(&path, toml::to_string(&store).unwrap()).unwrap();
        assert_eq!(load_redis_definition(&path), DefinitionsState::Ambiguous(2));

        let store = WorkloadStore {
            workloads: vec![definition(), definition(), memcached_definition()],
        };
        fs::write(&path, toml::to_string(&store).unwrap()).unwrap();
        assert_eq!(
            load_memcached_definition(&path),
            DefinitionsState::One(memcached_definition())
        );
    }

    #[test]
    fn append_retains_bounded_valid_history() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state/aic/workload-history.jsonl");
        let base = Utc::now();
        for index in 0..=MAX_WORKLOAD_HISTORY_SAMPLES {
            append_sample(
                &path,
                &WorkloadSample {
                    schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                    workload_id: "redis".into(),
                    captured_at: base + chrono::Duration::seconds(index as i64),
                    adapter: WorkloadAdapter::Redis,
                    outcome: WorkloadSampleOutcome::Collected {
                        endpoint: "127.0.0.1:6379".into(),
                        metrics: WorkloadMetrics::Redis(RedisMetrics {
                            connected_clients: 1,
                            used_memory: 1,
                            total_commands_processed: 1,
                            instantaneous_ops_per_sec: 1,
                            keyspace_hits: 1,
                            keyspace_misses: 1,
                        }),
                    },
                },
            )
            .unwrap();
        }
        let samples = aic_common::workload::load_workload_history(&path).unwrap();
        assert_eq!(samples.len(), MAX_WORKLOAD_HISTORY_SAMPLES);
        assert_eq!(samples[0].captured_at, base + chrono::Duration::seconds(1));
    }

    #[test]
    fn concurrent_reader_only_observes_valid_samples() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state/aic/workload-history.jsonl");
        let done = Arc::new(AtomicBool::new(false));
        let reader_done = done.clone();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            while !reader_done.load(Ordering::Acquire) {
                let samples = aic_common::workload::load_workload_history(&reader_path).unwrap();
                assert!(samples
                    .windows(2)
                    .all(|pair| pair[0].captured_at <= pair[1].captured_at));
            }
        });

        let base = Utc::now();
        for index in 0..200 {
            append_sample_with_limit(
                &path,
                &WorkloadSample {
                    schema_version: WORKLOAD_SAMPLE_SCHEMA_VERSION,
                    workload_id: "redis".into(),
                    captured_at: base + chrono::Duration::seconds(index),
                    adapter: WorkloadAdapter::Redis,
                    outcome: WorkloadSampleOutcome::Collected {
                        endpoint: "127.0.0.1:6379".into(),
                        metrics: WorkloadMetrics::Redis(RedisMetrics {
                            connected_clients: 1,
                            used_memory: 1,
                            total_commands_processed: index as u64,
                            instantaneous_ops_per_sec: 1,
                            keyspace_hits: 1,
                            keyspace_misses: 1,
                        }),
                    },
                },
                25,
            )
            .unwrap();
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap();
        assert_eq!(
            aic_common::workload::load_workload_history(&path)
                .unwrap()
                .len(),
            25
        );
    }

    #[test]
    fn valid_definition_collects_one_sample() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = WorkloadMonitorConfig {
            workloads_path: temp.path().join("workloads.toml"),
            history_path: temp.path().join("state/aic/workload-history.jsonl"),
            interval: Duration::from_secs(1),
        };
        let outcome = collect_once(
            &cfg,
            &definition(),
            || {
                Ok((
                    "127.0.0.1:6379".into(),
                    WorkloadMetrics::Redis(RedisMetrics {
                        connected_clients: 1,
                        used_memory: 2,
                        total_commands_processed: 3,
                        instantaneous_ops_per_sec: 4,
                        keyspace_hits: 5,
                        keyspace_misses: 6,
                    }),
                ))
            },
            Utc::now(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            TickOutcome::Appended(WorkloadSample {
                outcome: WorkloadSampleOutcome::Collected { .. },
                ..
            })
        ));
        assert_eq!(
            aic_common::workload::load_workload_history(&cfg.history_path)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn collect_records_rejected_failure_and_isolates_torn_tail() {
        let temp = tempfile::tempdir().unwrap();
        let history_path = temp.path().join("state/aic/workload-history.jsonl");
        let cfg = WorkloadMonitorConfig {
            workloads_path: temp.path().join("workloads.toml"),
            history_path: history_path.clone(),
            interval: Duration::from_secs(1),
        };
        fs::create_dir_all(history_path.parent().unwrap()).unwrap();
        fs::write(&history_path, "{\"torn\":").unwrap();
        let outcome = collect_once(
            &cfg,
            &definition(),
            || Err(WorkloadProbeError::Rejected("NOAUTH token=secret".into())),
            Utc::now(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            TickOutcome::Appended(WorkloadSample {
                outcome: WorkloadSampleOutcome::Failed {
                    reason: WorkloadSampleFailure::Rejected,
                    ..
                },
                ..
            })
        ));
        let samples = aic_common::workload::load_workload_history(&history_path).unwrap();
        assert_eq!(samples.len(), 1);
        let WorkloadSampleOutcome::Failed { detail, .. } = &samples[0].outcome else {
            panic!("expected failed sample");
        };
        assert_eq!(detail, "Redis rejected the INFO request");
        assert!(!detail.contains("secret"));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(history_path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&history_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn memcached_collection_uses_adapter_metrics_and_fixed_failure_text() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = WorkloadMonitorConfig {
            workloads_path: temp.path().join("workloads.toml"),
            history_path: temp.path().join("state/aic/workload-history.jsonl"),
            interval: Duration::from_secs(1),
        };
        let outcome = collect_once(
            &cfg,
            &memcached_definition(),
            || Err(WorkloadProbeError::Malformed("untrusted response".into())),
            Utc::now(),
        )
        .unwrap();
        let TickOutcome::Appended(sample) = outcome else {
            panic!("expected appended sample");
        };
        assert_eq!(sample.adapter, WorkloadAdapter::Memcached);
        let WorkloadSampleOutcome::Failed { reason, detail } = sample.outcome else {
            panic!("expected failed sample");
        };
        assert_eq!(reason, WorkloadSampleFailure::Malformed);
        assert_eq!(detail, "Memcached returned an invalid stats response");
    }

    #[test]
    fn redis_and_memcached_definitions_collect_independent_samples() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = WorkloadMonitorConfig {
            workloads_path: temp.path().join("workloads.toml"),
            history_path: temp.path().join("state/aic/workload-history.jsonl"),
            interval: Duration::from_secs(1),
        };
        let store = WorkloadStore {
            workloads: vec![definition(), memcached_definition()],
        };
        fs::write(&cfg.workloads_path, toml::to_string(&store).unwrap()).unwrap();
        let DefinitionsState::One(redis) =
            load_adapter_definition(&cfg.workloads_path, WorkloadAdapter::Redis)
        else {
            panic!("expected one Redis definition");
        };
        let DefinitionsState::One(memcached) =
            load_adapter_definition(&cfg.workloads_path, WorkloadAdapter::Memcached)
        else {
            panic!("expected one Memcached definition");
        };

        collect_once(
            &cfg,
            &redis,
            || Err(WorkloadProbeError::Unreachable("redis down".into())),
            Utc::now(),
        )
        .unwrap();
        collect_once(
            &cfg,
            &memcached,
            || {
                Ok((
                    "127.0.0.1:11211".into(),
                    WorkloadMetrics::Memcached(aic_common::workload::MemcachedMetrics {
                        curr_connections: 1,
                        bytes: 2,
                        cmd_get: 3,
                        cmd_set: 4,
                        get_hits: 5,
                        get_misses: 6,
                        evictions: 7,
                    }),
                ))
            },
            Utc::now(),
        )
        .unwrap();

        let samples = aic_common::workload::load_workload_history(&cfg.history_path).unwrap();
        assert_eq!(samples.len(), 2);
        assert!(samples.iter().any(|sample| {
            sample.adapter == WorkloadAdapter::Redis
                && matches!(sample.outcome, WorkloadSampleOutcome::Failed { .. })
        }));
        assert!(samples.iter().any(|sample| {
            sample.adapter == WorkloadAdapter::Memcached
                && matches!(sample.outcome, WorkloadSampleOutcome::Collected { .. })
        }));
    }

    #[tokio::test]
    async fn serve_stops_after_shutdown() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = WorkloadMonitorConfig {
            workloads_path: temp.path().join("missing.toml"),
            history_path: temp.path().join("history.jsonl"),
            interval: Duration::from_millis(10),
        };
        let (shutdown, receiver) = watch::channel(false);
        let handle = tokio::spawn(serve(cfg, receiver));
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn in_flight_collection_does_not_block_shutdown() {
        let (shutdown, mut receiver) = watch::channel(false);
        let (_sender, result) = oneshot::channel::<Result<TickOutcome>>();
        shutdown.send(true).unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_collection(result, &mut receiver),
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }
}
