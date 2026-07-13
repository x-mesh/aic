pub mod agent_event_bus;
pub mod aicd_autostart;
pub mod aicd_client;
pub mod attach_client;
pub mod attach_server;
pub mod boundary_detector;
pub mod boundary_ownership_gate;
pub mod command_record_store;
pub mod control_server;
pub mod lock;
pub mod metrics;
// SRE t6: opt-in OTLP host-metrics exporter → 중앙 collector push.
pub mod otlp_exporter;
pub mod output_processor;
pub mod pty_manager;
pub mod ring_buffer;
pub mod session_processor_pool;
pub mod session_registry;
pub mod session_runtime;
pub mod telemetry;
pub mod uds_server;
// SRE R2: webhook alert ingestion → aic diagnose 자동 spawn.
pub mod webhook_server;
