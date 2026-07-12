//! LLM 송신 직전 prompt redaction — secret/PII 마스킹.
//!
//! 구현은 `aic-common`으로 이동했다(aic-server의 OTLP exporter가 동일 로직을 공유해야 하므로,
//! SRE t6). 기존 `crate::redaction::redact` / `RedactionReport` API 호환을 위해 여기서 re-export만
//! 한다 — 호출부(llm_dispatcher/web/obs_tools 등)는 변경 없이 그대로 동작한다.

pub use aic_common::redaction::{redact, shannon_entropy, RedactionReport};
