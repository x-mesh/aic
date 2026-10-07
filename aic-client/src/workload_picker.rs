//! `aic workload enable`을 인자 없이 실행했을 때의 대화형 등록.
//!
//! 탐색한 후보를 고르고, 연결 주소와 서비스 종류에 필요한 계정 정보를 받고, 저장하기 전에 한 번
//! 점검한다. 비밀번호는 `file:NAME` 비밀 파일에 둔다. systemd로 뜬 aicd에는 로그인 셸의 환경
//! 변수가 전달되지 않고, 리눅스 keychain(커널 keyring)도 aicd와 셸이 같은 것을 보지 못한다.

use aic_client::workload;
use aic_common::{WorkloadAdapter, WorkloadCandidate, WorkloadConnectionConfig};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, FuzzySelect, Input, Password, Select};

const MAX_SECRET_NAME: usize = 64;
const PENDING_SUFFIX: &str = "-pending";

/// 어댑터마다 받는 계정 정보.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credentials {
    None,
    /// 사용자는 필수, 비밀번호는 선택(PostgreSQL, MySQL).
    UserRequired,
    /// 비밀번호만 또는 사용자와 비밀번호(Redis).
    PasswordOptionalUser,
    /// 사용자와 비밀번호를 함께 쓰거나 둘 다 쓰지 않는다.
    UserAndPassword,
    /// 사용자와 비밀번호를 함께 쓰며, TLS endpoint에서만 허용한다.
    UserAndPasswordOverTls,
}

fn credentials(adapter: WorkloadAdapter) -> Credentials {
    match adapter {
        WorkloadAdapter::PostgreSql | WorkloadAdapter::MySql => Credentials::UserRequired,
        WorkloadAdapter::Redis => Credentials::PasswordOptionalUser,
        WorkloadAdapter::MongoDb => Credentials::UserAndPassword,
        WorkloadAdapter::ClickHouse
        | WorkloadAdapter::Elasticsearch
        | WorkloadAdapter::OpenSearch
        | WorkloadAdapter::RabbitMq
        | WorkloadAdapter::Nginx => Credentials::UserAndPasswordOverTls,
        _ => Credentials::None,
    }
}

/// 이미지 digest(`@sha256:…`)는 사람이 구분하는 데 쓰이지 않고 줄만 길게 만든다.
fn image_without_digest(image: &str) -> &str {
    image.split('@').next().unwrap_or(image)
}

fn candidate_label(candidate: &WorkloadCandidate) -> String {
    let adapter = workload::adapter_display_name(candidate.adapter);
    match &candidate.container {
        Some(container) => format!(
            "[{adapter}] {} ({})",
            workload::short_name(&candidate.id),
            container
                .image
                .as_deref()
                .map(image_without_digest)
                .unwrap_or(&container.runtime),
        ),
        None => format!("[{adapter}] {}", workload::short_name(&candidate.id)),
    }
}

/// 짧은 라벨이 겹치면 그 후보들에만 전체 id를 붙인다.
fn candidate_labels(candidates: &[&WorkloadCandidate]) -> Vec<String> {
    let short = candidates
        .iter()
        .map(|candidate| candidate_label(candidate))
        .collect::<Vec<_>>();
    short
        .iter()
        .zip(candidates)
        .map(|(label, candidate)| {
            if short.iter().filter(|other| *other == label).count() > 1 {
                format!("{label} · {}", candidate.id)
            } else {
                label.clone()
            }
        })
        .collect()
}

fn secret_name(candidate: &WorkloadCandidate) -> String {
    let subject = candidate
        .container
        .as_ref()
        .map(|container| {
            container
                .name
                .clone()
                .unwrap_or_else(|| container.id.clone())
        })
        .unwrap_or_else(|| {
            candidate
                .id
                .rsplit('/')
                .next()
                .unwrap_or(&candidate.id)
                .to_string()
        });
    let raw = format!(
        "workload-{}-{subject}",
        workload::adapter_display_name(candidate.adapter)
    );
    let cleaned = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    cleaned
        .chars()
        .take(MAX_SECRET_NAME - PENDING_SUFFIX.len())
        .collect()
}

/// 받은 값으로 만든 연결과, 점검을 위해 임시로 저장한 비밀 파일 이름.
struct Draft {
    connection: WorkloadConnectionConfig,
    pending_secret: Option<String>,
}

fn optional(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn input_with_default(
    theme: &ColorfulTheme,
    prompt: &str,
    default: Option<&str>,
    allow_empty: bool,
) -> anyhow::Result<Option<String>> {
    let mut input = Input::<String>::with_theme(theme)
        .with_prompt(prompt)
        .allow_empty(allow_empty);
    if let Some(default) = default {
        input = input.default(default.to_string());
    }
    Ok(optional(input.interact_text()?))
}

/// 어댑터가 쓰는 연결 값만 남긴다. TLS에서만 인증을 허용하는 어댑터는 TLS가 아니면 계정을 뺀다.
fn applicable(
    adapter: WorkloadAdapter,
    endpoint: &str,
    defaults: &workload::ConnectionDefaults,
) -> workload::ConnectionDefaults {
    let mut values = defaults.clone();
    match credentials(adapter) {
        Credentials::None => {
            values.username = None;
            values.database = None;
        }
        Credentials::UserRequired => {}
        Credentials::PasswordOptionalUser | Credentials::UserAndPassword => {
            values.database = None;
        }
        Credentials::UserAndPasswordOverTls => {
            values.database = None;
            if !endpoint.starts_with("tls://") {
                values.username = None;
            }
        }
    }
    values
}

fn summary(adapter: WorkloadAdapter, values: &workload::ConnectionDefaults) -> String {
    let mut parts = vec![values.endpoint.clone().unwrap_or_default()];
    if let Some(user) = &values.username {
        parts.push(format!("사용자 {user}"));
    }
    if let Some(database) = &values.database {
        parts.push(format!("DB {database}"));
    }
    if credentials(adapter) == Credentials::UserRequired && values.username.is_none() {
        parts.push("사용자 미정".to_string());
    }
    parts.join(" · ")
}

/// 연결 값을 정한다. 제안이 모두 있으면 한 줄로 보여 주고 확인만 받는다. 틀렸다고 하거나
/// 다시 입력할 때만 항목별로 묻는다.
fn ask_connection_values(
    theme: &ColorfulTheme,
    adapter: WorkloadAdapter,
    defaults: &workload::ConnectionDefaults,
    edit: bool,
) -> anyhow::Result<workload::ConnectionDefaults> {
    let endpoint = defaults.endpoint.clone().unwrap_or_default();
    let proposed = applicable(adapter, &endpoint, defaults);
    let complete = proposed.endpoint.is_some()
        && (credentials(adapter) != Credentials::UserRequired || proposed.username.is_some())
        && (adapter != WorkloadAdapter::PostgreSql || proposed.database.is_some());
    if !edit
        && complete
        && Confirm::with_theme(theme)
            .with_prompt(format!("연결 {}", summary(adapter, &proposed)))
            .default(true)
            .interact()?
    {
        return Ok(proposed);
    }
    let endpoint =
        input_with_default(theme, "주소", defaults.endpoint.as_deref(), false)?.unwrap_or_default();
    let mut values = workload::ConnectionDefaults {
        endpoint: Some(endpoint.clone()),
        ..Default::default()
    };
    match credentials(adapter) {
        Credentials::None => {}
        Credentials::UserRequired => {
            values.username =
                input_with_default(theme, "사용자", defaults.username.as_deref(), false)?;
            let required = adapter == WorkloadAdapter::PostgreSql;
            let prompt = if required {
                "DB"
            } else {
                "DB (비우면 지정 안 함)"
            };
            values.database =
                input_with_default(theme, prompt, defaults.database.as_deref(), !required)?;
        }
        Credentials::PasswordOptionalUser => {
            values.username = input_with_default(
                theme,
                "사용자 (ACL을 쓰지 않으면 비움)",
                defaults.username.as_deref(),
                true,
            )?;
        }
        Credentials::UserAndPassword | Credentials::UserAndPasswordOverTls => {
            if credentials(adapter) == Credentials::UserAndPassword
                || endpoint.starts_with("tls://")
            {
                values.username = input_with_default(
                    theme,
                    "사용자 (인증하지 않으면 비움)",
                    defaults.username.as_deref(),
                    true,
                )?;
            }
        }
    }
    Ok(values)
}

fn ask_draft(
    theme: &ColorfulTheme,
    candidate: &WorkloadCandidate,
    defaults: &workload::ConnectionDefaults,
    edit: bool,
) -> anyhow::Result<Draft> {
    let values = ask_connection_values(theme, candidate.adapter, defaults, edit)?;
    let mut draft = Draft {
        connection: WorkloadConnectionConfig {
            endpoint: values.endpoint.unwrap_or_default(),
            username: values.username,
            secret_ref: None,
            database: values.database,
            auth_source: None,
        },
        pending_secret: None,
    };
    let wants_password = match credentials(candidate.adapter) {
        Credentials::None => false,
        Credentials::UserRequired | Credentials::PasswordOptionalUser => true,
        Credentials::UserAndPassword | Credentials::UserAndPasswordOverTls => {
            draft.connection.username.is_some()
        }
    };
    if wants_password {
        let secret = Password::with_theme(theme)
            .with_prompt("비밀번호 (비우면 없음)")
            .allow_empty_password(true)
            .interact()?;
        if !secret.is_empty() {
            let name = format!("{}{PENDING_SUFFIX}", secret_name(candidate));
            aic_common::secret::store_file_secret(&name, &secret).map_err(anyhow::Error::msg)?;
            draft.connection.secret_ref = Some(aic_common::secret::make_file_reference(&name));
            draft.pending_secret = Some(name);
        }
    }
    Ok(draft)
}

fn discard_pending(draft: &Draft) {
    if let Some(name) = &draft.pending_secret {
        let _ = aic_common::secret::delete_file_secret(name);
    }
}

/// 점검용 임시 비밀을 최종 이름으로 옮긴다.
fn commit_secret(
    candidate: &WorkloadCandidate,
    mut draft: Draft,
) -> anyhow::Result<WorkloadConnectionConfig> {
    if let Some(pending) = draft.pending_secret.take() {
        let dir = aic_common::secret::file_secret_dir();
        let name = secret_name(candidate);
        std::fs::rename(dir.join(&pending), dir.join(&name))?;
        draft.connection.secret_ref = Some(aic_common::secret::make_file_reference(&name));
    }
    Ok(draft.connection)
}

fn metrics_summary(report: &aic_common::workload::WorkloadMonitorReport) -> String {
    serde_json::to_value(report)
        .ok()
        .and_then(|value| value.get("metrics").cloned())
        .map(|metrics| metrics.to_string())
        .unwrap_or_default()
}

pub(crate) fn run_enable_picker() -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "인자 없는 `aic workload enable`은 터미널에서 후보를 골라 등록하는 화면입니다 — \
             스크립트에서는 `aic workload enable <id> --fingerprint <값> --endpoint ...`를 쓰세요"
        );
    }
    let theme = ColorfulTheme::default();
    let report = workload::discover()?;
    let candidates = report
        .candidates
        .iter()
        .filter(|candidate| workload::is_enableable_monitor_candidate(candidate))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        println!("등록할 수 있는 서비스가 없습니다. `aic workload discover`로 후보를 확인하세요.");
        return Ok(());
    }
    let labels = candidate_labels(&candidates);
    let Some(index) = FuzzySelect::with_theme(&theme)
        .with_prompt("서비스 (입력해 검색 · Esc 취소)")
        .items(&labels)
        .default(0)
        .max_length(15)
        .interact_opt()?
    else {
        return Ok(());
    };
    let candidate = candidates[index];
    let name = workload::short_name(&candidate.id);
    let existing = workload::list_configured()?
        .into_iter()
        .find(|definition| definition.id == candidate.id)
        .and_then(|definition| definition.connection);
    let mut defaults = match &existing {
        Some(connection) => {
            println!("이미 등록된 서비스입니다. 저장하면 연결 정보를 바꿉니다.");
            workload::ConnectionDefaults {
                endpoint: Some(connection.endpoint.clone()),
                username: connection.username.clone(),
                database: connection.database.clone(),
            }
        }
        None => workload::suggest_connection(candidate),
    };
    let mut edit = false;

    loop {
        let draft = ask_draft(&theme, candidate, &defaults, edit)?;
        defaults = workload::ConnectionDefaults {
            endpoint: Some(draft.connection.endpoint.clone()),
            username: draft.connection.username.clone(),
            database: draft.connection.database.clone(),
        };
        edit = true;
        if let Err(error) = draft.connection.validate_for(candidate.adapter) {
            discard_pending(&draft);
            println!("입력값 오류: {error}");
            continue;
        }
        let probe = workload::probe_with_connection(candidate, Some(&draft.connection));
        let save = match &probe {
            Ok(report) => {
                println!("점검 성공: {}", metrics_summary(report));
                if Confirm::with_theme(&theme)
                    .with_prompt("저장할까요?")
                    .default(true)
                    .interact()?
                {
                    true
                } else {
                    let choice = Select::with_theme(&theme)
                        .items(["다시 입력", "취소"])
                        .default(0)
                        .interact()?;
                    if choice == 1 {
                        discard_pending(&draft);
                        println!("취소했습니다. 저장한 것이 없습니다.");
                        return Ok(());
                    }
                    false
                }
            }
            Err(error) => {
                println!("점검 실패: {error}");
                match Select::with_theme(&theme)
                    .items(["다시 입력", "그래도 저장", "취소"])
                    .default(0)
                    .interact()?
                {
                    1 => true,
                    2 => {
                        discard_pending(&draft);
                        println!("취소했습니다. 저장한 것이 없습니다.");
                        return Ok(());
                    }
                    _ => false,
                }
            }
        };
        if !save {
            discard_pending(&draft);
            continue;
        }
        let connection = commit_secret(candidate, draft)?;
        workload::enable_candidate(candidate, Some(connection))?;
        println!(
            "등록: {name} ({}) · 1분 뒤 확인: aic workload status · aic workload history {name}",
            workload::adapter_display_name(candidate.adapter)
        );
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aic_common::{WorkloadContainer, WorkloadSelector};

    fn candidate(id: &str, adapter: WorkloadAdapter, container: Option<&str>) -> WorkloadCandidate {
        WorkloadCandidate {
            id: id.to_string(),
            fingerprint: "f".into(),
            selector: Some(WorkloadSelector::Executable {
                path: "/usr/local/bin/postgres".into(),
            }),
            adapter,
            driver_mode: None,
            bindings: Vec::new(),
            ambiguity: Vec::new(),
            container: container.map(|name| WorkloadContainer {
                runtime: "docker".into(),
                id: "a".repeat(64),
                name: Some(name.to_string()),
                image: Some("postgres:17".into()),
            }),
        }
    }

    /// 이 테스트가 지키는 것: 만든 비밀 이름이 `file:` 참조 규칙을 통과하는 것. 통과하지 못하면
    /// 비밀번호를 입력한 뒤에야 저장이 실패한다.
    #[test]
    fn secret_names_are_valid_file_references() {
        let long = "x".repeat(200);
        for c in [
            candidate(
                "container:docker:dnx-postgres-1:exe:/usr/local/bin/postgres",
                WorkloadAdapter::PostgreSql,
                Some("dnx-postgres-1"),
            ),
            candidate("exe:/usr/sbin/my nginx", WorkloadAdapter::Nginx, None),
            candidate("exe:/opt/x", WorkloadAdapter::Redis, Some(&long)),
        ] {
            let name = secret_name(&c);
            for name in [name.clone(), format!("{name}{PENDING_SUFFIX}")] {
                aic_common::secret::parse_secret_reference(&format!("file:{name}"))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        }
        assert_eq!(
            secret_name(&candidate(
                "container:docker:dnx-postgres-1:exe:/usr/local/bin/postgres",
                WorkloadAdapter::PostgreSql,
                Some("dnx-postgres-1"),
            )),
            "workload-postgresql-dnx-postgres-1"
        );
    }

    #[test]
    fn labels_lead_with_the_container_name() {
        let c = candidate(
            "container:docker:db:exe:/usr/local/bin/postgres",
            WorkloadAdapter::PostgreSql,
            Some("db"),
        );
        assert_eq!(candidate_label(&c), "[postgresql] db (postgres:17)");
    }

    #[test]
    fn labels_drop_the_image_digest_and_add_the_id_only_on_a_clash() {
        let mut digest = candidate(
            "container:docker:db:exe:/usr/local/bin/postgres",
            WorkloadAdapter::PostgreSql,
            Some("db"),
        );
        digest.container.as_mut().unwrap().image =
            Some("postgres:17.6-alpine@sha256:ef257d85f76e48da".into());
        assert_eq!(
            candidate_label(&digest),
            "[postgresql] db (postgres:17.6-alpine)"
        );

        let host = candidate("exe:/usr/sbin/nginx", WorkloadAdapter::Nginx, None);
        let other = candidate("exe:/opt/nginx/sbin/nginx", WorkloadAdapter::Nginx, None);
        let labels = candidate_labels(&[&digest, &host, &other]);
        assert_eq!(labels[0], "[postgresql] db (postgres:17.6-alpine)");
        assert_eq!(labels[1], "[nginx] nginx · exe:/usr/sbin/nginx");
        assert_eq!(labels[2], "[nginx] nginx · exe:/opt/nginx/sbin/nginx");
    }

    #[test]
    fn tls_only_credentials_are_dropped_over_plain_tcp() {
        let defaults = workload::ConnectionDefaults {
            endpoint: Some("tcp://127.0.0.1:80".into()),
            username: Some("admin".into()),
            database: Some("x".into()),
        };
        let plain = applicable(WorkloadAdapter::Nginx, "tcp://127.0.0.1:80", &defaults);
        assert_eq!(plain.username, None);
        assert_eq!(plain.database, None);
        let tls = applicable(WorkloadAdapter::Nginx, "tls://web:443", &defaults);
        assert_eq!(tls.username.as_deref(), Some("admin"));
        let postgres = applicable(
            WorkloadAdapter::PostgreSql,
            "tcp://127.0.0.1:5432",
            &defaults,
        );
        assert_eq!(postgres.database.as_deref(), Some("x"));
    }
}
