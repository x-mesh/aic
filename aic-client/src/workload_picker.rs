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

fn candidate_label(candidate: &WorkloadCandidate) -> String {
    let adapter = workload::adapter_display_name(candidate.adapter);
    match &candidate.container {
        Some(container) => format!(
            "[{adapter}] {} ({}) · {}",
            container.name.as_deref().unwrap_or(&container.id),
            container.image.as_deref().unwrap_or(&container.runtime),
            candidate.id
        ),
        None => format!("[{adapter}] {}", candidate.id),
    }
}

/// `file:` 비밀 이름. 사람이 알아볼 수 있게 어댑터와 컨테이너 이름(없으면 실행 파일 이름)으로 만든다.
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

fn ask_secret_ref(
    theme: &ColorfulTheme,
    candidate: &WorkloadCandidate,
    pending: &mut Option<String>,
) -> anyhow::Result<Option<String>> {
    let choice = Select::with_theme(theme)
        .with_prompt("비밀번호")
        .items([
            "여기서 입력해 aic 비밀 파일에 저장 (권장)",
            "aicd 환경 변수 이름 지정 (env:NAME)",
            "비밀번호 없음",
        ])
        .default(0)
        .interact()?;
    match choice {
        0 => {
            let secret = Password::with_theme(theme)
                .with_prompt("비밀번호 (화면에 표시하지 않음)")
                .interact()?;
            let name = format!("{}{PENDING_SUFFIX}", secret_name(candidate));
            aic_common::secret::store_file_secret(&name, &secret).map_err(anyhow::Error::msg)?;
            *pending = Some(name.clone());
            Ok(Some(aic_common::secret::make_file_reference(&name)))
        }
        1 => {
            let name: String = Input::with_theme(theme)
                .with_prompt("환경 변수 이름 (aicd 실행 환경에 있어야 함)")
                .interact_text()?;
            Ok(Some(format!("env:{}", name.trim())))
        }
        _ => Ok(None),
    }
}

fn ask_draft(
    theme: &ColorfulTheme,
    candidate: &WorkloadCandidate,
    previous: Option<&WorkloadConnectionConfig>,
) -> anyhow::Result<Draft> {
    let suggested = previous
        .map(|connection| connection.endpoint.clone())
        .or_else(|| workload::suggest_endpoint(candidate));
    let mut endpoint = Input::<String>::with_theme(theme)
        .with_prompt("연결 주소 (tcp://HOST:PORT, tls://HOST:PORT, unix:///PATH)");
    if let Some(suggested) = suggested {
        endpoint = endpoint.default(suggested);
    }
    let endpoint = endpoint.interact_text()?.trim().to_string();
    let mut draft = Draft {
        connection: WorkloadConnectionConfig {
            endpoint,
            username: None,
            secret_ref: None,
            database: None,
            auth_source: None,
        },
        pending_secret: None,
    };
    let previous_user = previous.and_then(|connection| connection.username.clone());
    let ask_user = |prompt: &str, default: Option<String>| -> anyhow::Result<String> {
        let mut input = Input::<String>::with_theme(theme).with_prompt(prompt);
        if let Some(default) = default {
            input = input.default(default);
        }
        Ok(input.interact_text()?.trim().to_string())
    };
    match credentials(candidate.adapter) {
        Credentials::None => {}
        Credentials::UserRequired => {
            let default_user = previous_user.or_else(|| {
                (candidate.adapter == WorkloadAdapter::PostgreSql).then(|| "postgres".to_string())
            });
            draft.connection.username = optional(ask_user("사용자", default_user)?);
            let database_default = previous
                .and_then(|connection| connection.database.clone())
                .or_else(|| {
                    (candidate.adapter == WorkloadAdapter::PostgreSql)
                        .then(|| "postgres".to_string())
                });
            let database_prompt = if candidate.adapter == WorkloadAdapter::PostgreSql {
                "데이터베이스"
            } else {
                "데이터베이스 (비우면 지정 안 함)"
            };
            let mut database = Input::<String>::with_theme(theme)
                .with_prompt(database_prompt)
                .allow_empty(candidate.adapter != WorkloadAdapter::PostgreSql);
            if let Some(default) = database_default {
                database = database.default(default);
            }
            draft.connection.database = optional(database.interact_text()?);
            draft.connection.secret_ref =
                ask_secret_ref(theme, candidate, &mut draft.pending_secret)?;
        }
        Credentials::PasswordOptionalUser => {
            draft.connection.secret_ref =
                ask_secret_ref(theme, candidate, &mut draft.pending_secret)?;
            if draft.connection.secret_ref.is_some() {
                let user = Input::<String>::with_theme(theme)
                    .with_prompt("사용자 (ACL을 쓰지 않으면 비움)")
                    .allow_empty(true)
                    .interact_text()?;
                draft.connection.username = optional(user);
            }
        }
        Credentials::UserAndPassword | Credentials::UserAndPasswordOverTls => {
            let tls_only = credentials(candidate.adapter) == Credentials::UserAndPasswordOverTls;
            let allowed = !tls_only || draft.connection.endpoint.starts_with("tls://");
            if allowed
                && Confirm::with_theme(theme)
                    .with_prompt("사용자와 비밀번호로 인증하나요?")
                    .default(previous_user.is_some())
                    .interact()?
            {
                draft.connection.username = optional(ask_user("사용자", previous_user)?);
                draft.connection.secret_ref =
                    ask_secret_ref(theme, candidate, &mut draft.pending_secret)?;
                if candidate.adapter == WorkloadAdapter::MongoDb {
                    let source = Input::<String>::with_theme(theme)
                        .with_prompt("인증 데이터베이스 (비우면 admin)")
                        .allow_empty(true)
                        .interact_text()?;
                    draft.connection.auth_source = optional(source);
                }
            }
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
    let labels = candidates
        .iter()
        .map(|candidate| candidate_label(candidate))
        .collect::<Vec<_>>();
    let Some(index) = FuzzySelect::with_theme(&theme)
        .with_prompt("감시할 서비스 (입력해 검색 · Esc 취소)")
        .items(&labels)
        .default(0)
        .max_length(15)
        .interact_opt()?
    else {
        return Ok(());
    };
    let candidate = candidates[index];
    let existing = workload::list_configured()?
        .into_iter()
        .find(|definition| definition.id == candidate.id);
    if existing.is_some() {
        println!("이미 등록된 서비스입니다. 저장하면 연결 정보를 새 값으로 바꿉니다.");
    }
    let mut previous = existing.and_then(|definition| definition.connection);

    loop {
        let draft = ask_draft(&theme, candidate, previous.as_ref())?;
        if let Err(error) = draft.connection.validate_for(candidate.adapter) {
            discard_pending(&draft);
            println!("입력값 오류: {error}");
            previous = Some(draft.connection);
            continue;
        }
        println!("점검 중: {}", draft.connection.endpoint);
        let probe = workload::probe_with_connection(candidate, Some(&draft.connection));
        let options: &[&str] = match &probe {
            Ok(report) => {
                println!("점검 성공: {}", metrics_summary(report));
                &["저장", "다시 입력", "취소"]
            }
            Err(error) => {
                println!("점검 실패: {error}");
                &["다시 입력", "그래도 저장", "취소"]
            }
        };
        let choice = Select::with_theme(&theme)
            .items(options)
            .default(0)
            .interact()?;
        match options[choice] {
            "저장" | "그래도 저장" => {
                let connection = commit_secret(candidate, draft)?;
                let definition = workload::enable_candidate(candidate, Some(connection))?;
                println!("등록: {}", definition.id);
                println!(
                    "aicd가 1분 안에 수집을 시작합니다. 확인: aic workload status · aic workload history {}",
                    definition.id
                );
                return Ok(());
            }
            "다시 입력" => {
                discard_pending(&draft);
                previous = Some(draft.connection);
            }
            _ => {
                discard_pending(&draft);
                println!("취소했습니다. 저장한 것이 없습니다.");
                return Ok(());
            }
        }
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
        assert_eq!(
            candidate_label(&c),
            "[postgresql] db (postgres:17) · container:docker:db:exe:/usr/local/bin/postgres"
        );
    }
}
