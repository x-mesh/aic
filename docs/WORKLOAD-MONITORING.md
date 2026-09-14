# Workload Monitor Operations

This document defines the current workload discovery, configuration, collection, and history contracts.

## Lifecycle

Use this sequence for each workload:

1. Run `aic workload discover --json`.
2. Record the candidate `id` and `fingerprint`.
3. Run `aic workload inspect <id> --json`.
4. Enable the candidate with its current fingerprint.
5. Run one monitor probe before daemon collection.
6. Start `aicd`, or keep the active daemon.
7. Read collection state and history.

Discovery is a one-time process scan. It does not save definitions or start collection.

Discovery does not watch new processes. Run discovery again after a service starts, stops, or changes identity.

The shell command `aic workload enable` is an explicit write. It saves the definition without another confirmation prompt.

The TTY `/discover` flow shows selected definitions and requests confirmation before it saves them.

The TTY `/workload enable <id> <fingerprint>` flow also requests confirmation before it saves one definition.

Enable rejects a changed fingerprint, an ambiguous candidate, or a candidate without a stable selector.

Definitions use `$XDG_CONFIG_HOME/aic/workloads.toml`. The default path is `~/.config/aic/workloads.toml`.

On Unix, AIC writes `workloads.toml` with mode `0600`. Definitions contain secret references, not secret values.

Use `env:NAME` or `keychain:ACCOUNT` references. AIC resolves each secret only for a probe.

## Discovery and driver modes

Discovery identifies supported services from local process evidence. It assigns `detect_only` unless a read-only access check succeeds.

An `inspect_ready` mode confirms local access. It does not confirm service metric collection.

A successful one-time probe returns `monitor_ready: true`. It does not update the saved driver mode.

The one-time probe does not write history. It uses a saved connection when one exists.

Run the one-time probe only for a current, unique, unambiguous candidate of that adapter.

```sh
aic workload discover --json
aic workload inspect "$WORKLOAD_ID" --json
aic workload monitor "$WORKLOAD_ID" --json
```

JVM, Kafka, and Consul are discovery-only adapters. AIC does not create history samples for these adapters.

## Adapter contract

Thirteen adapters support metric collection. Five adapters require an explicit connection before enablement.

| Adapter | Default endpoint | Connection contract | Authentication | TLS | Fixed probe |
| --- | --- | --- | --- | --- | --- |
| Redis or Valkey | Known local sockets, then `127.0.0.1:6379` | Optional `unix`, `tcp`, or `tls` endpoint | Optional username and secret | Native host roots | `INFO` |
| Memcached | `127.0.0.1:11211` | Optional `unix`, `tcp`, or `tls` endpoint | Not supported | Native host roots | `stats` |
| PostgreSQL | None | Explicit `tcp` or `tls`, with a username and database | Optional password secret | Native host roots | One `pg_stat_database` row |
| MySQL or MariaDB | None | Explicit `tcp` or `tls`, with a username and optional database | Optional password secret | Native host roots | Fixed `SHOW GLOBAL STATUS` |
| MongoDB | None | Explicit `tcp` or `tls`, without URI, SRV, or Unix support | Optional username and secret pair, with optional `auth_source` | OpenSSL file system CA paths | `serverStatus` |
| Prometheus | `127.0.0.1:9090` | Optional `tcp` or `tls` endpoint | Not supported | Native host roots | `GET /metrics` |
| ClickHouse | `127.0.0.1:8123` | Optional HTTP `tcp` or `tls` endpoint | Optional Basic authentication on TLS | Native host roots | One fixed system table query |
| etcd | `127.0.0.1:2379` | Optional `tcp` or `tls` endpoint | Not supported | Native host roots | `GET /metrics` |
| Elasticsearch | `127.0.0.1:9200` | Optional HTTP `tcp` or `tls` endpoint | Optional Basic authentication on TLS | Native host roots | `GET /_cluster/stats?timeout=2s` |
| OpenSearch | `127.0.0.1:9200` | Optional HTTP `tcp` or `tls` endpoint | Optional Basic authentication on TLS | Native host roots | `GET /_cluster/stats?timeout=2s` |
| RabbitMQ | `127.0.0.1:15672` | Optional management HTTP `tcp` or `tls` endpoint | Optional Basic authentication on TLS | Native host roots | `GET /api/overview` |
| Nginx | None | Explicit HTTP `tcp` or `tls` endpoint | Optional Basic authentication on TLS | Native host roots | `GET /stub_status` |
| HAProxy | None | Explicit absolute Unix socket | Not supported | Not applicable | `show stat` |

The explicit-connection adapters are PostgreSQL, MySQL, MongoDB, Nginx, and HAProxy.

HAProxy monitoring requires atomic close-on-exec socket creation. It fails closed on unsupported Unix targets, including macOS.

Use only `unix:///absolute/path`, `tcp://host:port`, or `tls://host:port`. Use brackets around an IPv6 address.

An explicit endpoint authorizes an outbound connection to that host and port. Verify the destination before enablement.

### Enable examples

Enable a default-endpoint adapter:

```sh
aic workload enable "$WORKLOAD_ID" \
  --fingerprint "$FINGERPRINT" \
  --json
```

Enable PostgreSQL with an environment secret reference:

```sh
export AIC_PG_MONITOR_PASSWORD='replace-me'
aic workload enable "$WORKLOAD_ID" \
  --fingerprint "$FINGERPRINT" \
  --endpoint tls://db.example:5432 \
  --username aic_monitor \
  --database app \
  --auth-env AIC_PG_MONITOR_PASSWORD \
  --json
```

Enable Nginx after you configure the exact `/stub_status` path:

```sh
aic workload enable "$WORKLOAD_ID" \
  --fingerprint "$FINGERPRINT" \
  --endpoint tcp://127.0.0.1:8080
```

Enable HAProxy with a Unix stats socket:

```sh
aic workload enable "$WORKLOAD_ID" \
  --fingerprint "$FINGERPRINT" \
  --endpoint unix:///run/haproxy/admin.sock
```

## Daemon collection

`aicd` reads saved definitions. It starts the first collection cycle immediately, then starts a cycle every 60 seconds.

Each cycle checks every monitor adapter. A saved definition becomes eligible without a daemon restart.

The next cycle sees a new definition. Allow up to 60 seconds after the first immediate cycle.

Each adapter permits exactly one saved definition. Multiple definitions block only that adapter.

An invalid connection blocks only its adapter. Other adapters continue their collection cycles.

Invalid TOML blocks every adapter because the daemon cannot parse the shared definition file.

A probe failure creates a failed sample. The next cycle retries that adapter.

Failure reasons are `unreachable`, `rejected`, or `malformed`. Stored details use fixed text and exclude server error content.

```sh
aic workload list --json
aic daemon start
aic daemon status
aic workload status --json
```

## Status and history

`aic workload status` reads definitions and history directly. It does not require a running daemon.

| State | Meaning |
| --- | --- |
| `fresh` | A sample exists, and its age is 180 seconds or less. |
| `stale` | The last sample age is more than 180 seconds. |
| `no_samples` | A monitor definition exists, but no sample exists for its ID and adapter. |
| `ambiguous_definitions` | More than one definition uses the same monitor adapter. |
| `not_collected` | The definition uses JVM, Kafka, Consul, or another non-monitor adapter. |

The `fresh` state describes sample age. Check `last_sample.outcome` to distinguish collection success from failure.

History uses `$XDG_STATE_HOME/aic/workload-history.jsonl`. The default path is `~/.local/state/aic/workload-history.jsonl`.

On Unix, the history directory has mode `0700`. The history file has mode `0600`.

The JSONL file retains 1,440 samples across all adapters. Retention is not per workload.

Readers ignore blank or invalid JSONL records. The writer rewrites retained valid records when it repairs or trims the file.

```sh
aic workload status
aic workload status --json
aic workload history "$WORKLOAD_ID" --limit 20
aic workload history "$WORKLOAD_ID" --limit 20 --json
```

AIC does not send workload history to a remote destination.

## Security and protocol limits

All probes use fixed read-only commands, queries, or paths. AIC does not accept user SQL or custom HTTP paths.

HTTP probes disable system proxies and redirects. Basic authentication requires TLS for supported HTTP adapters.

TLS verifies the endpoint host. Most adapters use native host roots. MongoDB uses OpenSSL file system CA paths.

Set `SSL_CERT_FILE` or `SSL_CERT_DIR` when MongoDB cannot find the required CA.

Connect operations use a 200 ms limit. Database and HTTP monitor probes use a three-second total limit.

Most response limits are 64 KiB. Nginx uses 16 KiB, HAProxy uses 256 KiB, and Prometheus uses 1 MiB.

MongoDB applies its 64 KiB limit after BSON decode. The driver can receive a larger response before this check.

PostgreSQL and MySQL libraries do not expose response byte limits. Their fixed queries bound the expected result shape.

Use least-privilege monitor accounts. Do not grant write, administration, or configuration permissions for these probes.
