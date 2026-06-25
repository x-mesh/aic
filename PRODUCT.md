# Product

## Register

product

## Users

Local developers and SRE-oriented operators using `aic` from a terminal workflow. They open the web dashboard when they need a fast read on local host resources, snapshots, incidents, audit history, command history, webhook ingestion, and optional observability backends without leaving the machine or exposing agentic execution controls.

## Product Purpose

`aic web` is a token-gated, read-only operational dashboard for the local `aic` environment. It exists to make local telemetry and diagnostic artifacts inspectable at a glance: current resource pressure, recent snapshots, RCA incidents, audit-chain activity, command history, webhook events, configuration shape, and optional Prometheus/Loki queries. Success means the user can connect, scan health, drill into evidence, and decide what to inspect next with minimal visual noise.

## Brand Personality

Calm, precise, operational. The interface should feel trustworthy and efficient under troubleshooting pressure, with enough visual hierarchy to guide scanning but no decorative drama.

## Anti-references

Avoid glossy SaaS dashboard tropes, chart-heavy Grafana complexity, decorative marketing polish, and a literal terminal clone. The dashboard should not feel like an agent chat surface or imply write access where the backend is read-only.

## Design Principles

- Lead with system state, then evidence.
- Keep dense data readable under pressure.
- Preserve local-first trust: no external assets, no surprise affordances, no write-like UI language.
- Use color only for selection, status, and severity.
- Make drill-down paths obvious without adding modal-heavy interaction.

## Accessibility & Inclusion

Target WCAG AA contrast for text, controls, and state indicators. Support keyboard-visible focus, reduced motion, and color-independent severity communication through labels and structure.
