---
slug: "gws-operator-bridge"
name: "Google Workspace CLI Operator Bridge"
vendor: "Google"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-04-14"
source_repo: "https://github.com/googleworkspace/cli"
---

# gws-operator-bridge — Architecture Specification

Implemented in grclanker as a companion to the native Google Workspace audit family:

- `gws_ops_check_cli`
- `gws_ops_investigate_alerts`
- `gws_ops_trace_admin_activity`
- `gws_ops_review_tokens`
- `gws_ops_collect_evidence_bundle`

## Overview

This slice adds a **read-only operator bridge** to the external `gws` CLI from `googleworkspace/cli`. It is intentionally separate from grclanker’s native Google Workspace compliance tools:

- The native GWS tools remain the authoritative assessment and framework-mapping path.
- The operator bridge is an optional convenience layer for ad hoc investigation and evidence collection when `gws` is already installed and authenticated.

## Scope

The first release is intentionally bounded:

- Read-only only
- GRC operator workflows only
- Curated commands only
- No arbitrary passthrough shelling to `gws`
- No write helpers like Gmail send, Docs write, Drive upload, or Calendar create

## Current Workflows

### `gws_ops_check_cli`

Checks whether `gws` is installed, reports the active CLI version, and previews or runs a harmless read-only Admin Reports probe.

### `gws_ops_investigate_alerts`

Uses the `gws` CLI to query Alert Center data and returns structured alert summaries plus the exact underlying command.

### `gws_ops_trace_admin_activity`

Uses the `gws` CLI to query recent Admin Reports activity for privileged changes.

### `gws_ops_review_tokens`

Uses the `gws` CLI to review token and OAuth activity telemetry. This is intentionally activity-first rather than a full tenant-wide token inventory clone.

### `gws_ops_collect_evidence_bundle`

Runs the curated alert, admin-activity, and token-activity workflows, then writes:

- raw structured CLI output
- normalized summaries
- executed commands
- a zipped operator evidence bundle

## Auth And Runtime

The bridge inherits `gws` auth/config behavior rather than duplicating it. The expected precedence remains owned by the upstream CLI:

1. `GOOGLE_WORKSPACE_CLI_TOKEN`
2. `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`
3. upstream encrypted credentials
4. upstream plaintext fallback

grclanker adds only:

- `GRCLANKER_GWS_BIN` for the binary path
- `config_dir` tool override mapped to `GOOGLE_WORKSPACE_CLI_CONFIG_DIR`

## Status

Implemented locally in grclanker as an optional operator workflow layer. Real smoke testing depends on having `gws` installed and authenticated against a tenant.
