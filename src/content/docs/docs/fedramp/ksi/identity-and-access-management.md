---
title: Identity and Access Management — FedRAMP KSI Domain
description: Official FRMR-generated summary for the IAM FedRAMP key security indicator domain.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# Identity and Access Management

Domain code: `IAM` · Domain ID: `KSI-IAM` · Web slug: `identity-and-access-management`

## Theme

A secure cloud service offering will protect user data, control access, and apply zero trust principles.

## Indicators

### `KSI-IAM-AAM` (formerly `KSI-IAM-07`) — Automating Account Management

Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.

Mapped Rev5 controls: `ac-2.2`, `ac-2.3`, `ac-2.13`, `ac-6.7`, `ia-4.4`, `ia-12`, `ia-12.2`, `ia-12.3`, `ia-12.5`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-APM` (formerly `KSI-IAM-02`) — Adopting Passwordless Methods

Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA for authentication.

Mapped Rev5 controls: `ac-2`, `ac-3`, `ia-2.1`, `ia-2.2`, `ia-2.8`, `ia-5.1`, `ia-5.2`, `ia-5.6`, `ia-6`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-ELP` (formerly `KSI-IAM-05`) — Ensuring Least Privilege

Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need.

Mapped Rev5 controls: `ac-2.5`, `ac-2.6`, `ac-3`, `ac-4`, `ac-6`, `ac-12`, `ac-14`, `ac-17`, `ac-17.1`, `ac-17.2`, `ac-17.3`, `ac-20`, `ac-20.1`, `cm-2.7`, `cm-9`, `ia-2`, `ia-3`, `ia-4`, `ia-4.4`, `ia-5.2`, `ia-5.6`, `ia-11`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `sc-4`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-39`, `si-3`

Terms: `Persistently`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-JIT` (formerly `KSI-IAM-04`) — Authorizing Just-in-Time

Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.

Mapped Rev5 controls: `ac-2`, `ac-2.1`, `ac-2.2`, `ac-2.3`, `ac-2.4`, `ac-2.6`, `ac-3`, `ac-4`, `ac-5`, `ac-6`, `ac-6.1`, `ac-6.2`, `ac-6.5`, `ac-6.7`, `ac-6.9`, `ac-6.10`, `ac-7`, `ac-20.1`, `ac-17`, `au-9.4`, `cm-5`, `cm-7`, `cm-7.2`, `cm-7.5`, `cm-9`, `ia-4`, `ia-4.4`, `ia-7`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `ps-9`, `ra-5.5`, `sc-2`, `sc-23`, `sc-39`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-MFA` (formerly `KSI-IAM-01`) — Enforcing Phishing-Resistant MFA

Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication.

Mapped Rev5 controls: `ac-2`, `ia-2`, `ia-2.1`, `ia-2.2`, `ia-2.8`, `ia-5`, `ia-8`, `sc-23`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-SNU` (formerly `KSI-IAM-03`) — Securing Non-User Authentication

Enforce appropriately secure authentication methods for non-user accounts and services.

Mapped Rev5 controls: `ac-2`, `ac-2.2`, `ac-4`, `ac-6.5`, `ia-3`, `ia-5.2`, `ra-5.5`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-IAM-SUS` (formerly `KSI-IAM-06`) — Responding to Suspicious Activity

Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity.

Mapped Rev5 controls: `ac-2`, `ac-2.1`, `ac-2.3`, `ac-2.13`, `ac-7`, `ps-4`, `ps-8`

Terms: `Vulnerability Response`

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
