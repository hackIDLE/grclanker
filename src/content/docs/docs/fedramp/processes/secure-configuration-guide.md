---
title: Secure Configuration Guide — FedRAMP Process
description: Official FRMR-generated summary for the SCG FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists and is ready for later integration.

# Secure Configuration Guide

Short name: `SCG` · Process ID: `SCG` · Web slug: `secure-configuration-guide`

Applies to: `both`

Official page: [https://fedramp.gov/docs/20x/secure-configuration-guide](https://fedramp.gov/docs/20x/secure-configuration-guide)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: required · Wide Release
- Shared requirements: 9

## Requirements and Recommendations

## BOTH

### `SCG-CSO-AUP` MUST — Use Instructions

Providers MUST include instructions in the FedRAMP authorization package that explain how to obtain and use the Secure Configuration Guide.

Terms: `Authorization Package`

Affects: Providers

Note: These instructions may appear in a variety of ways; it is up to the provider to do so in the most appropriate and effective ways for their specific customer needs.

Recent update: 2026-02-04 — This requirement is new in v-0.9.0 to clarify expectations.

### `SCG-CSO-PUB` (formerly `FRR-RSC-09`) SHOULD — Public Guidance

Providers SHOULD make the Secure Configuration Guide available publicly.

Affects: Providers

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-CSO-RSC` MUST — Recommended Secure Configuration

Providers MUST create, maintain, and make available recommendations for securely configuring their cloud services (the Secure Configuration Guide) that includes at least the following information:

Checklist items:
- Required: Instructions on how to securely access, configure, operate, and decommission top-level administrative accounts that control enterprise access to the entire cloud service offering.
- Required: Explanations of security-related settings that can be operated only by top-level administrative accounts and their security implications.
- Recommended: Explanations of security-related settings that can be operated only by privileged accounts and their security implications.

Terms: `Cloud Service Offering`, `Privileged account`, `Top-level administrative account`

Affects: Providers

Recent update: 2026-02-04 — Combined all required and recommended SCG information; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-CSO-SDF` (formerly `FRR-RSC-04`) SHOULD — Secure Defaults

Providers SHOULD set all settings to their recommended secure defaults for top-level administrative accounts and privileged accounts when initially provisioned.

Terms: `Privileged account`, `Top-level administrative account`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-ENH-API` (formerly `FRR-RSC-07`) SHOULD — API Capability

Providers SHOULD offer the capability to view and adjust security settings via an API or similar capability.

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-ENH-CMP` (formerly `FRR-RSC-05`) SHOULD — Comparison Capability

Providers SHOULD offer the capability to compare all current settings for top-level administrative accounts and privileged accounts to the recommended secure defaults.

Terms: `Privileged account`, `Top-level administrative account`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-ENH-EXP` (formerly `FRR-RSC-06`) SHOULD — Export Capability

Providers SHOULD offer the capability to export all security settings in a machine-readable format.

Terms: `Machine-Readable`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-ENH-MRG` (formerly `FRR-RSC-08`) SHOULD — Machine-Readable Guidance

Providers SHOULD also provide the Secure Configuration Guide in a machine-readable format that can be used by customers or third-party tools to compare against current settings.

Terms: `Machine-Readable`

Affects: Providers

Recent update: 2026-02-04 — Removed unnecessary recommended; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCG-ENH-VRH` (formerly `FRR-RSC-10`) SHOULD — Versioning and Release History

Providers SHOULD provide versioning and a release history for recommended secure default settings for top-level administrative accounts and privileged accounts as they are adjusted over time.

Terms: `Privileged account`, `Top-level administrative account`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
