---
title: Key Security Indicators — FedRAMP Process
description: Official FRMR-generated summary for the KSI FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# Key Security Indicators

Short name: `KSI` · Process ID: `KSI` · Web slug: `key-security-indicators`

Applies to: `20x`

Official page: [https://fedramp.gov/docs/20x/key-security-indicators](https://fedramp.gov/docs/20x/key-security-indicators)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: no
- Shared requirements: 0

## Requirements and Recommendations

## 20X

### `KSI-CSX-MAS` (formerly `FRR-KSI-01`) SHOULD — Application within MAS

Providers SHOULD apply ALL Key Security Indicators to ALL aspects of their cloud service offering that are within the FedRAMP Minimum Assessment Scope.

Terms: `Cloud Service Offering`

Affects: Providers

Recent update: 2026-02-04 — Removed unnecessary cloud service at the beginning; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `KSI-CSX-ORD` MAY — AFR Order of Criticality

Providers MAY use the following order of criticality for approaching Authorization by FedRAMP Key Security Indicators for an initial authorization package:

Checklist items:
- Minimum Assessment Scope (MAS)
- Authorization Data Sharing (ADS)
- Using Cryptographic Modules (UCM)
- Vulnerability Detection and Response (VDR)
- Significant Change Notifications (SCN)
- Persistent Validation and Assessment (PVA)
- Secure Configuration Guide (RSC)
- Collaborative Continuous Monitoring (CCM)
- FedRAMP Security Inbox (FSI)
- Incident Communications Procedures (ICP)

Terms: `Authorization Package`, `Authorization data`, `FedRAMP Security Inbox`, `Incident`, `Persistent Validation`, `Persistently`, `Significant change`, `Vulnerability`, `Vulnerability Detection`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-02-04 — This recommendation is new in v-0.9.0 to clarify expectations.

### `KSI-CSX-SUM` (formerly `FRR-KSI-02`) MUST — Implementation Summaries

Providers MUST maintain simple high-level summaries of at least the following for each Key Security Indicator:

Checklist items:
- Goals for how it will be implemented and validated, including clear pass/fail criteria and traceability
- The consolidated _information resources_ that will be validated (this should include consolidated summaries such as "all employees with privileged access that are members of the Admin group")
- The machine-based processes for _validation_ and the _persistent_ cycle on which they will be performed (or an explanation of why this doesn't apply)
- The non-machine-based processes for _validation_ and the _persistent_ cycle on which they will be performed (or an explanation of why this doesn't apply)
- Current implementation status
- Any clarifications or responses to the assessment summary

Terms: `Machine-Based (information resources)`, `Persistent Validation`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
