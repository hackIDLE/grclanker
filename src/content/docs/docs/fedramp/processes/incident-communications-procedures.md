---
title: Incident Communications Procedures — FedRAMP Process
description: Official FRMR-generated summary for the ICP FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# Incident Communications Procedures

Short name: `ICP` · Process ID: `ICP` · Web slug: `incident-communications-procedures`

Applies to: `20x`

Official page: [https://fedramp.gov/docs/20x/incident-communications-procedures](https://fedramp.gov/docs/20x/incident-communications-procedures)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: no
- Shared requirements: 0

## Requirements and Recommendations

## 20X

### `ICP-CSX-AUR` (formerly `FRR-ICP-08`) SHOULD — Automated Reporting

Providers SHOULD use automated mechanisms for reporting incidents and providing updates to all necessary parties (including CISA).

Terms: `All Necessary Parties`, `Incident`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-FIR` (formerly `FRR-ICP-07`) MUST — Final Incident Report

Providers MUST provide a final report once the incident is resolved and recovery is complete that describes at least:

Checklist items:
- What occurred
- Root cause
- Response
- Lessons learned
- Changes needed

Terms: `Incident`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-HRM` (formerly `FRR-ICP-09`) SHOULD — Human and Machine-Readable

Providers SHOULD make incident report information available in consistent human-readable and machine-readable formats.

Terms: `Incident`, `Machine-Readable`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-ICU` (formerly `FRR-ICP-04`) MUST — Incident Updates

Providers MUST update all necessary parties, including at least FedRAMP, CISA (if applicable), and all agency customers, at least once per calendar day until the incident is resolved and recovery is complete.

Terms: `Agency`, `All Necessary Parties`, `Incident`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-IRA` (formerly `FRR-ICP-02`) MUST — Incident Reporting to Agencies

Providers MUST responsibly report incidents to all agency customers within 1 hour of identification using the incident communications points of contact provided by each agency customer.

Terms: `Agency`, `Incident`

Affects: Providers

Structured timeframe: `1` hours

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-IRC` (formerly `FRR-ICP-03`) MUST — Incident Reporting to CISA

Providers MUST responsibly report incidents to CISA within 1 hour of identification if the incident is confirmed or suspected to be the result of an attack vector listed at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy, following the CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident Reporting System at https://myservices.cisa.gov/irf.

Terms: `Incident`

Affects: Providers

Structured timeframe: `1` hours

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-IRF` (formerly `FRR-ICP-01`) MUST — Incident Reporting to FedRAMP

Providers MUST responsibly report incidents to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov.

Terms: `Incident`

Affects: Providers

Structured timeframe: `1` hours

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-RPT` (formerly `FRR-ICP-05`) MUST — Incident Report Availability

Providers MUST make incident report information available in their secure FedRAMP repository (such as USDA Connect) or trust center.

Terms: `Incident`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ICP-CSX-RSD` (formerly `FRR-ICP-06`) MUST NOT — Responsible Disclosure

Providers MUST NOT irresponsibly disclose specific sensitive information about incidents that would likely increase the impact of the incident, but MUST disclose sufficient information for informed risk-based decision-making to all necessary parties.

Terms: `All Necessary Parties`, `Incident`, `Likely`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
