---
title: Minimum Assessment Scope — FedRAMP Process
description: Official FRMR-generated summary for the MAS FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# Minimum Assessment Scope

Short name: `MAS` · Process ID: `MAS` · Web slug: `minimum-assessment-scope`

Applies to: `both`

Official page: [https://fedramp.gov/docs/20x/minimum-assessment-scope](https://fedramp.gov/docs/20x/minimum-assessment-scope)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: optional · Wide Release
- Shared requirements: 5

## Requirements and Recommendations

## BOTH

### `MAS-CSO-FLO` (formerly `FRR-MAS-05`) MUST — Information Flows and Security Objectives

Providers MUST clearly identify, document, and explain information flows and security objectives for ALL information resources or sets of information resources in the cloud service offering.

Terms: `Cloud Service Offering`, `Handle`, `Information Resource`, `Third-party Information Resource`

Affects: Providers

Note: Information resources (including third-party information resources) MAY vary by security objectives as appropriate to the level of information handled or impacted by the information resource.

Recent update: 2026-02-04 — Updated wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `MAS-CSO-IIR` (formerly `FRR-MAS-01`) MUST — Identify Information Resources

Providers MUST identify a set of information resources to assess for FedRAMP authorization that includes all information resources that are likely to handle federal customer data or likely to impact the confidentiality, integrity, or availability of federal customer data handled by the cloud service offering; this set of information resources is the cloud service offering.

Terms: `Cloud Service Offering`, `Federal Customer Data`, `Handle`, `Information Resource`, `Likely`

Affects: Providers

Recent update: 2026-02-04 — Added notes from former AY sections; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `MAS-CSO-MDI` (formerly `FRR-MAS-04`) MUST — Metadata Inclusion

Providers MUST include metadata (including metadata about federal customer data) in the Minimum Assessment Scope ONLY IF MAS-CSO-IIR APPLIES.

Terms: `Federal Customer Data`

Affects: Providers

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `MAS-CSO-SUP` (formerly `FRR-MAS-EX-01`) MAY — Supplemental Information

Providers MAY include additional materials about other information resources that are not part of the cloud service offering in a FedRAMP assessment and authorization package supplement; these resources will not be FedRAMP authorized and MUST be clearly marked and separated from the cloud service offering.

Terms: `Agency`, `Authorization Package`, `Cloud Service Offering`, `Information Resource`

Affects: Providers

Note: This is intended to allow inclusion of things like security materials for apps, supplemental marketing collateral, and other information that is not part of the cloud service offering but may be useful to agencies.

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `MAS-CSO-TPR` MUST — Third-Party Information Resources

Providers MUST address the potential impact to federal customer data from third-party information resources used by the cloud service offering, ONLY IF MAS-CSO-IIR APPLIES, by documenting the following information about each applicable third-party information resource:

Checklist items:
- General usage and configuration
- Explanation or justification for use
- Mitigation measures in place to reduce the potential impact to federal customer data
- Compensating controls in place to reduce the potential impact to federal customer data

Terms: `Cloud Service Offering`, `Federal Customer Data`, `Information Resource`, `Third-party Information Resource`

Affects: Providers

Recent update: 2026-02-04 — Rephrased w/ following information, updated application to all third-party resources and merged with former FRR-MAS-02; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
