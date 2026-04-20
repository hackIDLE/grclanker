---
title: Authorization Data Sharing — FedRAMP Process
description: Official FRMR-generated summary for the ADS FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists and is ready for later integration.

# Authorization Data Sharing

Short name: `ADS` · Process ID: `ADS` · Web slug: `authorization-data-sharing`

Applies to: `both`, `20x`, `rev5`

Official page: [https://fedramp.gov/docs/20x/authorization-data-sharing](https://fedramp.gov/docs/20x/authorization-data-sharing)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: optional · Open Beta
- Shared requirements: 15

## Requirements and Recommendations

## BOTH

### `ADS-CSO-CBF` (formerly `FRR-ADS-02`) MUST — Consistency Between Formats

Providers MUST use automation to ensure information remains consistent between human-readable and machine-readable formats when authorization data is provided in both formats.

Terms: `Authorization data`, `Machine-Readable`

Affects: Providers

Recent update: 2026-02-04 — Simplified statement; removed italics and changed the ID as part of new standardization in v0.9.0-beta.

### `ADS-CSO-HAD` (formerly `FRR-ADS-09`) MUST — Historical Authorization Data

Providers MUST make historical versions of authorization data available for three years to all necessary parties UNLESS otherwise specified by applicable FedRAMP requirements; deltas between versions MAY be consolidated quarterly.

Terms: `All Necessary Parties`, `Authorization data`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-CSO-PUB` (formerly `FRR-ADS-01`) MUST — Public Information

Providers MUST publicly share up-to-date information about the cloud service offering in both human-readable and machine-readable formats, including at least:

Checklist items:
- Direct link to the FedRAMP Marketplace for the offering
- Service Model
- Deployment Model
- Business Category
- UEI Number
- Contact Information
- Overall Service Description
- Detailed list of specific services and their security objectives (see ADS-CSO-SVC)
- Summary of customer responsibilities and secure configuration guidance (if applicable, see the FedRAMP Secure Configuration Guide process)
- Process for accessing information in the trust center (if applicable)
- Availability status and recent disruptions for the trust center (if applicable)
- Customer support information for the trust center (if applicable)
- Next Ongoing Authorization Report date (see CCM-OAR-NRD)

Terms: `Cloud Service Offering`, `Machine-Readable`, `Ongoing Authorization Report (OAR)`, `Trust Center`

Affects: Providers

Note: Generally, this information should be available on a public webpage.

Recent update: 2026-02-04 — Added requirements from other processes; removed italics and changed the ID as part of new standardization in v0.9.0-beta.

### `ADS-CSO-RIS` (formerly `FRR-ADS-05`) MUST — Responsible Information Sharing

Providers MUST provide sufficient information in authorization data to support authorization decisions but SHOULD NOT include sensitive information that would likely enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the cloud service offering.

Terms: `Authorization data`, `Cloud Service Offering`, `Likely`

Affects: Providers

Note: This is not a license to exclude accurate risk information, but specifics that would likely lead to compromise should be abstracted. A breach of confidentiality with authorization data should be anticipated by a secure cloud service provider.

Recent update: 2026-02-04 — Added technical assistance; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-CSO-SVC` (formerly `FRR-ADS-03`) MUST — Service List

Providers MUST publicly share a detailed list of specific services and their security objectives that are included in the cloud service offering using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP Minimum Assessment Scope without requesting access to underlying authorization data.

Terms: `Authorization data`, `Cloud Service Offering`

Affects: Providers

Recent update: 2026-02-04 — Changed impact levels to security objectives; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-AAI` (formerly `FRR-ADS-TC-05`) MUST — Agency Access Inventory

Trust centers MUST maintain an inventory and history of federal agency users or systems with access to authorization data and MUST make this information available to FedRAMP without interruption.

Terms: `Agency`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-ACL` (formerly `FRR-ADS-TC-06`) MUST — Access Logging

Trust centers MUST log access to authorization data and store summaries of access for at least six months; such information, as it pertains to specific parties, SHOULD be made available upon request by those parties.

Terms: `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-HMR` (formerly `FRR-ADS-TC-02`) SHOULD — Human and Machine-Readable

Trust centers SHOULD make authorization data available to view and download in both human-readable and machine-readable formats.

Terms: `Authorization data`, `Machine-Readable`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-PAC` (formerly `FRR-ADS-TC-03`) MUST — Programmatic Access

Trust centers MUST provide documented programmatic access to all authorization data, including programmatic access to human-readable materials.

Terms: `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-RSP` (formerly `FRR-ADS-TC-07`) SHOULD — Responsive Performance

Trust centers SHOULD deliver responsive performance during normal operating conditions and minimize service disruptions.

Terms: `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-SSM` (formerly `FRR-ADS-TC-04`) SHOULD — Self-Service Access Management

Trust centers SHOULD include features that encourage all necessary parties to provision and manage access to authorization data for their users and services directly.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-TRC-USH` (formerly `FRR-ADS-04`) MUST — Uninterrupted Sharing

Trust centers MUST share authorization data with all necessary parties without interruption.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Note: "Without interruption" means that parties should not have to request manual approval each time they need to access authorization data or go through a complicated process. The preferred way of ensuring access without interruption is to use on-demand just-in-time access provisioning.

Recent update: 2026-02-04 — Removed unnecessary specification of necessary parties; changed from provider to trust center responsibility; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-UTC-AAD` (formerly `ADS-CSO-AAD`) MUST — Agency Access Denial

Providers MUST notify FedRAMP by email to info@fedramp.gov within 5 business days of denying an agency access request for authorization data.

Terms: `Agency`, `Authorization data`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-02-04 — Split from FRR-ADS-AC-02; removed italics and changed the ID as part of new standardization in v0.9.0-beta.

### `ADS-UTC-AGA` SHOULD — Agency Access

Providers SHOULD share the authorization package with agencies upon request.

Terms: `Agency`, `Authorization Package`

Affects: Providers

Recent update: 2026-02-04 — Split into ADS-CSO-AGA and ADS-CSO-AAD; removed italics and changed the ID as part of new standardization in v0.9.0-beta.

### `ADS-UTC-PGD` MUST — Public Guidance

Providers MUST publicly provide plain-language policies and guidance for all necessary parties that explains how they can obtain and manage access to authorization data stored in the trust center.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

## 20X

### `ADS-CSX-UTC` (formerly `FRR-ADS-07`) MUST — Use Trust Centers

Providers MUST use a FedRAMP-compatible trust center to store and share authorization data with all necessary parties.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Modified to must for 20x, clarified wider application; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

## REV5

### `ADS-CSL-LRE` (formerly `FRR-ADS-EX-01`) MAY — Legacy Repository Exception

Providers of FedRAMP Rev5 Authorized cloud service offerings at FedRAMP High using a legacy self-managed repository for authorization data MAY ignore the Authorization Data Sharing process until future notice.

Terms: `Authorization data`, `Cloud Service Offering`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-CSL-TCM` (formerly `FRR-ADS-08`) MUST — Trust Center Migration

Providers MUST notify all necessary parties when migrating to a trust center and MUST provide information in their existing USDA Connect Community Portal secure folders explaining how to use the trust center to obtain authorization data.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-CSL-UCP` (formerly `FRR-ADS-06`) MUST — USDA Connect

Providers MUST share authorization data via the USDA Connect Community Portal UNLESS they use a FedRAMP-compatible trust center.

Terms: `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `ADS-CSL-UTC` (formerly `ADS-CSX-UTC`) SHOULD — Use Trust Centers

Providers SHOULD use a FedRAMP-compatible trust center to store and share authorization data with all necessary parties.

Terms: `All Necessary Parties`, `Authorization data`, `Trust Center`

Affects: Providers

Recent update: 2026-02-04 — Modified to should, clarified wider application; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
