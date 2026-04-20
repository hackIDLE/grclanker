---
title: Persistent Validation and Assessment — FedRAMP Process
description: Official FRMR-generated summary for the PVA FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists and is ready for later integration.

# Persistent Validation and Assessment

Short name: `PVA` · Process ID: `PVA` · Web slug: `persistent-validation-and-assessment`

Applies to: `20x`

Official page: [https://fedramp.gov/docs/20x/persistent-validation-and-assessment](https://fedramp.gov/docs/20x/persistent-validation-and-assessment)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: no
- Shared requirements: 0

## Requirements and Recommendations

## 20X

### `PVA-CSX-FAV` (formerly `FRR-PVA-02`) MUST — Issues As Vulnerabilities

Providers MUST treat issues detected during persistent validation and failures of the persistent validation process as vulnerabilities, then follow the requirements and recommendations in the FedRAMP Vulnerability Detection and Response process for such findings.

Terms: `Persistent Validation`, `Persistently`, `Vulnerability`, `Vulnerability Detection`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-CSX-IVV` (formerly `FRR-PVA-05`) MUST — Independent Verification and Validation

Providers MUST have the implementation of their goals and validation processes assessed by a FedRAMP-recognized independent assessor OR by FedRAMP directly AND MUST include the results of this assessment in their authorization data without modification.

Terms: `Authorization data`, `Persistent Validation`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-CSX-NMV` MUST — Non-Machine Validation

Providers MUST complete the validation processes for Key Security Indicators of non-machine-based information resources at least once every 3 months.

Terms: `Information Resource`, `Machine-Based (information resources)`, `Persistent Validation`

Affects: Providers

### `PVA-CSX-PMV` — Persistent Machine Validation



Terms: `Information Resource`, `Machine-Based (information resources)`, `Persistent Validation`

Affects: Providers

### `PVA-CSX-PTE` (formerly `FRR-PVA-07`) SHOULD — Provide Technical Evidence

Providers SHOULD provide technical explanations, demonstrations, and other relevant supporting information to all necessary assessors for the technical capabilities they employ to meet Key Security Indicators and to provide validation.

Terms: `All Necessary Assessors`, `Persistent Validation`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-CSX-RAD` (formerly `FRR-PVA-08`) MAY — Receiving Advice

Providers MAY ask for and accept advice from their assessor during assessment regarding techniques and procedures that will improve their security posture or the effectiveness, clarity, and accuracy of their validation and reporting procedures for Key Security Indicators, UNLESS doing so might compromise the objectivity and integrity of the assessment (see also PVA-TPX-SHA).

Terms: `Persistent Validation`

Affects: Providers

Note: The related A2LA requirements are waived for FedRAMP 20x Phase Two assessments.

Recent update: 2026-02-09 — Fixed incorrect reference to old FRR by changing PVA-TPX-AMA to PVA-TPX-SHA; no material changes.

### `PVA-CSX-RPV` (formerly `FRR-PVA-03`) MUST — Report Persistent Validation

Providers MUST include persistent validation activity in the reports on vulnerability detection and response activity required by the FedRAMP Vulnerability Detection and Response process.

Terms: `Persistent Validation`, `Persistently`, `Vulnerability`, `Vulnerability Detection`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-CSX-VAL` (formerly `FRR-PVA-01`) MUST — Persistent Validation

Providers MUST persistently perform validation of their Key Security Indicators; this process is called persistent validation and is part of vulnerability detection.

Terms: `Persistent Validation`, `Persistently`, `Vulnerability`, `Vulnerability Detection`

Affects: Providers

Recent update: 2026-02-04 — Clarified; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-MME` (formerly `FRR-PVA-13`) MUST — Mixed Methods Evaluation

Assessors MUST perform evaluation using a combination of quantitative and expert qualitative assessment as appropriate AND document which is applied to which aspect of the assessment.

Affects: Assessors

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-NOR` (formerly `FRR-PVA-18`) MUST NOT — No Overall Recommendation

Assessors MUST NOT deliver an overall recommendation on whether or not the cloud service offering meets the requirements for FedRAMP authorization.

Terms: `Cloud Service Offering`

Affects: Assessors

Note: FedRAMP will make the final authorization decision based on the assessor's findings and other relevant information.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-OUC` (formerly `FRR-PVA-12`) MUST — Outcome Consistency

Assessors MUST verify and validate whether or not the underlying processes are consistently creating the desired security outcome documented by the provider.

Terms: `Persistent Validation`

Affects: Assessors

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-PAD` (formerly `FRR-PVA-16`) MUST — Procedure Adherence

Assessors MUST assess whether or not procedures are consistently followed, including the processes in place to ensure this occurs, without relying solely on the existence of a procedure document for assessing if appropriate processes and procedures are in place.

Affects: Assessors

Note: This includes evaluating tests or plans for activities that may occur in the future but have not yet occurred.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-PDK` (formerly `FRR-PVA-11`) MUST — Processes Derived from Key Security Indicators

Assessors MUST verify and validate the implementation of processes derived from Key Security Indicators to determine whether or not the provider has accurately documented their process and goals.

Terms: `Persistent Validation`

Affects: Assessors

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-PEX` (formerly `FRR-PVA-14`) SHOULD — Provider Experts

Assessors SHOULD engage provider experts in discussion to understand the decisions made by the provider and inform expert qualitative assessment, and SHOULD perform independent research to test such information as part of the expert qualitative assessment process.

Affects: Assessors

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-SHA` (formerly `FRR-PVA-09`) MAY — Sharing Advice

Assessors MAY share advice with providers they are assessing about techniques and procedures that will improve their security posture or the effectiveness, clarity, and accuracy of their validation and reporting procedures for Key Security Indicators, UNLESS doing so might compromise the objectivity and integrity of the assessment (see also PVA-CSX-RAD).

Terms: `Persistent Validation`

Affects: Assessors

Recent update: 2026-02-09 — Fixed incorrect reference to old FRR by changing PVA-CSX-RIA to PVA-CSX-RAD; no material changes.

### `PVA-TPX-STE` (formerly `FRR-PVA-15`) MUST NOT — Static Evidence

Assessors MUST NOT rely on screenshots, configuration dumps, or other static output as evidence EXCEPT when evaluating the accuracy and reliability of a process that generates such artifacts.

Affects: Assessors

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-SUM` (formerly `FRR-PVA-17`) MUST — Assessment Summary

Assessors MUST deliver a high-level summary of their assessment process and findings for each Key Security Indicator; this summary will be included in the authorization data for the cloud service offering.

Terms: `Authorization data`, `Cloud Service Offering`

Affects: Assessors

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `PVA-TPX-UNP` (formerly `FRR-PVA-10`) MUST — Underlying Processes

Assessors MUST verify and validate the underlying processes (both machine-based and non-machine-based) that providers use to validate Key Security Indicators; this should include at least:

Checklist items:
- The effectiveness, completeness, and integrity of the automated processes that perform validation of the cloud service offering's security posture.
- The effectiveness, completeness, and integrity of the human processes that perform validation of the cloud service offering's security posture
- The coverage of these processes within the cloud service offering, including if all of the consolidated information resources listed are being validated.

Terms: `Cloud Service Offering`, `Information Resource`, `Machine-Based (information resources)`, `Persistent Validation`

Affects: Assessors

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
