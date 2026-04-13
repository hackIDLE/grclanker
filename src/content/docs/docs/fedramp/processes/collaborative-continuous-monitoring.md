---
title: Collaborative Continuous Monitoring — FedRAMP Process
description: Official FRMR-generated summary for the CCM FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# Collaborative Continuous Monitoring

Short name: `CCM` · Process ID: `CCM` · Web slug: `collaborative-continuous-monitoring`

Applies to: `both`

Official page: [https://fedramp.gov/docs/20x/collaborative-continuous-monitoring](https://fedramp.gov/docs/20x/collaborative-continuous-monitoring)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: optional · Open Beta
- Shared requirements: 24

## Requirements and Recommendations

## BOTH

### `CCM-AGM-CSC` (formerly `FRR-CCM-AG-02`) SHOULD — Consider Security Category

Agencies SHOULD consider the Security Category noted in their Authorization to Operate of the federal information system that includes the cloud service offering in its boundary and assign appropriate information security resources for reviewing Ongoing Authorization Reports, attending Quarterly Reviews, and other ongoing authorization data.

Terms: `Agency`, `Authorization data`, `Cloud Service Offering`, `Quarterly Review`

Affects: Agencies

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-NAR` (formerly `FRR-CCM-AG-06`) MUST NOT — No Additional Requirements

Agencies MUST NOT place additional security requirements on cloud service providers beyond those required by FedRAMP UNLESS the head of the agency or an authorized delegate makes a determination that there is a demonstrable need for such; this does not apply to seeking clarification or asking general questions about authorization data.

Terms: `Agency`, `Authorization data`

Affects: Agencies

Note: This is a statutory requirement in 44 USC § 3613 (e) related to the Presumption of Adequacy for a FedRAMP authorization.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-NFA` (formerly `FRR-CCM-AG-07`) MUST — Notify FedRAMP After Requests

Agencies MUST notify FedRAMP after requesting any additional information or materials from a cloud service provider beyond those FedRAMP requires by sending an email to info@fedramp.gov.

Terms: `Agency`

Affects: Agencies

Note: Agencies are required to notify FedRAMP by OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-02-04 — Clarified notification requirements; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-NFR` (formerly `FRR-CCM-AG-05`) MUST — Notify FedRAMP of Concerns

Agencies MUST notify FedRAMP by sending an email to info@fedramp.gov if the information presented in an Ongoing Authorization Report, Quarterly Review, or other ongoing authorization data causes significant concerns that may lead the agency to stop operation of the cloud service offering.

Terms: `Agency`, `Authorization data`, `Cloud Service Offering`, `Ongoing Authorization Report (OAR)`, `Quarterly Review`

Affects: Agencies

Note: Agencies are required to notify FedRAMP by OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-NPC` (formerly `FRR-CCM-AG-04`) SHOULD — Notify Provider of Concerns

Agencies SHOULD formally notify the provider if the information presented in an Ongoing Authorization Report, Quarterly Review, or other ongoing authorization data causes significant concerns that may lead the agency to remove the cloud service offering from operation.

Terms: `Agency`, `Authorization data`, `Cloud Service Offering`, `Ongoing Authorization Report (OAR)`, `Quarterly Review`

Affects: Agencies

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-ROR` (formerly `FRR-CCM-AG-01`) MUST — Review Ongoing Reports

Agencies MUST review each Ongoing Authorization Report to understand how changes to the cloud service offering may impact the previously agreed-upon risk tolerance documented in the agency's Authorization to Operate of a federal information system that includes the cloud service offering in its boundary.

Terms: `Agency`, `Cloud Service Offering`, `Ongoing Authorization Report (OAR)`

Affects: Agencies

Note: This is required by 44 USC § 35, OMB A-130, FIPS-200, and M-24-15.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-AGM-SSR` (formerly `FRR-CCM-AG-03`) — Senior Security Reviewer



Terms: `Agency`, `Cloud Service Offering`, `Quarterly Review`

Affects: Agencies

Recent update: 2026-03-17 — Changed mention of Security Category to security objective and added Low and Moderate.

### `CCM-OAR-AFS` (formerly `FRR-CCM-05`) MUST — Anonymized Feedback Summary

Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each Ongoing Authorization Report as an addendum to the Ongoing Authorization Report.

Terms: `Agency`, `Ongoing Authorization Report (OAR)`

Affects: Providers

Note: This is intended to encourage sharing of information and decrease the burden on the cloud service provider - providing this summary will reduce duplicate questions from agencies and ensure FedRAMP has access to this information. It is generally in the provider’s interest to update this addendum frequently throughout the quarter.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-AVL` (formerly `FRR-CCM-01`) MUST — Report Availability

Providers MUST make an Ongoing Authorization Report available to all necessary parties every 3 months, covering the entire period since the previous summary, in a consistent format that is human readable; this report MUST include high-level summaries of at least the following information:

Checklist items:
- Changes to authorization data
- Planned changes to authorization data during at least the next 3 months
- Accepted vulnerabilities
- Transformative changes
- Updated recommendations or best practices for security, configuration, usage, or similar aspects of the cloud service offering

Terms: `Accepted Vulnerability`, `All Necessary Parties`, `Authorization data`, `Cloud Service Offering`, `Ongoing Authorization Report (OAR)`, `Transformative`, `Vulnerability`

Affects: Providers

Recent update: 2026-02-04 — Re-ordered phrasing; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-FBM` (formerly `FRR-CCM-04`) MUST — Feedback Mechanism

Providers MUST establish and share an asynchronous mechanism for all necessary parties to provide feedback or ask questions about each Ongoing Authorization Report.

Terms: `All Necessary Parties`, `Ongoing Authorization Report (OAR)`

Affects: Providers

Note: This could be email by default but providers are encouraged to consider something more interactive as appropriate.

Recent update: 2026-02-04 — Added note; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-LSI` (formerly `FRR-CCM-06`) MUST NOT — Limit Sensitive Information

Providers MUST NOT irresponsibly disclose sensitive information in an Ongoing Authorization Report that would likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Ongoing Authorization Report (OAR)`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-NRD` (formerly `FRR-CCM-03`) MUST — Next Report Date

Providers MUST publicly include the target date for their next Ongoing Authorization Report with other public authorization data.

Terms: `Authorization data`, `Ongoing Authorization Report (OAR)`

Affects: Providers

Recent update: 2026-02-04 — Clarified; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-RPS` (formerly `FRR-CCM-07`) MAY — Responsible Public Sharing

Providers MAY responsibly share some or all of the information an Ongoing Authorization Report publicly or with other parties if the provider determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Ongoing Authorization Report (OAR)`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-OAR-SOR` (formerly `FRR-CCM-02`) SHOULD — Spread Out Reports

Providers SHOULD establish a regular 3 month cycle for Ongoing Authorization Reports that is spread out from the beginning, middle, or end of each quarter.

Terms: `Agency`, `Regularly`

Affects: Providers

Note: This recommendation is intended to discourage hundreds of cloud service providers from releasing their Ongoing Authorization Reports during the first or last week of each quarter because that is the easiest way for a single provider to track this deliverable; the result would overwhelm agencies with many cloud services. Widely used cloud service providers are encouraged to work with their customers to identify ideal timeframes for this cycle.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-ACT` (formerly `FRR-CCM-QR-07`) SHOULD — Additional Content

Providers SHOULD include additional information in Quarterly Reviews that the provider determines is of interest, use, or otherwise relevant to agencies.

Terms: `Agency`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-MTG` — Quarterly Review Meeting



Terms: `Agency`, `All Necessary Parties`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Combined requirements and recommendations that varied by impact level into a single set with minor wording modification as appropriate.

### `CCM-QTR-NID` (formerly `FRR-CCM-QR-04`) MUST NOT — No Irresponsible Disclosure

Providers MUST NOT irresponsibly disclose sensitive information in a Quarterly Review that would likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-NRD` (formerly `FRR-CCM-QR-06`) MUST — Next Review Date

Providers MUST publicly include the target date for their next Quarterly Review with other public authorization data.

Terms: `Authorization data`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Clarified; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-REG` (formerly `FRR-CCM-QR-05`) MUST — Meeting Registration Info

Providers MUST include either a registration link or a downloadable calendar file with meeting information for Quarterly Reviews in the authorization data available to all necessary parties required by ADS-CSL-UCP and ADS-CSO-FCT.

Terms: `All Necessary Parties`, `Authorization data`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-RTP` (formerly `FRR-CCM-QR-08`) SHOULD NOT — Restrict Third Parties

Providers SHOULD NOT invite third parties to attend Quarterly Reviews intended for agencies unless they have specific relevance.

Terms: `Agency`, `Likely`, `Quarterly Review`

Affects: Providers

Note: This is because agencies are less likely to actively participate in meetings with third parties; the cloud service provider's independent assessor should be considered relevant by default.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-RTR` (formerly `FRR-CCM-QR-09`) SHOULD — Record/Transcribe Reviews

Providers SHOULD record or transcribe Quarterly Reviews and make such available to all necessary parties with other authorization data.

Terms: `All Necessary Parties`, `Authorization data`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Simplified; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-SAR` (formerly `FRR-CCM-QR-03`) SHOULD — Schedule Around Reports

Providers SHOULD regularly schedule Quarterly Reviews to occur at least 3 business days after releasing an Ongoing Authorization Report AND within 10 business days of such release.

Terms: `Ongoing Authorization Report (OAR)`, `Quarterly Review`, `Regularly`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-SCR` (formerly `FRR-CCM-QR-11`) MAY — Share Content Responsibly

Providers MAY responsibly share content prepared for a Quarterly Review with the public or other parties if the provider determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `CCM-QTR-SRR` (formerly `FRR-CCM-QR-10`) MAY — Share Recordings Responsibly

Providers MAY responsibly share recordings or transcriptions of Quarterly Reviews with the public or other parties ONLY if the provider removes all agency information (comments, questions, names, etc.) AND determines sharing will NOT likely have an adverse effect on the cloud service offering.

Terms: `Agency`, `Cloud Service Offering`, `Likely`, `Quarterly Review`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
