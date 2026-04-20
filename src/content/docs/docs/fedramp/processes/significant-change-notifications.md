---
title: Significant Change Notifications — FedRAMP Process
description: Official FRMR-generated summary for the SCN FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists and is ready for later integration.

# Significant Change Notifications

Short name: `SCN` · Process ID: `SCN` · Web slug: `significant-change-notifications`

Applies to: `both`

Official page: [https://fedramp.gov/docs/20x/significant-change-notifications](https://fedramp.gov/docs/20x/significant-change-notifications)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: optional · Wide Release
- Shared requirements: 17

## Requirements and Recommendations

## BOTH

### `SCN-ADP-NTF` (formerly `FRR-SCN-AD-01`) MUST — Notification Requirements

Providers MUST notify all necessary parties within 10 business days after finishing adaptive changes, also including the following information:

Checklist items:
- Summary of any new risks identified and/or POA&Ms resulting from the change (if applicable)

Terms: `Adaptive`, `All Necessary Parties`

Affects: Providers

Structured timeframe: `10` bizdays

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-CSO-ARI` (formerly `FRR-SCN-10`) MAY — Additional Relevant Information

Providers MAY include additional relevant information in Significant Change Notifications.

Terms: `Significant change`

Affects: Providers

Note: This allows providers to convey whatever additional information they think is relevant without worrying about negative consequences from not following an exact template.

Recent update: 2026-02-20 — Added note.

### `SCN-CSO-EMG` (formerly `FRR-SCN-EX-02`) MAY — Emergency Changes

Providers MAY execute significant changes (including transformative changes) during an emergency or incident without meeting Significant Change Notification requirements in advance. In such emergencies, providers MUST follow all relevant procedures, notify all necessary parties, retroactively provide all Significant Change Notification materials, and complete appropriate assessment after the incident.

Terms: `All Necessary Parties`, `Incident`, `Significant change`, `Transformative`

Affects: Providers

Note: Procedures for emergency changes should be documented in the authorization package.

Recent update: 2026-02-20 — Clarified wording and added note.

### `SCN-CSO-EVA` MUST — Evaluate Changes

Providers MUST evaluate all potential significant changes to determine the type of significant change and apply the appropriate Significant Change Notification requirements and recommendations.

Checklist items:
- Is it a significant change? --> Continue evaluation and follow the Significant Change Notification process.
- If it is, is it an impact categorization change?  --> This requires a new assessment and cannot be done under the Significant Change Notification process.
- If it is not, is it a routine recurring change? --> Follow the Routine Recurring Change process (SCN-RTR Routine Recurring Changes).
- If it is not, is it a transformative change? --> Follow the Transformative Change process (SCN-TRF Transformative Changes).
- If it is not, then it is an adaptive change --> Follow the Adaptive Change process (SCN-ADP Adaptive Changes).

Terms: `Adaptive`, `Impact Categorization`, `Routine Recurring`, `Significant change`, `Transformative`

Affects: Providers

Recent update: 2026-04-08 — Clarified links to SCN sections within the document; no material changes.

### `SCN-CSO-HIS` (formerly `FRR-SCN-05`) MUST — Historical Notifications

Providers MUST keep 12 months of historical Significant Change Notifications available with their authorization data.

Terms: `All Necessary Parties`, `Significant change`

Affects: Providers

Recent update: 2026-02-20 — Updated requirement to specify 12 months of retention to showcase historical performance.

### `SCN-CSO-HRM` (formerly `FRR-SCN-08`) MUST — Human and Machine-Readable

Providers MUST make ALL Significant Change Notifications and related audit records available in human-readable and machine-readable formats.

Terms: `Machine-Readable`, `Significant change`

Affects: Providers

Note: During the SCN beta, many cloud service providers met this requirement by using carefully structured and organized csv files to meet human-readable and machine-readable requirements simultaneously.

Recent update: 2026-02-20 — Clarified wording and added note.

### `SCN-CSO-INF` (formerly `FRR-SCN-09`) MUST — Required Information

Providers MUST include at least the following information in Significant Change Notifications:

Checklist items:
- Service Offering FedRAMP ID
- Assessor Name (if applicable)
- Related POA&M (if applicable)
- Significant Change type and explanation of categorization
- Short description of change
- Reason for change
- Summary of customer impact, including changes to services and customer configuration responsibilities
- Plan and timeline for the change, including for the verification, assessment, and/or validation of impacted Key Security Indicators or controls
- Copy of the business or security impact analysis
- Name and title of approver

Terms: `Persistent Validation`, `Significant change`

Affects: Providers

Note: Structure of the information may vary depending on how the provider tracks this internally.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-CSO-MAR` (formerly `FRR-SCN-04`) MUST — Maintain Audit Records

Providers MUST maintain auditable records of the significant change evaluation activities required by SCN-CSO-EVA (Evaluate Changes) and make them available to FedRAMP.

Terms: `All Necessary Parties`, `Significant change`

Affects: Providers

Note: These audit records must be available to FedRAMP on request; these records do not need to be included in the authorization package by default.

Recent update: 2026-02-20 — Clarified that this applies to SCN-CSO-EVA evaluation activities.

### `SCN-CSO-NOM` (formerly `FRR-SCN-07`) MAY — Notification Mechanisms

Providers MAY notify necessary parties in a variety of ways as long as the mechanism for notification is clearly documented in the authorization package and easily accessible.

Affects: Providers

Recent update: 2026-02-20 — Clarified wording and added notes.

### `SCN-FRP-CAP` (formerly `FRR-SCN-EX-01`) MAY — Corrective Action Plan Conditions

FedRAMP MAY require providers to delay significant changes beyond the standard Significant Change Notification period and/or submit significant changes for approval in advance as a condition of a formal FedRAMP Corrective Action Plan or other agreement.

Terms: `Significant change`

Affects: FedRAMP

Note: The circumstances and conditions of such a Corrective Action Plan will vary and be documented in the Correcive Action Plan.

Recent update: 2026-02-04 — Moved to FRP; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-RTR-NNR` (formerly `FRR-SCN-RR-01`) SHOULD NOT — No Notification Requirements

Providers SHOULD NOT make formal Significant Change Notifications for routine recurring changes; this type of change is exempted from the notification requirements of this process.

Terms: `Routine Recurring`, `Significant change`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-TRF-NAF` (formerly `FRR-SCN-TR-04`) MUST — Notification After Finishing

Providers MUST notify all necessary parties within 5 business days after finishing transformative changes, including updates to all previously sent information.

Terms: `All Necessary Parties`, `Transformative`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-02-26 — Moved update from following information to direct statement.

### `SCN-TRF-NAV` (formerly `FRR-SCN-TR-05`) MUST — Notification After Verification

Providers MUST notify all necessary parties within 5 business days after completing the verification, assessment, and/or validation of transformative changes, also including the following information:

Checklist items:
- Updates to all previously sent information
- Summary of any new risks identified and/or POA&Ms resulting from the change (if applicable)
- Copy of the security assessment report (if applicable)

Terms: `All Necessary Parties`, `Persistent Validation`, `Transformative`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-TRF-NFP` (formerly `FRR-SCN-TR-03`) MUST — Notification of Final Plans

Providers MUST notify all necessary parties of final plans for transformative changes at least 10 business days before starting transformative changes, including updates to all previously sent information.

Terms: `All Necessary Parties`, `Transformative`

Affects: Providers

Structured timeframe: `10` bizdays

Recent update: 2026-02-26 — Clarified that any updates should be included in each new notification.

### `SCN-TRF-NIP` (formerly `FRR-SCN-TR-02`) MUST — Notification of Initial Plans

Providers MUST notify all necessary parties of initial plans for transformative changes at least 30 business days before starting transformative changes, including a summary of any likely security impacts or changes in risk.

Terms: `All Necessary Parties`, `Transformative`, `Likely`

Affects: Providers

Structured timeframe: `30` bizdays

Recent update: 2026-02-26 — Add an explicit requirement to include a summary of any likely changes to risks that will result from the change.

### `SCN-TRF-TPR` (formerly `FRR-SCN-TR-01`) SHOULD — Third-Party Review

Providers SHOULD engage a third-party assessor to review the scope and impact of the planned change before starting transformative changes if human validation is necessary; such reviews SHOULD be limited to security decisions that require human validation.

Terms: `Cloud Service Offering`, `Persistent Validation`, `Significant change`, `Transformative`

Affects: Providers

Note: Activities that match the transformative significant change type are rare for a cloud service offering, adjusted for the size, scale, and complexity of the service. Small cloud service offerings may go years without transformative changes, while hyperscale providers may release multiple transformative changes per year.

Recent update: 2026-02-04 — Clarified wording; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `SCN-TRF-UPD` (formerly `FRR-SCN-TR-06`) MUST — Update Documentation

Providers MUST publish updated service documentation and other materials to reflect transformative changes within 30 business days after finishing transformative changes.

Terms: `Transformative`

Affects: Providers

Structured timeframe: `30` bizdays

Note: This requirement is focused on service documentation like user guides, information listed in the marketplace, and other such materials; it does not require updating the system security plan or authorization package.

Recent update: 2026-02-20 — Added note.
