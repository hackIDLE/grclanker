---
title: FedRAMP Security Inbox — FedRAMP Process
description: Official FRMR-generated summary for the FSI FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists, but grclanker still treats `FedRAMP/docs` as the active source until structured rules land there.

# FedRAMP Security Inbox

Short name: `FSI` · Process ID: `FSI` · Web slug: `fedramp-security-inbox`

Applies to: `both`

Official page: [https://fedramp.gov/docs/20x/fedramp-security-inbox](https://fedramp.gov/docs/20x/fedramp-security-inbox)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: required · Wide Release
- Shared requirements: 16

## Requirements and Recommendations

## BOTH

### `FSI-CSO-ACK` (formerly `FRR-FSI-13`) SHOULD — Acknowledge Receipt

Providers SHOULD promptly and automatically acknowledge the receipt of messages received from FedRAMP in their FedRAMP Security Inbox.

Terms: `FedRAMP Security Inbox`, `Promptly`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-CRA` (formerly `FRR-FSI-14`) MUST — Complete Required Actions

Providers MUST complete the required actions in Emergency or Emergency Test designated messages sent by FedRAMP within the timeframe included in the message.

Terms: `Cloud Service Offering`

Affects: Providers

Note: Timeframes may vary by impact level of the cloud service offering.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-EMR` (formerly `FRR-FSI-15`) MUST — Emergency Message Routing

Providers MUST route Emergency designated messages sent by FedRAMP to a senior security official for their awareness.

Affects: Providers

Note: Senior security officials are determined by the provider.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-IMA` (formerly `FRR-FSI-16`) SHOULD — Important Message Actions

Providers SHOULD complete the required actions in Important designated messages sent by FedRAMP within the timeframe specified in the message.

Terms: `Cloud Service Offering`

Affects: Providers

Note: Timeframes may vary by impact level of the cloud service offering.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-INB` (formerly `FRR-FSI-09`) MUST — Maintain a FedRAMP Security Inbox

Providers MUST establish and maintain an email address to receive messages from FedRAMP; this inbox is a FedRAMP Security Inbox (FSI).

Terms: `FedRAMP Security Inbox`

Affects: Providers

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-NOC` (formerly `FRR-FSI-12`) MUST — Notification of Changes

Providers MUST immediately notify FedRAMP of any changes in addressing for their FedRAMP Security Inbox by emailing info@fedramp.gov with the name and FedRAMP ID of the cloud service offering and the updated email address.

Terms: `Cloud Service Offering`, `FedRAMP Security Inbox`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-RCV` (formerly `FRR-FSI-11`) MUST — Receive Email Without Disruption

Providers MUST receive and react to email messages from FedRAMP without disruption and without requiring additional actions from FedRAMP.

Affects: Providers

Note: This requirement is intended to prevent cloud service providers from requiring FedRAMP to complete a CAPTCHA, log into a customer portal, or otherwise take service-specific actions that might prevent the security team from receiving the message.

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-CSO-TFG` (formerly `FRR-FSI-10`) MUST — Trust @fedramp.gov and @gsa.gov

Providers MUST treat any email originating from an @fedramp.gov or @gsa.gov email address as if it was sent from FedRAMP by default; if such a message is confirmed to originate from someone other than FedRAMP then FedRAMP Security Inbox requirements no longer apply.

Terms: `FedRAMP Security Inbox`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-CDS` (formerly `FRR-FSI-02`) MUST — Criticality Designators

FedRAMP MUST convey the criticality of the message in the subject line, IF the message requires an elevated reaction, using one of the following designators:

Checklist items:
- **Emergency:** There is a potential incident or crisis such that FedRAMP requires an extremely urgent reaction; emergency messages will contain aggressive timeframes for reaction and failure to meet these timeframes will result in corrective action.
- **Emergency Test:** FedRAMP requires an extremely urgent reaction to confirm the functionality and effectiveness of the FedRAMP Security Inbox; emergency test messages will contain aggressive timeframes for reaction and failure to meet these timeframes will result in corrective action.
- **Important:** There is an important issue that FedRAMP requires the cloud service provider to address; important messages will contain reasonable timeframes for reaction and failure to meet these timeframes may result in corrective action.

Terms: `FedRAMP Security Inbox`, `Incident`

Affects: FedRAMP

Note: Messages sent by FedRAMP without one of these designators are considered general communications and do not require an elevated reaction; these may be resolved in the normal course of business by the cloud service provider.

Recent update: 2026-02-04 — Reframed for clarity; changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-COR` (formerly `FRR-FSI-07`) MUST — Explain Corrective Actions

FedRAMP MUST clearly specify the corrective actions that will result from failure to complete the required actions in the body of messages that require an elevated reaction; such actions may vary from negative ratings in the FedRAMP Marketplace to suspension of FedRAMP authorization depending on the severity of the event.

Affects: FedRAMP

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-ERT` (formerly `FRR-FSI-06`) MUST — Elevated Reaction Timeframes

FedRAMP MUST clearly specify the expected timeframe for completing required actions in the body of messages that require an elevated reaction; timeframes for actions will vary depending on the situation but the default timeframes to provide an estimated resolution time for Emergency and Emergency Test designated messages will be as follows:

Checklist items:
- **High Impact:** within 12 hours
- **Moderate Impact:** by 3:00 p.m. Eastern Time on the 2nd business day
- **Low Impact:** by 3:00 p.m. Eastern Time on the 3rd business day

Terms: `Catastrophic Adverse Effect`

Affects: FedRAMP

Note: High impact cloud service providers are expected to address Emergency messages (including tests) from FedRAMP with a reaction time appropriate to operating a service where failure to react rapidly might have a severe or catastrophic adverse effect on the U.S. Government; some Emergency messages may require faster reaction and all such messages should be addressed as quickly as possible.

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-PNT` (formerly `FRR-FSI-04`) MUST — Public Notice of Emergency Tests

FedRAMP MUST post a public notice at least 10 business days in advance of sending an Emergency Test message; such notices MUST include explanation of the likely expected actions and timeframes for the Emergency Test message.

Terms: `Likely`

Affects: FedRAMP

Structured timeframe: `10` bizdays

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-RPM` (formerly `FRR-FSI-08`) MAY — Reaction Metrics

FedRAMP MAY track and publicly share the time required by cloud service providers to take the actions specified in messages that require an elevated reaction.

Affects: FedRAMP

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-RQA` (formerly `FRR-FSI-05`) MUST — Required Actions

FedRAMP MUST clearly specify the required actions in the body of messages that require an elevated reaction.

Affects: FedRAMP

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-UFS` (formerly `FRR-FSI-03`) MUST — Use FedRAMP_Security Email in Emergencies

FedRAMP MUST send Emergency and Emergency Test designated messages from fedramp_security@gsa.gov OR fedramp_security@fedramp.gov.

Affects: FedRAMP

Recent update: 2026-02-04 — Changed response to reaction for clarity; removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `FSI-FRP-VRE` (formerly `FRR-FSI-01`) MUST — Verified Emails

FedRAMP MUST send messages to cloud service providers using an official @fedramp.gov or @gsa.gov email address with properly configured Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and Domain-based Message Authentication Reporting and Conformance (DMARC) email authentication.

Affects: FedRAMP

Note: Anyone at GSA can send email from @fedramp.gov or @gsa.gov - FedRAMP team members will typically have "FedRAMP" or "Q20B" in their name but this is not universal or enforceable. The nature of government enterprise IT services makes it difficult for FedRAMP to isolate FedRAMP-specific team members with enforceable identifiers.

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.
