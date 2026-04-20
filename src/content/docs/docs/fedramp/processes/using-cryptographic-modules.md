---
title: Using Cryptographic Modules — FedRAMP Process
description: Official FRMR-generated summary for the UCM FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/docs](https://github.com/FedRAMP/docs) GitHub repo.
> Source path: [`FRMR.documentation.json`](https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json) on `main` at blob `5c6bfee74029`.
> FRMR version: `0.9.43-beta` · upstream `last_updated`: `2026-04-08`.
> The official `FedRAMP/rules` repo exists and is ready for later integration.

# Using Cryptographic Modules

Short name: `UCM` · Process ID: `UCM` · Web slug: `using-cryptographic-modules`

Applies to: `20x`

Official page: [https://fedramp.gov/docs/20x/using-cryptographic-modules](https://fedramp.gov/docs/20x/using-cryptographic-modules)

## Effective Status

- 20x: required · Phase 2 Pilot
- Rev5: no
- Shared requirements: 0

## Requirements and Recommendations

## 20X

### `UCM-CSX-CAT` (formerly `FRR-UCM-02`) SHOULD — Configuration of Agency Tenants

Providers SHOULD configure agency tenants by default to use cryptographic services that use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when such modules are available.

Terms: `Agency`, `Persistent Validation`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `UCM-CSX-CMD` (formerly `FRR-UCM-01`) MUST — Cryptographic Module Documentation

Providers MUST document the cryptographic modules used in each service (or groups of services that use the same modules) where cryptographic services are used to protect federal customer data, including whether these modules are validated under the NIST Cryptographic Module Validation Program or are update streams of such modules.

Terms: `Federal Customer Data`, `Persistent Validation`

Affects: Providers

Recent update: 2026-02-04 — Removed italics and changed the ID as part of new standardization in v0.9.0-beta; no material changes.

### `UCM-CSX-UVM` — Using Validated Cryptographic Modules



Terms: `Federal Customer Data`, `Persistent Validation`

Affects: Providers
