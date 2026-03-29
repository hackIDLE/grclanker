# grclanker

Open-source `spec.md` files for building GRC compliance automations. Grab one. Feed it to your agent.

Each spec describes a Go CLI tool that authenticates to a vendor's API, pulls security configuration data, and maps findings to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, and STIG controls.

---

## Why?

Compliance automation is treated like a black box — as if it's spectacularly complicated rocket science. It's not. It's API connectors pulling information that's always been there. The industry overcomplicates it for no reason.

These specs take the ideas out of my head and give them away because that's the right thing to do. Every spec is a complete blueprint: the APIs, the auth flow, the security controls, the framework mappings, the architecture, the build sequence. Hand it to any coding agent and you get a working compliance tool.

The spec-driven approach is inspired in part by projects like OpenAI's [Symphony SPEC.md](https://github.com/openai/symphony/blob/main/SPEC.md) — the idea that a well-structured spec file is all an agent needs to build something real. No proprietary platform required. No vendor lock-in. Just a markdown file and whatever agent you already use.

---

## Quick Start

**Clone everything:**

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
```

**Grab a single spec:**

```bash
curl -O https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md
```

**Feed it to your agent:**

```bash
# Claude Code
claude "Read https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md and build the tool"

# OpenAI Codex CLI
codex "Read https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md and build the tool"

# Gemini CLI
gemini "Read https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md and implement this spec"

# Any agent — just pass the raw URL
your-agent "Read https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md and build the tool"
```

---

## Spec Catalog

### Cloud Infrastructure

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [aws-sec-inspector](specs/aws-sec-inspector.spec.md) | Amazon Web Services | Security Hub, Config, IAM, Access Analyzer. Unified multi-framework compliance reports. |
| [azure-sec-inspector](specs/azure-sec-inspector.spec.md) | Microsoft | Azure subscriptions and M365 tenants via Graph API, ARM, Defender for Cloud. |
| [gcp-sec-inspector](specs/gcp-sec-inspector.spec.md) | Google Cloud | GCP infrastructure, IAM policies, encryption, org constraints via Security Command Center. |
| [oci-sec-inspector](specs/oci-sec-inspector.spec.md) | Oracle | OCI IAM, networking, Cloud Guard posture, vault key management, audit logging. |
| [snowflake-sec-inspector](specs/snowflake-sec-inspector.spec.md) | Snowflake | IAM, network security, data protection policies, encryption, audit logging. |

### Identity & Access Management

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [duo-sec-inspector](specs/duo-sec-inspector.spec.md) | Cisco | MFA configurations, policies, user enrollment, trust monitor alerts via Admin API. |
| [gws-inspector-go](specs/gws-inspector-go.spec.md) | Google | Multi-framework compliance audit for Google Workspace. |

### Security & Network Infrastructure

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [crowdstrike-sec-inspector](specs/crowdstrike-sec-inspector.spec.md) | CrowdStrike | Falcon EDR: prevention policies, sensor deployment, device control settings. |
| [paloalto-sec-inspector](specs/paloalto-sec-inspector.spec.md) | Palo Alto Networks | Prisma Cloud CSPM/CWPP and PAN-OS firewalls. Policy enforcement, compliance configs. |
| [zscaler-sec-inspector](specs/zscaler-sec-inspector.spec.md) | Zscaler | ZIA and ZPA: URL filtering, DLP policies, SSL inspection, app segmentation. |
| [cloudflare-sec-inspector](specs/cloudflare-sec-inspector.spec.md) | Cloudflare | WAF configs, Zero Trust policies, SSL/TLS, DNS security, API token permissions. |

### Vulnerability & Application Security

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [qualys-sec-inspector](specs/qualys-sec-inspector.spec.md) | Qualys | Vuln management configs, compliance profiles, scan coverage, asset group hygiene. |
| [tenable-sec-inspector](specs/tenable-sec-inspector.spec.md) | Tenable | Scan policies, asset coverage, credential audits, agent deployment, user permissions. |
| [veracode-sec-inspector](specs/veracode-sec-inspector.spec.md) | Veracode | Scan coverage, policy compliance, flaw aging, SCA library health, access controls. |
| [knowbe4-sec-inspector](specs/knowbe4-sec-inspector.spec.md) | KnowBe4 | Security awareness training coverage, completion rates, user risk scores. |

### Monitoring, Logging & Observability

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [splunk-sec-inspector](specs/splunk-sec-inspector.spec.md) | Splunk | Authentication, authorization, server settings, data pipelines, index clustering. |
| [datadog-sec-inspector](specs/datadog-sec-inspector.spec.md) | Datadog | RBAC, API key management, log pipelines, security monitoring. |
| [newrelic-sec-inspector](specs/newrelic-sec-inspector.spec.md) | New Relic | Authentication, user access controls, API key management, data governance. |
| [sumologic-sec-inspector](specs/sumologic-sec-inspector.spec.md) | Sumo Logic | Authentication policies, access controls, data governance, operational security. |
| [elastic-sec-inspector](specs/elastic-sec-inspector.spec.md) | Elastic | Authentication realms, TLS configs, RBAC, field/document-level security. |

### SaaS & Collaboration

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [salesforce-sec-inspector](specs/salesforce-sec-inspector.spec.md) | Salesforce | Security settings, user permissions, auth policies, data protection. |
| [servicenow-sec-inspector](specs/servicenow-sec-inspector.spec.md) | ServiceNow | Platform security configs, ACL rules, user/role management, authentication. |
| [slack-sec-inspector](specs/slack-sec-inspector.spec.md) | Slack | Enterprise Grid: SSO enforcement, MFA policies, DLP settings, external sharing. |
| [zoom-sec-inspector](specs/zoom-sec-inspector.spec.md) | Zoom | Zoom for Government: meeting policies, recording controls, auth enforcement. |
| [webex-sec-inspector](specs/webex-sec-inspector.spec.md) | Cisco | IAM, messaging policies, meeting security, recording governance, device management. |
| [zendesk-sec-inspector](specs/zendesk-sec-inspector.spec.md) | Zendesk | Authentication settings, agent access controls, data protection, audit logging. |
| [box-sec-inspector](specs/box-sec-inspector.spec.md) | Box | Authentication policies, sharing controls, data governance, device trust. |

### DevOps & Developer Platforms

| Spec | Vendor | What It Audits |
|------|--------|----------------|
| [github-sec-inspector](specs/github-sec-inspector.spec.md) | GitHub | Enterprise Cloud: SSO enforcement, branch protection, code security, Actions workflows. |
| [pagerduty-sec-inspector](specs/pagerduty-sec-inspector.spec.md) | PagerDuty | Authentication settings, user roles, access controls, escalation policy coverage. |
| [launchdarkly-sec-inspector](specs/launchdarkly-sec-inspector.spec.md) | LaunchDarkly | IAM, feature flag hygiene, API token lifecycle, integration security. |
| [mulesoft-sec-inspector](specs/mulesoft-sec-inspector.spec.md) | MuleSoft | Anypoint Platform: IAM, API gateway policies, runtime security, environment isolation. |

---

## Spec Format

Every spec follows the same 10-section structure:

1. **Overview** -- What the tool does and why it matters
2. **APIs & SDKs** -- Vendor API endpoints and SDK references
3. **Authentication** -- Credential models and auth flows
4. **Security Controls** -- What security configurations are audited
5. **Compliance Framework Mappings** -- How controls map to FedRAMP, CMMC, SOC 2, etc.
6. **Existing Tools** -- What's already out there (and what's missing)
7. **Architecture** -- Tool design and data flow
8. **CLI Interface** -- Commands, flags, output formats
9. **Build Sequence** -- Step-by-step implementation order
10. **Status** -- Current implementation state

All specs include YAML frontmatter with metadata: `slug`, `name`, `vendor`, `category`, `language`, `status`, `version`, `source_repo`.

---

Built by [Ethan Troy](https://ethantroy.dev)
