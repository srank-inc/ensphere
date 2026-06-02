# Agent Workflow

Ensphere includes AI-agent methodology files for authorized assessments. The CLI owns deterministic execution and measurement. The agent or human analyst owns interpretation, classification, confidence, exploitability, chaining, and report writing.

## Install Skill Files

```bash
./install-skills.sh
```

From a target project, invoke the installed skill:

```text
Claude Code: /ensphere
Codex: ensphere
```

## Assessment Sessions

Run one session at a time and clear context between sessions. Progress persists in `ensphere-pentest/`.

| Session | Category | Focus |
|---------|----------|-------|
| 01 | Recon | Endpoints, roles, tech stack, attack surface |
| 02 | Injection | SQLi, command injection, LFI/RFI, SSTI, traversal, deserialization |
| 03 | Auth | Sessions, credentials, OAuth, MFA, token handling |
| 04 | Authz | IDOR, privilege escalation, role confusion, workflow bypass |
| 05 | XSS | Reflected, stored, DOM-based execution paths |
| 06 | SSRF | Classic, blind, semi-blind, stored SSRF, redirect chains |
| 07 | Cloud | AWS, Azure, GCP, Kubernetes, IaC, scanner ingestion |
| 09 | API | Rate limiting, property authz, mass assignment, pagination, webhooks |
| 08 | Report | Executive and technical report from evidence-backed findings |

First run creates `ensphere-pentest/config.md` with target URL, credentials, authorization boundaries, and scope. The template lives at [../templates/config.md](../templates/config.md).

## Evidence Standards

Automated CLI writes and manual evidence logs assign `EVID-XXX` IDs at write time. Evidence rows are factual records only. The `result` field must be one of:

```text
baseline, probe, payload, control, callback, manual_note
```

Do not put conclusions such as confirmed, potential, safe, high confidence, exploitability, or severity in evidence rows. Put those in session notes and reports, with evidence IDs cited.

See [../skills/shared/evidence-standards.md](../skills/shared/evidence-standards.md).

## Browser Testing

Browser-based verification should use Playwright MCP when available. For Claude Code:

```bash
claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest
```

The browser step is used for workflows that need user interaction, DOM execution proof, screenshots, or session-aware navigation.

## Dogfood Runs

Dogfood runbooks are in [dogfood/README.md](dogfood/README.md). Sample reports must be regenerated only from verified local evidence files and saved transcripts.
