# Agent Workflow

Ensphere provides an evidence-first, agent-guided assessment workflow for authorized targets. The CLI owns deterministic measurement, workspace gates, and evidence integrity. The analyst owns interpretation, classification, confidence, severity, priority, impact, and report writing. Session 10 is disabled by default and requires exact human authorization whether its executor is a human or AI agent.

## Install Skill Files

```bash
./install-skills.sh
```

From a target project, invoke the installed skill or agent entry point:

```text
Claude Code: /ensphere
Codex: ensphere
```

To create the standard workspace and handoff files first:

```bash
ensphere run init --target https://staging.example.com --source yes --target-type api_backend --in-scope staging.example.com
ensphere run plan
ensphere run next
ensphere run report
# Optional after Session 09 is DONE and impact validation is explicitly enabled:
ensphere run validate-impact --finding VULN-001
# Optional after the exact strict plan SHA-256 is human-authorized:
ensphere run impact-ready --finding VULN-001 --authorization 10-impact-validation/authorizations/VULN-001-agent.yaml
# Optional after Session 10 writes impact-validation outcomes:
ensphere run final
```

The runner writes `ensphere-pentest/next-action.md` and
`ensphere-pentest/agent-prompt.md`. `run plan` writes or validates
`assessment-plan.yaml` and keeps the Session 01.5 mirror in sync; the generated
plan is a deterministic draft from config until Session 01.5 updates it from
Recon evidence or `01-recon/target-profile.yaml`. `run report` writes the
Session 09 readiness gate and blocks on missing plans, incomplete sessions,
missing session reports, invalid evidence chains, invalid finding registry
contracts, or unsafe citation paths. `run validate-impact` requires Session 09 to be
marked `DONE`, validates selected IDs against the Session 09 finding registry,
and writes `10-impact-validation/selected-findings.yaml` with authorization,
executor, environment, plan, and cleanup gates. The analyst writes each exact
plan and pauses; the human then authorizes a human or AI executor. `run final` derives the Session
11 registry from Session 10 outcomes without mutating Session 09 artifacts or
base statuses; run it only after
`10-impact-validation/impact-validation-outcomes.yaml` exists and every selected finding has an
outcome with authorization evidence, executor provenance, and cleanup status.
The runner command itself prepares and validates workspace contracts; it does
not autonomously start Session 10 actions.

## Assessment Sessions

Run one session at a time and clear context between sessions. Progress persists in `ensphere-pentest/`. Session 01.5 creates the adaptive plan that decides which later sessions run, skip, block, or operate with limited coverage.

| Session | Category | Focus |
|---------|----------|-------|
| 01 | Recon | Endpoints, roles, tech stack, attack surface |
| 01.5 | Session Plan | Target classification, coverage labels, session decisions |
| 02 | Injection | SQLi, command injection, LFI/RFI, SSTI, traversal, deserialization |
| 03 | Auth | Sessions, credentials, OAuth, MFA, token handling |
| 04 | Authz | IDOR, privilege escalation, role confusion, workflow bypass |
| 05 | XSS | Reflected, stored, DOM-based execution paths |
| 06 | SSRF | Classic, blind, semi-blind, stored SSRF, redirect chains |
| 07 | Cloud | AWS, Azure, GCP, Kubernetes, IaC, Prowler/Trivy ingestion |
| 08 | API | Rate limiting, property authz, mass assignment, pagination, webhooks |
| 09 | Assessment Report | Evidence-backed assessment report and finding registry |
| 10 | Human-Authorized Impact Validation | Opt-in execution by a human or AI for explicitly selected findings and an exactly authorized plan |
| 11 | Validation-Aware Report | Optional derived report with base finding statuses preserved |

First run creates `ensphere-pentest/config.md` with target URL, credentials, authorization boundaries, and scope. The template lives at [../templates/config.md](../templates/config.md).

The adaptive plan lives at `ensphere-pentest/assessment-plan.yaml` and uses the shared decision values, coverage labels, evidence categories, and report honesty rules in [../skills/shared/workflow-contract.md](../skills/shared/workflow-contract.md). `ensphere run status` and `ensphere run next` read this plan and include the relevant next-session decision in their JSON output and handoff files.

Session 10 appears in `run next` only when Session 09 is marked `DONE`,
impact validation is explicitly enabled, and `10-impact-validation/selected-findings.yaml`
has been produced by `run validate-impact` with IDs that resolve against a valid
`09-report/finding-registry.yaml`. `assessment-plan.yaml` may propose selected
findings, but the runner requires the explicit Session 10 handoff before
advancing. Every outcome must identify the authorized executor, cite the
separate authorization record whose SHA-256 matches the plan, account for the
performed actions and elapsed time, and cite cleanup evidence. Even after
Session 10 is `DONE`, `run next` stops; Session 11 begins only when the human
explicitly invokes `run final`.

## Evidence Standards

Automated CLI writes and manual evidence logs assign `EVID-XXX` IDs at write time. Evidence rows are factual records only. The `result` field must be one of:

```text
baseline, probe, payload, control, callback, manual_note
```

Do not put conclusions such as confirmed, potential, safe, high confidence, exploitability, or severity in evidence rows. Put those in session notes and reports, with evidence IDs cited.

See [../skills/shared/evidence-standards.md](../skills/shared/evidence-standards.md).

Finding status, confidence, evidence strength, severity, priority, and impact belong in the finding registry and reports, not CLI evidence rows. Use base statuses `confirmed`, `likely`, `informational`, `not_supported`, and `not_tested`. Imported scanner severity is source-provided until corroborated by Ensphere measurements or manual proof. Planned external importers should follow the same source-provided lead model.

## Browser Testing

Browser-based verification should use Playwright MCP when available. For Claude Code:

```bash
claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest
```

The browser step is used for workflows that need user interaction, DOM execution proof, screenshots, or session-aware navigation.

## Benchmark Runs

Reports stay local until they are backed by a verified workspace; the
repository does not ship synthetic sample reports.
