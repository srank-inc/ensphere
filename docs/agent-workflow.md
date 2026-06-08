# Agent Workflow

Ensphere provides an evidence-first autonomous assessment workflow for authorized targets. The CLI owns deterministic execution, measurement, workspace gates, and evidence integrity. The AI agent or human analyst owns interpretation, classification, confidence, exploitability, chaining, and report writing.

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
# Optional after Session 09 is DONE and exploitation is explicitly enabled:
ensphere run exploit --finding VULN-001
# Optional after Session 10 writes exploit outcomes:
ensphere run final
```

The runner writes `ensphere-pentest/next-action.md` and
`ensphere-pentest/agent-prompt.md`. `run plan` writes or validates
`assessment-plan.yaml` and keeps the Session 01.5 mirror in sync; the generated
plan is a deterministic draft from config until Session 01.5 updates it from
Recon evidence or `01-recon/target-profile.yaml`. `run report` writes the
Session 09 readiness gate and blocks on missing plans, incomplete sessions,
missing session reports, invalid evidence chains, invalid finding registry
contracts, or unsafe citation paths. `run exploit` requires Session 09 to be
marked `DONE`, validates selected IDs against the Session 09 finding registry,
and writes `10-exploitation/selected-findings.yaml` with the exploit policy and
required handoff gates. `run final` derives the Session 11 finding registry from
Session 10 outcomes without mutating Session 09 artifacts; run it only after
`10-exploitation/exploit-outcomes.yaml` exists and every selected finding has an
outcome with cleanup status. The runner does not run the AI or execute exploit
attempts.

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
| 10 | Optional Exploitation | Opt-in prove-by-exploitation for selected findings |
| 11 | Final Report | Exploit-verified final report after Session 10 |

First run creates `ensphere-pentest/config.md` with target URL, credentials, authorization boundaries, and scope. The template lives at [../templates/config.md](../templates/config.md).

The adaptive plan lives at `ensphere-pentest/assessment-plan.yaml` and uses the shared decision values, coverage labels, evidence categories, and report honesty rules in [../skills/shared/workflow-contract.md](../skills/shared/workflow-contract.md). `ensphere run status` and `ensphere run next` read this plan and include the relevant next-session decision in their JSON output and handoff files.

Session 10 appears in `run next` only when Session 09 is marked `DONE`,
exploitation is explicitly enabled, and `10-exploitation/selected-findings.yaml`
has been produced by `run exploit` with IDs that resolve against a valid
`09-report/finding-registry.yaml`. `assessment-plan.yaml` may propose selected
findings, but the runner requires the explicit Session 10 handoff before
advancing. Session 11 appears only after Session 10 is marked `DONE`.

## Evidence Standards

Automated CLI writes and manual evidence logs assign `EVID-XXX` IDs at write time. Evidence rows are factual records only. The `result` field must be one of:

```text
baseline, probe, payload, control, callback, manual_note
```

Do not put conclusions such as confirmed, potential, safe, high confidence, exploitability, or severity in evidence rows. Put those in session notes and reports, with evidence IDs cited.

See [../skills/shared/evidence-standards.md](../skills/shared/evidence-standards.md).

Finding status, confidence, severity, exploitability, and business impact belong in the finding registry and reports, not CLI evidence rows. Imported scanner severity is source-provided until corroborated by Ensphere measurements or manual proof. Planned external importers such as Nmap, Nuclei, SARIF, ZAP/Burp, and SQLMap should follow the same source-provided lead model.

## Browser Testing

Browser-based verification should use Playwright MCP when available. For Claude Code:

```bash
claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest
```

The browser step is used for workflows that need user interaction, DOM execution proof, screenshots, or session-aware navigation.

## Dogfood Runs

Dogfood runbooks are in [dogfood/README.md](dogfood/README.md). Sample reports must be regenerated only from verified local evidence files and saved transcripts.
