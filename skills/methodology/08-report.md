# Session 08: Executive Report

Synthesize all category reports into a final security assessment.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| CVSS scoring | Tier 1 | `ensphere cvss` |
| Compliance mapping | Tier 1 | `ensphere compliance` |
| Evidence lookup | Tier 1 | `ensphere evidence query` |
| Not applicable | Tier 2 | No HTTP probing during reporting |
| Not applicable | Tier 3 | No browser testing during reporting |

## Process

1. Read all session reports:
   - `ensphere-pentest/01-recon/report.md`
   - `ensphere-pentest/02-injection/report.md`
   - `ensphere-pentest/03-auth/report.md`
   - `ensphere-pentest/04-authz/report.md`
   - `ensphere-pentest/05-xss/report.md`
   - `ensphere-pentest/06-ssrf/report.md`
   - `ensphere-pentest/07-cloud/report.md`
   - `ensphere-pentest/09-api/report.md`

2. Read external scan results (if they exist):
   - `ensphere-pentest/01-recon/nmap.txt`
   - `ensphere-pentest/01-recon/subdomains.txt`
   - `ensphere-pentest/01-recon/httpx.txt`

3. Read `ensphere-pentest/config.md` for target details and authorization statement.

4. Read all evidence files from sessions 02-07 and 09:
   - `ensphere-pentest/02-injection/evidence.jsonl`
   - `ensphere-pentest/03-auth/evidence.jsonl`
   - `ensphere-pentest/04-authz/evidence.jsonl`
   - `ensphere-pentest/05-xss/evidence.jsonl`
   - `ensphere-pentest/06-ssrf/evidence.jsonl`
   - `ensphere-pentest/07-cloud/evidence.jsonl`
   - `ensphere-pentest/09-api/evidence.jsonl`
   Use `ensphere evidence query --file <path>` to read entries from each.

## Report Template

Write to `ensphere-pentest/08-report/report.md`:

```markdown
# Security Assessment Report

## Authorization & Attestation

[Copy the Authorization section from ensphere-pentest/config.md verbatim here]

**Assessor**: Ensphere Autonomous Security Assessment
**Report Date**: [current date]
**Ensphere CLI Version**: [output of ensphere --version or "latest"]
**Assessment Mode**: WHITE_BOX | BLACK_BOX

## Executive Summary
- **Target**: [URL from config]
- **Assessment Date**: [current date]
- **Scope**: Authentication, authorization, injection, XSS, SSRF, cloud security

## Assessment Mode Notes (Black-Box Only)

Include this section ONLY when Assessment Mode is BLACK_BOX.

### Coverage Limitations
- No source code review — all detection is behavioral (HTTP request/response analysis)
- Technology identification is inference-based (headers, cookies, error pages, HTML signatures)
- No callback server available — blind SSRF and out-of-band SQL injection cannot be definitively confirmed
- Remediation recommendations describe fix classes (e.g., "use parameterized queries") but cannot reference specific file:line locations
- Attack surface limited to endpoints discovered via crawling, JS analysis, API documentation, and directory probing — undiscoverable internal endpoints may exist

### Confidence Adjustments
- **HIGH confidence**: Concrete evidence obtained — data extracted, JavaScript executed, unauthorized access achieved, SQL error with injected content
- **MEDIUM confidence**: Behavioral signals — timing differences, response length changes, error message analysis, indirect indicators
- **LOW confidence**: Findings that would require out-of-band verification (callback server) to confirm definitively

### Technology Profile
[Copy the Technology Profile from ensphere-pentest/progress.md here]

[2-3 paragraph overview: overall security posture, most critical findings, key recommendations]

## Vulnerability Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Injection | N | N | N | N | N |
| Authentication | N | N | N | N | N |
| Authorization | N | N | N | N | N |
| XSS | N | N | N | N | N |
| SSRF | N | N | N | N | N |
| Cloud | N | N | N | N | N |
| **Total** | **N** | **N** | **N** | **N** | **N** |

## Remediation Timeline

| Severity | Deadline | Finding Count |
|----------|----------|---------------|
| Critical | 24 hours | N |
| High | 7 days | N |
| Medium | 30 days | N |
| Low | 90 days | N |

## Critical Findings

[For each EXPLOITED and POTENTIAL vulnerability across all categories, ordered by CVSS score descending:]

### VULN-{NNN}: [Title]
- **Category**: [Injection/Auth/Authz/XSS/SSRF/Cloud]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS v4.0**: [score] [severity] `[vector string]`
- **CVSS v3.1**: [score] [severity] `[vector string]`
- **Endpoint**: [affected endpoint]
- **Impact**: [business impact]
- **Compliance Impact**:
  - OWASP: [control IDs]
  - PCI-DSS: [control IDs]
  - SOC 2: [control IDs]
  - ISO 27001: [control IDs]
- **Evidence**: [EVID-XXX references]
- **Screenshots**: [screenshot paths if applicable]
- **Reproduction**: [brief steps — full details in category report]
- **Remediation**: [specific fix recommendation]
- **Deadline**: [24h/7d/30d/90d based on severity]

## Network Reconnaissance
[Security-relevant findings from nmap, subfinder, httpx — exposed services, misconfigurations, expanded attack surface]

## Potential Findings
[Vulnerabilities blocked by external constraints, not security controls]

## Assessment Coverage
[Summary of what was tested, any blind spots or constraints noted in category reports]

### Mode-Specific Coverage Notes (Black-Box Only)
Include when Assessment Mode is BLACK_BOX:
- **Discovery methodology**: crawl, JS analysis, API schema, directory probing, GraphQL introspection
- **Total endpoints discovered**: [N]
- **Input vectors identified**: [N]
- **Injection testing approach**: behavioral error-character probing + technology-aware payload selection
- **Authorization testing approach**: multi-session access control matrix ([N] endpoints × [N] roles)
- **Known blind spots**: endpoints not discoverable without source code, internal-only routes, undocumented APIs

## Appendix A: Evidence Index

| Evidence ID | Session | Probe Type | Technique | URL | Result Stage | Finding Ref |
|-------------|---------|------------|-----------|-----|--------------|-------------|
| EVID-001 | 02 | sqli | blind_time | ... | payload | VULN-001 |
| ... | ... | ... | ... | ... | ... | ... |

## Appendix B: Compliance Summary

### OWASP Top 10 2025
| Control ID | Control Name | Status | Related Findings |
|------------|-------------|--------|-----------------|
| A01 | Broken Access Control | PASS/FAIL/NOT TESTED | VULN-IDs |
| A02 | Security Misconfiguration | PASS/FAIL/NOT TESTED | VULN-IDs |
| A03 | Software Supply Chain Failures | PASS/FAIL/NOT TESTED | VULN-IDs |
| A04 | Cryptographic Failures | PASS/FAIL/NOT TESTED | VULN-IDs |
| A05 | Injection | PASS/FAIL/NOT TESTED | VULN-IDs |
| A06 | Insecure Design | PASS/FAIL/NOT TESTED | VULN-IDs |
| A07 | Authentication Failures | PASS/FAIL/NOT TESTED | VULN-IDs |
| A08 | Software or Data Integrity Failures | PASS/FAIL/NOT TESTED | VULN-IDs |
| A09 | Security Logging and Alerting Failures | PASS/FAIL/NOT TESTED | VULN-IDs |
| A10 | Mishandling of Exceptional Conditions | PASS/FAIL/NOT TESTED | VULN-IDs |

### PCI-DSS v4.0.1
| Control ID | Control Name | Status | Related Findings |
|------------|-------------|--------|-----------------|
| 6.2.4 | Software Engineering Techniques | PASS/FAIL/NOT TESTED | VULN-IDs |
| 7.2.1 | Access Control Model | PASS/FAIL/NOT TESTED | VULN-IDs |
| 7.2.2 | Role-Based Access Assignment | PASS/FAIL/NOT TESTED | VULN-IDs |
| 8.2.1 | Unique User Identification | PASS/FAIL/NOT TESTED | VULN-IDs |
| 8.3.1 | Strong Authentication | PASS/FAIL/NOT TESTED | VULN-IDs |

### SOC 2
| Control ID | Control Name | Status | Related Findings |
|------------|-------------|--------|-----------------|
| CC6.1 | Logical Access Security | PASS/FAIL/NOT TESTED | VULN-IDs |
| CC6.3 | Role-Based Access | PASS/FAIL/NOT TESTED | VULN-IDs |
| CC6.6 | System Boundaries | PASS/FAIL/NOT TESTED | VULN-IDs |
| CC7.1 | Monitoring & Detection | PASS/FAIL/NOT TESTED | VULN-IDs |
| CC7.2 | Anomaly Detection | PASS/FAIL/NOT TESTED | VULN-IDs |

### ISO 27001
| Control ID | Control Name | Status | Related Findings |
|------------|-------------|--------|-----------------|
| A.8.26 | Application Security | PASS/FAIL/NOT TESTED | VULN-IDs |
| A.8.28 | Secure Coding | PASS/FAIL/NOT TESTED | VULN-IDs |
| A.8.12 | Data Leakage Prevention | PASS/FAIL/NOT TESTED | VULN-IDs |
| A.8.5 | Secure Authentication | PASS/FAIL/NOT TESTED | VULN-IDs |

## Appendix C: Tool Versions
- Ensphere CLI: [version]
- CVSS Calculator: v3.1 + v4.0
- Skill files: [date of last methodology update]
```

## CVSS Scoring

For each finding, compute BOTH CVSS scores:

```bash
# CVSS v4.0 (primary)
ensphere cvss --version 4.0 --av N --ac L --at N --pr N --ui N --vc H --vi L --va N --sc H --si L --sa N

# CVSS v3.1 (secondary, for backward compatibility)
ensphere cvss --version 3.1 --av N --ac L --pr N --ui N --s C --c H --i L --a N
```

Include both in each finding for maximum compatibility with compliance frameworks.

## Compliance Impact

For each finding, look up compliance mappings:

```bash
ensphere compliance sqli
ensphere compliance xss
```

Include in each finding the affected framework controls (OWASP Top 10, PCI-DSS, SOC 2, ISO 27001).

## Evidence Cross-Referencing

1. Read all `evidence.jsonl` files from sessions 02-07 and 09 using `ensphere evidence query --file <path>`
2. Preserve evidence IDs assigned by `ensphere evidence log` or verify commands at write time
3. Cross-reference each relevant evidence entry with its corresponding VULN-{NNN} finding
4. Populate Appendix A with all evidence entries using factual result stages (`baseline`, `probe`, `payload`, `control`, `callback`, `manual_note`)

## Rules
- Sessions marked SKIPPED in progress.md still have a report.md — read it for the skip reason and note it in Assessment Coverage
- Only include EXPLOITED and POTENTIAL findings — not false positives
- VULN-ID assignment: sequential, ordered by CVSS score descending
- Order by severity (Critical → High → Medium → Low)
- Remediation timelines: Critical→24h, High→7d, Medium→30d, Low→90d
- Keep reproduction steps brief — reference category reports for full details
- Audience: technical leadership (CTOs, CISOs) — precise but concise
- Do not include technology stack details (they know their own stack)
- Focus on business impact and actionable findings
- Always include both CVSS v4.0 and v3.1 scores per finding
- Always include compliance impact per finding
- Compliance status: FAIL if any EXPLOITED finding affects control, PASS only if tested and clean, NOT TESTED if outside assessment scope
- Copy Authorization section from config.md verbatim into report header
- When Assessment Mode is BLACK_BOX, include the "Assessment Mode Notes" section after Executive Summary
- Behavioral-only findings (timing, response length) should be MEDIUM confidence, not HIGH
- Coverage limitations must be honestly documented — black-box cannot guarantee completeness
- Include Technology Profile in the report for context on payload selection decisions
