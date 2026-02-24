# Session 03: Authentication

Analyze and exploit authentication mechanisms — identity verification and session management.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Token/session bypass | Tier 1 | `ensphere verify auth` |
| Custom auth flows, brute force, rate limiting | Tier 2 | `curl` via Bash |
| OAuth/SSO redirect flows | Tier 3 | Playwright MCP (only when browser state required) |

**Decision flow:**
1. Use `ensphere verify auth --technique <type>` for automated bypass verification (no_token, expired_token, alg_none, method_override)
2. Use `curl` for custom auth flows, brute force attempts, and rate limiting checks
3. Use Playwright ONLY for OAuth/SSO redirect flows requiring browser state:
   - `browser_navigate` to SSO login page
   - `browser_click` on SSO provider button
   - Observe redirect chain via `browser_network_requests`
   - Capture tokens from URL fragments or cookies
   - `browser_evaluate` to extract `document.cookie` or `localStorage`
   - `browser_take_screenshot` for evidence
   - Test token replay and state parameter manipulation

## Black-Box Path

When assessment mode is BLACK_BOX, the existing Phase A 9-point checklist still applies — most items are already behavioral (checking HTTP headers, cookie flags, login responses). Make these adjustments:

**Items to skip in BLACK_BOX mode:**
- Checklist item 6: "No default credentials in code, fixtures, or bootstrap scripts" — cannot check without source code. Instead: test common default credentials (admin/admin, admin/password, test/test) against login.
- Checklist item 6: "Passwords stored with one-way hashing" — cannot verify without source code. Skip this check.

**Items to add in BLACK_BOX mode:**

### BB-Additional: JWT Deep Analysis
If auth uses JWT (detected in Session 01 Technology Profile):
- Base64-decode header and payload (no secret needed)
- Check `alg` claim: should be RS256/ES256, not HS256 with weak secret or `none`
- Check `exp` claim: should have expiration
- Check for sensitive data in claims (passwords, full user records = vulnerability)
- Check `kid` header (potential injection vector for path traversal or SQLi)
- Use `ensphere verify auth --technique alg_none --url URL --token TOKEN --in-scope SCOPE`

### BB-Additional: Session Token Entropy Analysis
- Collect 10+ session tokens from repeated logins
- Analyze: length, character set, sequential patterns, common prefixes
- Tokens should be ≥128 bits of entropy, no predictable patterns

### BB-Additional: Login Enumeration Timing
- Send login with valid-username + wrong-password → record response time
- Send login with invalid-username + wrong-password → record response time
- Timing difference >100ms suggests different code paths = user enumeration possible

After these adjustments, proceed with the standard Phase A checklist and Phase B (Exploitation).

## Phase A: Analysis (9-Point Checklist)

Read `pentest/01-recon/report.md` sections 3 (Auth & Session) and 4 (API Endpoints).
Create a task for each checklist item.

### 1. Transport & Caching
- All auth endpoints enforce HTTPS (no HTTP fallbacks)
- HSTS header present at edge
- Auth responses include `Cache-Control: no-store` / `Pragma: no-cache`
→ If failed: `transport_exposure` → credential/session theft

### 2. Rate Limiting & Abuse Defenses
- Login, signup, reset, token endpoints have per-IP and/or per-account rate limits
- Repeated failures trigger lockout, backoff, or CAPTCHA
- Monitoring/alerting exists for failed-login spikes
→ If failed: `abuse_defenses_missing` → brute_force / credential_stuffing / password_spraying

### 3. Session Cookies
- `HttpOnly` and `Secure` flags set on all session cookies
- `SameSite` set to Lax or Strict
- Session ID rotated after successful login (no reuse)
- Logout invalidates server-side session
- Idle timeout and absolute session timeout configured
- Session IDs not in URLs
→ If failed: `session_cookie_misconfig` → session_hijacking / session_fixation

### 4. Token Properties
- Custom tokens use cryptographic randomness (not sequential/guessable)
- Tokens sent only over HTTPS, never logged
- Explicit expiration (TTL), invalidated on logout
→ If failed: `token_management_issue` → token_replay / offline_guessing

### 5. Session Fixation
- Pre-login vs post-login session IDs differ (new ID on auth success)
→ If failed: `login_flow_logic` → session_fixation

### 6. Password & Account Policy
- No default credentials in code, fixtures, or bootstrap scripts
- Strong password policy enforced server-side (if applicable)
- Passwords stored with one-way hashing (not reversible encryption)
- MFA available/enforced where required
→ If failed: `weak_credentials` → credential_stuffing / password_spraying

### 7. Login/Signup Responses
- Error messages are generic (no user-enumeration hints like "user not found" vs "wrong password")
- Auth state not reflected in URLs/redirects that could be abused
→ If failed: `login_flow_logic` → account_enumeration / open_redirect_chain

### 8. Recovery & Logout
- Password reset uses single-use, short-TTL tokens
- Reset attempts rate-limited
- Reset responses don't enumerate users
- Logout invalidates server-side session and clears client cookies
→ If failed: `reset_recovery_flaw` → reset_token_guessing / takeover

### 9. SSO/OAuth (if applicable)
- `state` parameter validated (CSRF protection)
- `nonce` parameter validated (replay protection)
- Exact redirect URI allowlists (no wildcards)
- IdP tokens: signature verified, algorithms pinned, `iss`/`aud`/`exp` validated
- Public clients use PKCE
- **nOAuth check**: User identification uses immutable `sub` claim, NOT mutable attributes (`email`, `preferred_username`, `name`). Using mutable attributes allows attackers to impersonate users via their own OAuth tenant.
→ If failed: `login_flow_logic` / `token_management_issue` → oauth_code_interception / noauth_attribute_hijack

## Phase B: Exploitation

For each vulnerability found in Phase A, attempt active exploitation:

### Stage 1: Active Attack
Execute the suggested attack pattern — not just confirmation, but actual exploitation:
- **No rate limiting** → attempt brute force/enumeration with many requests
- **Weak password policy** → create weak accounts AND try accessing other accounts
- **User enumeration** → build list of valid users for subsequent attacks
- **Missing HttpOnly** → attempt cookie theft via XSS vector
- **Session fixation** → set session before auth, verify it persists after login

### Stage 2: Impact Demonstration
Prove you have become another user or bypassed authentication:
- Visit protected page (`/profile`, `/dashboard`) as the victim user
- Evidence: content of page proving assumed identity
- Chain exploits: use enumerated users in password attacks

### Attack Techniques
- **Session hijacking**: inject stolen cookie via Playwright `addCookies()` or `curl -b`
- **Credential stuffing**: POST to login with known weak/common passwords
- **JWT `alg:none`**: decode JWT, change `alg` to `none`, modify payload, re-encode without signature
- **Password reset manipulation**: request reset for victim, intercept and redirect token

## Report Format

Write to `pentest/03-auth/report.md`:
- Successfully Exploited (with full reproduction steps)
- Secure by Design: Validated Components (table of safe checks)
