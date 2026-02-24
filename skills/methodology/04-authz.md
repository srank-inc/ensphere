# Session 04: Authorization

Analyze and exploit authorization mechanisms — access control, privilege escalation, IDOR.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Horizontal IDOR verification | Tier 1 | `ensphere verify idor` |
| Supabase RLS testing | Tier 1 | `ensphere verify rls` |
| Vertical privilege escalation, workflow bypass | Tier 2 | `curl` via Bash |
| UI-driven role switching | Tier 3 | Playwright MCP (only for UI role changes) |

**Decision flow:**
1. Use `ensphere verify idor` for automated horizontal IDOR verification with evidence logging
2. Use `ensphere verify rls` for Supabase-specific tenant isolation testing
3. Use `curl` for vertical privilege escalation (admin endpoint access) and workflow bypass testing
4. Use Playwright only when role switching requires UI interaction (e.g., admin panel toggle)

## Black-Box Path

When assessment mode is BLACK_BOX, replace Phase A (code review) with the following. Phase B (Exploitation) still applies after this.

### Phase A-BB: Access Control Matrix (replaces code review)

Read `pentest/01-recon/report.md` sections 4 (API Endpoints), 7 (Role & Privilege Architecture), and 8 (Authorization Vulnerability Candidates).
Read the Technology Profile from `pentest/progress.md`.

**Step 1 — Session Setup**: Create separate authenticated sessions for each available role:
- **User A** (standard user) — login via curl, save token/cookies
- **User B** (different standard user) — login via curl, save token/cookies
- **Admin** (if admin credentials available in `pentest/config.md`) — login, save token/cookies
- **Unauthenticated** — no token/cookies

For Playwright-based testing, use separate browser contexts per role.

Capture object IDs owned by each user (user IDs, resource IDs, org IDs) from their respective API responses.

**Step 2 — Build Access Control Matrix**: For EVERY endpoint from the recon report, test access with each session. Record status code and whether the response contains authorized data.

| Endpoint | Method | User A (owner) | User B (other) | Admin | Unauth | Expected | Verdict |
|----------|--------|----------------|----------------|-------|--------|----------|---------|
| GET /api/items/123 | GET | 200 ✓ | 200 ✗ | 200 ✓ | 401 | A-only | **IDOR** |
| DELETE /api/items/123 | DELETE | 200 | 200 | 200 | 401 | A-only | **IDOR** |
| GET /api/admin/users | GET | 403 | 403 | 200 | 401 | admin-only | Secure |

Test ALL HTTP methods (GET, POST, PUT, PATCH, DELETE) on each endpoint — an endpoint may allow GET but also respond to DELETE without authorization.

**Step 3 — Horizontal Authorization (IDOR)**:
For each endpoint with object IDs:
- Swap IDs between User A and User B
- Test sequential ID enumeration (for numeric IDs: try id-1, id+1, id+2)
- Test UUID harvesting: collect UUIDs from User A's list responses, use them in User B's detail requests
- Test batch/list endpoints: does `/api/items` return items from ALL users or only the authenticated user?
- Use `ensphere verify idor --url URL --id VICTIM_ID --token ATTACKER_TOKEN --in-scope SCOPE`

**Step 4 — Vertical Authorization (Privilege Escalation)**:
- Access admin-only endpoints with unprivileged tokens (from the matrix)
- Test role manipulation in profile update: `PUT /api/profile {"role":"admin"}`, `{"is_admin":true}`, `{"permissions":["admin"]}`
- Test admin API paths: `/admin/*`, `/api/admin/*`, `/internal/*`, `/management/*`
- If JWT-based auth: modify role claims in JWT payload and re-encode (without valid signature — test if signature is verified)

**Step 5 — Workflow/Context Authorization**:
For multi-step workflows discovered in recon:
- Map the intended sequence (e.g., create order → add items → checkout → pay)
- Test step skipping: call checkout directly without creating order
- Test reverse ordering: call pay before checkout
- Test state manipulation: modify status parameters (e.g., `{"status":"approved"}` on a pending item)
- Test forced state transitions: directly set final state without processing

After Phase A-BB, proceed to **Phase B: Exploitation** (same as white-box path).

## Phase A: Analysis

Read `pentest/01-recon/report.md` section 8 (Authorization Vulnerability Candidates).
Create a task for each candidate endpoint organized by type.

### 1. Horizontal Authorization (Ownership/IDOR)

For each item in recon section 8.1:
1. Start at the endpoint
2. Trace backward through code until you find either:
   - A **sufficient guard** (session auth + ownership binding + tenant validation + runs before side effect + dominates all paths), OR
   - A **side effect** reached without sufficient guard
3. Side effects: DB read/write of user objects, file changes, cross-tenant data access, metadata exposure
4. **Verdict**: guarded (guard dominates sink) or vulnerable (side effect before guard)

### 2. Vertical Authorization (Role Escalation)

For each item in recon section 8.2:
1. Start at the endpoint
2. Trace backward until you find either:
   - A **sufficient role/capability guard** (explicit role check + runs before side effect + dominates all paths), OR
   - A **privileged side effect** without such guard
3. Side effects: user/role management, system config, DB export/import, global state changes
4. **Verdict**: guarded or vulnerable

### 3. Context/Workflow Authorization (State Bypass)

For each item in recon section 8.3:
1. Start at the workflow step endpoint
2. Walk forward through intended flow
3. At each step, verify later actions validate prior state (status flags, stage tokens, nonces)
4. Guard must run before applying state change
5. **Verdict**: guarded (all steps validate prior state) or vulnerable (side effect without prior state check)

### Proof Rules
- Guards appearing AFTER the side effect do not count
- UI-only checks (hidden buttons, disabled forms) do not count as guards
- Authentication ≠ authorization (being logged in ≠ ownership check exists)
- Don't trust framework defaults without explicit configuration evidence

## Phase B: Exploitation

For each vulnerable endpoint from Phase A:

### Horizontal Attacks
- **Identifier manipulation**: change `user_id`, `order_id`, `file_id` in requests to access other users' resources
- **Sequential enumeration**: iterate through predictable ID patterns
- **Tenant boundary crossing**: manipulate `org_id`, `company_id`, `tenant_id`
- **Reference swapping**: replace your reference tokens with other users'

### Vertical Attacks
- **Direct access**: hit admin endpoints (`/admin/*`, `/api/admin/*`) with lower-privilege session
- **Role manipulation**: modify role-related parameters in requests
- **Header injection**: add/modify authorization-related headers
- **Permission field editing**: modify permission fields in update requests

### Context/Workflow Attacks
- **Step skipping**: execute later steps without completing prerequisites
- **State manipulation**: modify state parameters to bypass validation
- **Out-of-order execution**: execute workflow steps in wrong sequence
- **Forced state transitions**: directly set final states without processing

### Stage 1: Confirmation
Execute the `minimal_witness` from the analysis — prove access control bypass is real.

### Stage 2: Impact Demonstration
Access protected resources, modify unauthorized data, or demonstrate elevated privileges.
Evidence: the unauthorized data or functionality accessed.

## Report Format

Write to `pentest/04-authz/report.md`:
- Successfully Exploited (with type: Horizontal/Vertical/Context, full reproduction steps)
- Vectors Confirmed Secure (table: Endpoint | Guard Location | Defense | Verdict)
