# Session 05: Cross-Site Scripting (XSS)

Covers: Reflected, Stored, and DOM-based XSS.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Reflection check | Tier 1 | `ensphere verify xss` |
| Initial payload testing | Tier 2 | `curl` via Bash |
| DOM execution proof (L3 evidence) | Tier 3 | Playwright MCP (**REQUIRED** for confirmed XSS) |

**Decision flow:**
1. Use `ensphere verify xss` to check if payloads are reflected unencoded
2. Use `curl` for rapid payload iteration and filter bypass testing
3. Use Playwright for DOM execution proof — **required for L3 evidence**:
   - `browser_navigate` to vulnerable page
   - Inject payload via `browser_type` / `browser_fill_form` or URL parameter
   - `browser_evaluate` to verify JS executed: `document.querySelector('#xss-proof') !== null` or `window.__xss_executed === true`
   - `browser_take_screenshot` → save to `ensphere-pentest/05-xss/screenshots/xss-{vuln-id}.png`
   - Record screenshot path and evaluate result in evidence
   - Demonstrate impact: `browser_evaluate → document.cookie`, `localStorage.getItem('token')`, DOM data extraction

**Black-box note:** In BLACK_BOX mode, `ensphere sinks` is not available. Rely on reflection-based detection and JS analysis from Session 01 instead.

## Black-Box Path

When assessment mode is BLACK_BOX, replace Phase A (sink-to-source analysis) with the following reflection-based approach. Phase B (Exploitation) still applies after this.

### Phase A-BB: Reflection-Based XSS Detection (replaces sink-to-source analysis)

Read `ensphere-pentest/01-recon/report.md` sections 5 (Input Vectors) and 9 (XSS Reflection Points) for your target list.
Read the Technology Profile from `ensphere-pentest/progress.md` — framework determines default encoding behavior.

**Step 1 — Systematic Canary Injection**: If not already done during Session 01 recon, inject a unique tracking string (e.g., `ensph3r3canary`) into every input parameter:
- Query parameters (GET)
- Form fields (POST)
- JSON body fields
- HTTP headers (Referer, User-Agent — some apps reflect these)
- Cookie values (some apps display cookie data)

Search each response body for the canary string.

**Step 2 — Context Analysis**: For each reflected canary, examine the surrounding HTML/JS to classify the render context:

| Surrounding Pattern | Context | Breakout Sequence | Example Payload |
|--------------------|---------|-------------------|-----------------|
| `<p>...CANARY...</p>` | HTML_BODY | Direct tag injection | `<script>alert(1)</script>` |
| `<div class="CANARY">` | HTML_ATTRIBUTE | Close attribute + tag | `"><script>alert(1)</script>` |
| `<input value="CANARY">` | HTML_ATTRIBUTE | Close attribute + event | `" onfocus=alert(1) autofocus="` |
| `<a href="CANARY">` | URL_ATTRIBUTE | javascript: protocol | `javascript:alert(1)` |
| `var x = "CANARY"` | JS_STRING | Close string + inject | `";alert(1)//` |
| `var x = 'CANARY'` | JS_STRING | Close string + inject | `';alert(1)//` |
| `/* CANARY */` | JS_COMMENT | Close comment + inject | `*/alert(1)/*` |
| JSON `{"key":"CANARY"}` | JSON_VALUE | Depends on rendering | Test if JSON rendered as HTML |

**Step 3 — Character Filtering Analysis**: For each reflection point, test which characters survive unencoded. Inject each individually:
- `<` → if encoded to `&lt;`, HTML tag injection blocked
- `>` → if encoded to `&gt;`, HTML tag injection blocked
- `"` → if encoded to `&quot;`, attribute breakout blocked
- `'` → if encoded to `&#39;`, JS string breakout blocked
- `/` → needed for closing tags
- `(` and `)` → needed for function calls
- `on` → needed for event handlers (some WAFs block this)

Build a filter profile: "This endpoint HTML-encodes `<>` but passes `"'()` through" → attribute-based XSS possible.

**Step 4 — Context-Aware Payload Selection**: Based on context + filter profile:
- HTML body, `<>` allowed: `ensphere payloads xss --technique reflected --tag script`
- HTML attribute, `"` allowed: `ensphere payloads xss --technique reflected --tag attribute`
- JS string context: `ensphere payloads xss --technique reflected --tag js_string`
- WAF detected: `ensphere payloads xss --tag bypass`
- Use `ensphere verify xss --url URL --param PARAM --payload PAYLOAD --in-scope SCOPE` for each candidate

**Step 5 — DOM XSS Testing**: Using Playwright:
- From Session 01 JS analysis, check for DOM sinks (`innerHTML`, `eval`, `document.write`) that read from URL sources
- Test URL fragment/hash inputs: navigate to `TARGET/page#<img src=x onerror=alert(1)>`
- Test `postMessage` handlers: `browser_evaluate("window.postMessage('<img src=x onerror=alert(1)>','*')")`
- Compare page with JS enabled vs JS disabled (via curl): if input only reflected when JS runs, it's DOM-based

**Step 6 — Stored XSS Testing**: For each write endpoint that accepts user input (profile name, comment, message, etc.):
1. Submit a payload via the write endpoint (e.g., `POST /api/comments {"body":"<script>alert(1)</script>"}`)
2. Navigate to the read endpoint where stored content renders (e.g., `GET /comments` page)
3. Use Playwright for execution proof:
   - `browser_navigate` to the page
   - `browser_evaluate("document.querySelector('script')?.textContent")` to verify injection
   - `browser_take_screenshot` for L3 evidence
   - Save screenshot to `ensphere-pentest/05-xss/screenshots/`

After Phase A-BB, proceed to **Phase B: Exploitation** (same as white-box path).

## Phase A: Sink-to-Source Analysis

Read `ensphere-pentest/01-recon/report.md` section 9 (XSS Sinks).
Create a task for each sink-context pair.

### Sink Catalog

**HTML Body**: innerHTML, outerHTML, document.write(), document.writeln(), insertAdjacentHTML(), createContextualFragment(), jQuery: add/after/append/before/html/prepend/replaceWith/wrap

**HTML Attribute**: Event handlers (onclick, onerror, onmouseover, onload, onfocus), URL attributes (href, src, formaction, action, data), style attribute, srcdoc, general attributes (value, id, class, name)

**JavaScript**: eval(), Function() constructor, setTimeout/setInterval(string), writing into `<script>` tags

**CSS**: element.style properties, writing into `<style>` tags

**URL**: location/window.location, location.href/replace/assign, window.open(), history.pushState/replaceState, URL.createObjectURL(), jQuery selector `$(userInput)` (older versions)

### Backward Taint Analysis

For each sink:
1. **Trace backward** from sink through application logic
2. **Early termination**: if you hit a sanitizer, check:
   - Is it the correct type for THIS render context? (see encoding rules below)
   - Any mutations (concat) between sanitizer and sink?
   - If correct match AND no intermediate mutations → path is SAFE, stop tracing
3. **Path forking**: if variable populated from multiple branches, trace each independently
4. **Database read checkpoint**: if trace reaches a DB read without valid sanitizer → **Stored XSS** (assume DB data is untrusted)
5. **Source identification**:
   - Terminates at DB read → **Stored XSS**
   - Terminates at URL param/form body/header → **Reflected XSS**
   - Entire path in client-side JS (e.g., location.hash → innerHTML) → **DOM-based XSS**

### Encoding Context Rules

| Render Context | Required Encoding |
|---------------|-------------------|
| HTML_BODY | HTML entity encoding (`<` → `&lt;`) |
| HTML_ATTRIBUTE | Attribute encoding |
| JAVASCRIPT_STRING | JavaScript string escaping (`'` → `\'`) |
| URL_PARAM | URL encoding |
| CSS_VALUE | CSS hex encoding |

Mismatch = vulnerable. HTML encoding in a JS string context does NOT prevent XSS.

## Phase B: Exploitation

For each vulnerable path, craft context-aware payloads:

### Payload Strategy
1. Start with the `witness_payload` from analysis
2. Craft payloads matching source format constraints and sink render context
3. Test via curl (reflected) or Playwright (stored/DOM)
4. Iterate based on how payload transforms at each node

### Bypass Techniques (when blocked)
- Alternative tags: `<img>`, `<svg>`, `<iframe>`, `<details>` when `<script>` blocked
- Event handlers: `onerror`, `onload`, `onfocus`, `onmouseover`
- String escapes for JS contexts: single quotes, double quotes, backticks
- Encoding variations: hex, Unicode, base64, URL encoding, double encoding
- Parser differentials and mutation XSS (mXSS)
- CSP bypasses: JSONP endpoints, script gadgets in allowed libraries, base-uri manipulation

### Impact Demonstration
Go beyond `alert(1)`:
- **Session hijacking**: steal cookies (`document.cookie`) or JWTs from localStorage
- **Unauthorized actions**: CSRF via XSS
- **Credential harvesting**: inject convincing phishing forms
- **Information disclosure**: extract sensitive data from DOM

### Advanced Considerations
- **DOM Clobbering**: inject HTML with id/name attributes to overwrite global JS variables
- **Mutation XSS**: browser HTML parser "corrects" malformed HTML containing payload
- **Template injection**: inject template syntax (`{{7*7}}`) if server-side templating used
- **CSP analysis**: check `script-src` for JSONP endpoints, old library versions with known gadgets

## Report Format

Write to `ensphere-pentest/05-xss/report.md`:
- Successfully Exploited (with type: Reflected/Stored/DOM, full payload, impact evidence)
- Vectors Confirmed Secure (table: Source | Endpoint | Defense | Render Context | Verdict)
- CSP analysis and bypass attempts
