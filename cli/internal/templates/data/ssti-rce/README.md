# SSTI RCE

Tests server-side template injection by injecting math expressions (e.g., `{{7*7}}`)
targeting multiple template engines and checking whether the computed result (e.g., `49`)
appears in the response.

## Setup

1. Identify an endpoint that renders user-supplied input through a template engine
2. Edit `exploit.py` and fill in TARGET_URL and PARAM
3. Optionally set METHOD (defaults to GET)

## Usage

```bash
python3 exploit.py
```

## Probes

Tests 12 template engine expression syntaxes:
- Jinja2/Twig: `{{7*7}}`, `{{7*'7'}}`
- Mako/FreeMarker: `${7*7}`
- ERB: `<%= 7*7 %>`
- Velocity: `#set($x=7*7)${x}`
- Smarty: `{7*7}`
- Pebble/Nunjucks: `{{7*7}}`
- Thymeleaf: `[[${7*7}]]`
- Handlebars: `{{#with ...}}`
- doT: `{{=7*7}}`

Also sends a unique canary string to verify input reflection.

## Output

JSON with `schema_version: 2` and `measurements` containing canary reflection check, baseline round, and per-engine results with `found` boolean (computed result present), `raw_payload_present` boolean (template syntax not evaluated), and round data. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
