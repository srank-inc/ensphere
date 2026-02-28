# Command Injection Reverse Check

Tests command injection by injecting OS-level sleep commands and measuring
response timing deltas against a baseline.

## Setup

1. Identify an endpoint that processes user input in a system command (e.g., ping, DNS lookup)
2. Edit `exploit.py` and fill in TARGET_URL and PARAM
3. Optionally set METHOD (defaults to POST)

## Usage

```bash
python3 exploit.py
```

## Probes

Tests 9 injection variants across Linux and Windows:
- Linux: semicolon, pipe, ampersand, backtick, `$()`, newline separators with `sleep`
- Windows: pipe, ampersand with `ping -n`, `timeout /t`

Also runs a control probe with `sleep 0` to confirm syntax acceptance without delay.

## Output

JSON with `schema_version: 2` and `measurements` containing baseline rounds with average, per-payload results with `delta_ms` (difference from baseline), and control round. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
