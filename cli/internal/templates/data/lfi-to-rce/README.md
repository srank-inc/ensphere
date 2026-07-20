# LFI to RCE

Tests local file inclusion via directory traversal by sending path traversal
payloads targeting known OS files and checking responses for file content signatures.

## Setup

1. Identify an endpoint that includes files based on a parameter (e.g., template viewer, file download)
2. Edit `probe.py` and fill in TARGET_URL and PARAM
3. Optionally set OS (defaults to "linux"; set to "windows" for Windows targets)

## Usage

```bash
python3 probe.py
```

## Probes

**Linux** (10 payloads targeting):
- `/etc/passwd` via 3, 6, 10 levels of traversal
- Null byte, double-encoding, and dot-truncation bypasses
- `/etc/shadow`, `/proc/self/environ`, `/proc/self/cmdline`, `/etc/hosts`

**Windows** (8 payloads targeting):
- `win.ini` via backslash and forward-slash traversal
- `system.ini`, `hosts`, `boot.ini`
- Null byte and double-encoding bypasses

Checks responses against 8 known signatures per OS (e.g., `root:x:0:0`, `[fonts]`).

## Output

JSON with `measurements` containing baseline round, per-probe results with `matched_signatures`, `hash_matches_baseline`, and `length_delta`. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
