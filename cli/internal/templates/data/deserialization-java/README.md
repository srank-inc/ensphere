# Java Deserialization Detection

Tests for unsafe Java deserialization by sending serialized object headers,
XStream XML, and Jackson polymorphic payloads. Measures timing deltas and
checks error responses for deserialization-related signatures.

## Setup

1. Identify an endpoint that accepts binary or object data (e.g., import, upload, RMI)
2. Edit `probe.py` and fill in TARGET_URL and ENDPOINT
3. Optionally set AUTH_HEADER for authenticated endpoints

## Usage

```bash
python3 probe.py
```

## Probes

Tests 5 deserialization vectors:
- Java serialization magic bytes (ACED0005)
- TC_OBJECT with dummy class descriptor
- RMI protocol header (JRMI)
- XStream XML deserialization payload
- Jackson polymorphic type probe

Also checks whether the endpoint accepts `application/x-java-serialized-object` content type.

Checks error responses for 12 deserialization-related signatures (ClassNotFoundException,
InvalidClassException, StreamCorruptedException, etc.).

## Output

JSON with `measurements` containing baseline rounds, per-probe results with `delta_ms`, `matched_error_signatures`, and `response_snippet`, plus content-type acceptance checks. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
