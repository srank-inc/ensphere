# Upload Polyglot Check

Tests file upload validation by sending files with mismatched content-type,
extension, and actual content.

## Setup

1. Identify a file upload endpoint
2. Edit `probe.py` and fill in UPLOAD_URL
3. Set AUTH_HEADER if authentication is required
4. Set FIELD_NAME if the upload field is not named "file"

## Usage

```bash
python3 probe.py
```

## Test Cases

| Test | Filename | Content-Type | Actual Content |
|------|----------|-------------|----------------|
| html_as_image | test.png | image/png | HTML with script tag |
| svg_xss | test.svg | image/svg+xml | SVG with embedded script |
| exe_as_pdf | test.pdf | application/pdf | PE executable header |
| double_extension | test.php.png | image/png | PHP code |
| null_byte | test.php%00.png | image/png | PHP code |
| html_content_type | test.txt | text/html | JavaScript |

## Output

JSON with `measurements` containing per-test round results (`status_code`,
`elapsed_ms`, `body_hash`, and `body_length`). It does not infer whether the
application accepted, stored, rendered, or executed an upload; the analyst
decides that from the response and any separately captured retrieval evidence.

## Exit Codes

- `0` — probes completed (JSON on stdout)
