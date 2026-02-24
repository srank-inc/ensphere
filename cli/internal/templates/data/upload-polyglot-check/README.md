# Upload Polyglot Check

Tests file upload validation by sending files with mismatched content-type,
extension, and actual content.

## Setup

1. Identify a file upload endpoint
2. Edit `exploit.py` and fill in UPLOAD_URL
3. Set AUTH_HEADER if authentication is required
4. Set FIELD_NAME if the upload field is not named "file"

## Usage

```bash
python3 exploit.py
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

## Interpreting Results

- **confirmed**: 2+ polyglot uploads accepted — validation is insufficient
- **potential**: 1 upload accepted — may be intentional
- **safe**: All polyglot uploads rejected
