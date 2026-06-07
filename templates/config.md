# Pentest Configuration

## Target
- URL: https://localhost:3000
- Source code: yes | no
- Target type: auto | web_app | api_backend | static_site | mobile_client_remote_backend | mobile_client_offline | desktop_or_extension_client | cloud_only | library_or_cli
- Cloud: none | aws | gcp | azure | kubernetes | (comma-separated if multiple)

## Authentication
- Login URL: /login
- Username: testuser
- Password: testpass123
- (Add additional accounts for multi-role testing)

## Scope
- In scope: All network-reachable endpoints of the target application
- Out of scope: Third-party services, production systems
- Rules to avoid: (e.g., no DoS, no data destruction)
- Areas to focus: (e.g., payment flow, admin panel)

## Exploitation
- Enabled: false
- Selected findings: []
- Max risk: 3
- Allowed actions: read_only_data_extraction, browser_js_execution
- Forbidden actions: data_deletion, persistence, credential_dumping
- Cleanup evidence required: true

## Authorization
This test is fully authorized against the specified controlled environment.
