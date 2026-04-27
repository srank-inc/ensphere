# Pentest Configuration

## Target
- URL: https://localhost:3000
- Source code: yes | no
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

## Authorization
This test is fully authorized against the specified controlled environment.
