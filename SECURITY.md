# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| 0.6.x   | Active support |
| 0.5.x   | Security fixes only |
| < 0.5   | End of life |

## Reporting a Vulnerability

If you discover a security vulnerability in CloudFail-Killer, please report it responsibly.

### How to Report

1. **Preferred**: Send an email to the project maintainers with the subject `[SECURITY] CloudFail-Killer Vulnerability`
2. **Alternative**: Create a new [GitHub Security Advisory](https://github.com/smart-jemy/cloudfail-killer/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Status updates** every 7 days until resolution
- **Credit** in the release notes (if desired)

### Responsible Disclosure

We follow a coordinated disclosure process:
1. Report received and acknowledged
2. Investigate and validate the issue
3. Develop and test the fix
4. Release the fix in a security update
5. Publicly disclose after the fix is available (typically 90 days after report)

## Security Design

CloudFail-Killer is designed with security in mind:

- **No raw SYN scans**: Active probing uses HTTP-level requests only
- **Encrypted by default**: All API calls use HTTPS
- **Rate limiting**: Per-source rate limiting prevents abuse
- **Stealth mode**: Optional stealth features for authorized testing
- **No data exfiltration**: Results are stored locally only
- **Minimal permissions**: Runs as unprivileged user, no root required

## Allowed Use

This tool is intended for **authorized security testing** only:
- Systems you own or operate
- Systems with explicit written authorization
- Educational/CTF environments
- Bug bounty programs with scope authorization

Unauthorized use against systems without permission is illegal and violates the tool's license.

## Dependency Security

Dependencies are audited using:
- `safety check` — Python package vulnerability scanner
- `bandit` — Python code security linter
- GitHub Dependabot — Automated dependency updates

To run security checks locally:
```bash
safety check
bandit -r cloudkill/ -x tests/
```
