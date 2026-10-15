# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

Fixes are released on the latest 0.2.x version only.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, pull request or discussion for a suspected vulnerability.

Include what you can of:
- the affected version (`acasentry --version`) and command,
- steps to reproduce, using `--demo` data or redacted output,
- the impact you expect.

Never include real secrets, tokens, tenant IDs or subscription IDs in a report.

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment (confirmed or not, and severity) within 10 business days.
- For confirmed issues, a fix or mitigation plan, with a target of 30 days for high severity issues, and progress updates through the advisory at least every 14 days.
- Credit in the advisory and CHANGELOG if you want it, once a fix is released.

## Scope

acasentry reads Azure Container Apps, role assignment and Microsoft Graph data with the signed-in identity, and changes apps only with `--apply`. Issues in Azure itself or in the Azure SDKs should be reported to Microsoft.
