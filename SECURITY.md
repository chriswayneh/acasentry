# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.3 | Yes |
| < 0.2.3 | No |

Fixes are released on the latest version only. 0.2.3 fixes unescaped terminal output, CSV formula cells after leading whitespace or a newline, and Graph redirects that could forward the sign-in token, so upgrade from earlier versions.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Do not open a public issue, pull request or discussion for a suspected vulnerability.

Include what you can of:
- the affected version (`acasentry --version`) and command,
- steps to reproduce, using `--demo` data or redacted output,
- the impact you expect.

Never include real secrets, tokens, tenant IDs or subscription IDs in a report.

## What to expect

acasentry is maintained by one person, so responses are best effort. The aim is to acknowledge a report within a week, then keep you updated on the assessment and any fix. Credit in the CHANGELOG is offered once a fix is released, if you want it.

## Scope

acasentry reads Azure Container Apps, role assignment and Microsoft Graph data with the signed-in identity, and changes apps only with `--apply`. Issues in Azure itself or in the Azure SDKs should be reported to Microsoft.
