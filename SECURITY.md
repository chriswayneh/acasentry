# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

Fixes are released on the latest 0.2.x version only.

## Reporting a vulnerability

While this repository is private, report vulnerabilities by messaging @chriswayneh on GitHub directly. Do not open an issue, pull request or discussion for a suspected vulnerability. Private reporting through the repository's **Security** tab (GitHub Security Advisories) will be turned on once the repository is public, and will then be the preferred channel.

Include what you can of:
- the affected version (`acasentry --version`) and command,
- steps to reproduce, using `--demo` data or redacted output,
- the impact you expect.

Never include real secrets, tokens, tenant IDs or subscription IDs in a report.

## What to expect

acasentry is maintained by one person, so responses are best effort. The aim is to acknowledge a report within a week, then keep you updated on the assessment and any fix. Credit in the CHANGELOG is offered once a fix is released, if you want it.

## Scope

acasentry reads Azure Container Apps, role assignment and Microsoft Graph data with the signed-in identity, and changes apps only with `--apply`. Issues in Azure itself or in the Azure SDKs should be reported to Microsoft.
