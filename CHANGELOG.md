# Changelog

## Unreleased

### Security
- Env var values are never kept or printed. Live data records only whether a literal value is set, and the `secrets` output has a new `VALUE` column that always shows the fixed mask `********` for `PLAINTEXT_ENV` rows (and `-` for `INLINE_SECRET` rows), in both the table and CSV. There is deliberately no opt-in flag to reveal values: a governance report is often pasted into tickets, CI logs and spreadsheets, and the value is not needed to fix the finding. Read it in the Azure portal if you must.
- The Microsoft Graph token used by `rbac` is refreshed when it is expired or within 5 minutes of expiring, and once more if Graph returns 401.

### Added
- SECURITY.md with the supported versions and how to report a vulnerability privately.
- Dependabot version updates for pip and GitHub Actions (weekly).

## 0.2.0 (2026-10-14)

### Breaking changes
- Python 3.9 is no longer supported. acasentry now requires Python 3.10 or newer.
- `secrets`: the `PLAINTEXT_SECRET` flag is renamed `INLINE_SECRET`. It marks a Container Apps secret that is not a Key Vault reference (Container Apps encrypts these, but they are not centrally managed or rotated). Env vars with a literal, secret-looking value keep their own flag, `PLAINTEXT_ENV`, and now include init containers. New `CONTAINER` column.
- `exposure`: the `INGRESS` column is replaced by `REACHABILITY` (`public` or `vnet-only`). The `AUTH` column now shows `required`, `optional` or `off`. New flags `AUTH_NOT_ENFORCED` (auth enabled but anonymous requests allowed, or no unauthenticated action set) and `AUTH_EXCLUDED_PATHS`. Internet flags (`NO_IP_RULES`, `NO_AUTH`, ...) apply only to `public` apps.
- `identity` and `lockdown` output gain a `RESOURCE_GROUP` column.
- Exit codes: `0` success, `1` partial failure during `--apply` (some resources changed, some failed), `2` usage, sign-in, permission, subscription or other Azure errors (one-line `error:` message, no traceback), `130` interrupted.

### Added
- Live Azure hardening: `DefaultAzureCredential` with actionable error messages, full pagination of every list call, and retries for 408/429/5xx and connection errors (honors `Retry-After`, exponential backoff capped at 30 seconds, 5 attempts). The Azure SDK pipeline retry is disabled so retries do not stack.
- `lockdown <app>` accepts an app name, a full resource ID, or `--resource-group`. An ambiguous name is refused and the candidate resource IDs are listed. `identity` accepts `--resource-group` to limit its scope.
- `--apply` prints the plan first, then reports each resource as `OK` or `FAILED`.
- `rbac` resolves principal object IDs to UPNs or display names through Microsoft Graph, which needs `User.Read.All` or `Directory.Read.All`. Guests are detected by `#EXT#` in the UPN or `userType` Guest. Without Graph access, object IDs are shown with a warning.
- `--allow-ip` is validated as a CIDR or full IP address, `0.0.0.0/0` and `::/0` are refused, and very broad ranges (IPv4 /1 to /8, IPv6 /1 to /32) print a warning. Existing Allow rules are kept.
- `--version`.

### Security
- CSV export escapes formula injection: cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading `'`. The `-` placeholder cell is left as is.
