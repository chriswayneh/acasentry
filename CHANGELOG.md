# Changelog

## 0.2.2 (2026-10-15)

### Fixed
- Every Azure SDK or HTTP error and every connection error that reaches the CLI now prints a one-line `error:` message with a hint and exits with code `2`, as documented, instead of a traceback with exit code `1`. New hints cover 400 (check arguments and that the Microsoft.App provider is registered), 404 (check the app name, `--resource-group` and `--subscription`), 409 (another operation in progress), any other HTTP status, other Azure SDK errors, and connection failures or timeouts (check network, proxy and DNS). Only the first line of the Azure message is shown. Errors that are not from Azure or the network (programming bugs) still raise normally.
- If the `--csv` file cannot be written (missing folder, permission denied and other OS errors), acasentry prints `error: cannot write CSV to <path>: <reason>` and exits with code `2` instead of a traceback. The CSV is written before any `--apply` change, so a CSV failure means nothing was applied.

- `identity --apply` and `lockdown --apply` no longer send the whole app back to Azure. They send narrow JSON merge-patch updates (only `identity`, or only `ingress.external` / `ingress.ipSecurityRestrictions`) built from a fresh read just before the update, so concurrent changes to other settings are not overwritten. The Container Apps API has no ETag / If-Match support, so a concurrent edit of the same IP rule list can still race; a 412 response, if Azure ever returns one, prints a clean error.
- A failure while polling an update no longer resubmits the change; polling resumes from the continuation token.
- `identity --apply` decides the new identity type from a fresh read of the app, not from the earlier listing, and does nothing if a system-assigned identity was added in the meantime.
- `lockdown --allow-ip` on an app with Deny IP rules is now refused when the plan is built (exit `2`, nothing applied). Previously a CIDR already present as a Deny rule produced "Nothing to change" and exit `0`.
- An apply error with an empty message no longer crashes the per-resource summary.
- New IP rule names (`acasentry-allow-N`) never collide with existing rule names.
- Transient error detection uses exception types (connection errors and their subclasses, `URLError`), so Graph network errors are retried.

### Changed
- `--apply` exit codes: `1` now means some changes applied and some failed; if every change failed (nothing applied) the exit code is `2`.
- `rbac` table and CSV gain `SCOPE_ID` and `PRINCIPAL_ID` columns at the end, so rows stay distinct when scope or principal names repeat.
- SECURITY.md: the repository is public, so vulnerabilities are reported through the Security tab's **Report a vulnerability** (GitHub private vulnerability reporting).

## 0.2.1 (2026-10-15)

### Changed
- The `secrets` table and CSV gain a `VALUE` column, placed before `FLAG` (columns: APP, KIND, CONTAINER, NAME, VALUE, FLAG). `FLAG` moves from column 5 to column 6 (in 0.2.0 the columns were APP, KIND, CONTAINER, NAME, FLAG), so scripts that read the secrets CSV by position must be updated.

### Security
- Env var values are never printed. Normalization drops each env var value and keeps only a has-value flag; the Azure SDK response objects briefly hold them in memory while the app list is fetched and normalized. The `VALUE` column always shows the fixed mask `********` for `PLAINTEXT_ENV` rows (and `-` for `INLINE_SECRET` rows), in both the table and CSV. There is deliberately no opt-in flag to reveal values: a governance report is often pasted into tickets, CI logs and spreadsheets, and the value is not needed to fix the finding.
- The Microsoft Graph token used by `rbac` is refreshed when it is expired or within 5 minutes of expiring. acasentry also calls Graph once more on a 401; azure-identity cannot force a refresh, so this usually reuses the cached token. A CAE claims challenge is not handled yet. Proper CAE handling is planned.
- A failure to get the Graph sign-in token (for example an expired `az login`) or a persistent 401 from Graph now prints a warning to run `az login` again, instead of the permission-grant advice.

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
