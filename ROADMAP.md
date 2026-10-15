# acasentry roadmap

Plan for acasentry by phase. Each phase ships something you can run from the command line. acasentry stays CLI-only: no GUI, no web dashboard, no hosted service. Later phases do not block earlier ones. Versions are direction, not date promises.

## Current status

| Item | Details |
| --- | --- |
| **Latest release** | [`v0.2.0`](https://github.com/chriswayneh/acasentry/releases/tag/v0.2.0) |
| **Next** | Phase 2: Report (not started) |
| **Next target** | `v0.3.0` |

## Phase map

| Phase | Name | Version | Outcome | Status |
| --- | --- | --- | --- | --- |
| **0** | Foundation | `v0.1.0` | Five commands, demo mode, CSV export, tests | Done |
| **1** | Harden | `v0.2.0` | Reliable live mode, safe apply, clear errors, CI | Done |
| **2** | Report | `v0.3.0` | JSON and SARIF output, severity, exit-on-findings for CI | Planned |
| **3** | Scale | `v0.4.0` | Multi-subscription and management group scans, baselines | Planned |
| **4** | Deepen | `v0.5.0` | Wider identity and access checks | Planned |
| **5** | Policy | `v0.6.0` | Configurable rules, suppressions, more safe fixes | Planned |
| **6** | Stable | `v1.0.0` | Stable CLI, flag names, report schema and exit codes | Planned |

## Phase 0: Foundation (v0.1.0)

**Goal:** Clone it and run every command in demo mode in about a minute.

- [x] `rbac`: role assignments on each environment and app, flagging Owner, Contributor and guest users
- [x] `exposure`: apps with external ingress, flagging no IP rules and no built-in auth
- [x] `secrets`: secrets not backed by Key Vault references and sensitive-looking env vars with literal values
- [x] `identity`: enable system-assigned managed identity, dry run unless `--apply`
- [x] `lockdown <app>`: switch ingress to internal or set IP allow rules with `--allow-ip`, dry run unless `--apply`
- [x] `--demo` on every command with built-in mock data, `--apply` simulated in demo mode
- [x] `--csv` export and `--subscription` for live mode via `DefaultAzureCredential`
- [x] Tests and README with real demo output

**Done when:** every command runs in demo mode as documented. Shipped as `0.1.0` (no tag or CHANGELOG entry).

## Phase 1: Harden (v0.2.0)

**Goal:** Live mode you can point at a real subscription without surprises.

- [x] Actionable one-line `error:` messages for sign-in, subscription and permission failures, no tracebacks
- [x] Full pagination of every list call
- [x] Retries for 408, 429, 5xx and connection errors with `Retry-After` and capped backoff, SDK retry disabled so they do not stack
- [x] Exit codes `0`, `1` (partial apply), `2` (usage or Azure errors), `130` (interrupted)
- [x] `--apply` prints the plan first, then `OK` or `FAILED` per resource
- [x] `lockdown` targets by name, resource ID or `--resource-group`, and refuses ambiguous names
- [x] `identity --resource-group` to limit scope
- [x] `rbac` resolves principals to UPNs or display names through Microsoft Graph, guests by `#EXT#` or `userType`
- [x] `exposure` reports `REACHABILITY` (`public` or `vnet-only`), `AUTH_NOT_ENFORCED` and `AUTH_EXCLUDED_PATHS`
- [x] `secrets` splits `INLINE_SECRET` and `PLAINTEXT_ENV`, covers init containers
- [x] `--allow-ip` validated as CIDR, `0.0.0.0/0` and `::/0` refused, broad ranges warned, existing Allow rules kept
- [x] CSV formula injection escaped
- [x] `--version`, Python 3.10 or newer
- [x] CI on Python 3.10 to 3.13 with pinned actions and least-privilege token

**Done when:** live mode handles throttling, paging and partial failure cleanly and CI is green. Shipped in [`v0.2.0`](https://github.com/chriswayneh/acasentry/releases/tag/v0.2.0).

## Phase 2: Report (v0.3.0)

**Goal:** Feed acasentry results into pipelines and other tools, not just terminals.

- [ ] `--format table|json|csv` on every command, with a documented JSON schema
- [ ] `--sarif FILE` so findings show up in GitHub code scanning
- [ ] Severity per flag (`high`, `medium`, `low`) and `--min-severity`
- [ ] `--fail-on SEVERITY` exit code for CI gates, separate from error codes
- [ ] `scan` command that runs `rbac`, `exposure`, `secrets` and `identity` checks in one pass
- [ ] Example GitHub Actions workflow using OIDC federated credentials (no stored secrets)

**Done when:** a CI job can run `acasentry scan --sarif` against a subscription and fail on high findings.

## Phase 3: Scale (v0.4.0)

**Goal:** Review a whole tenant estate, not one subscription at a time.

- [ ] Multiple `--subscription` values and `--management-group` to scan every subscription under it
- [ ] `--all-subscriptions` for every subscription the identity can read
- [ ] Bounded concurrency with the existing retry policy
- [ ] `--baseline FILE` to report only new findings since a saved scan
- [ ] `diff` command to compare two JSON reports

**Done when:** a management group scan finishes within Azure throttling limits and baseline diffs are stable across runs.

## Phase 4: Deepen (v0.5.0)

**Goal:** Cover the identity and access paths that the first checks miss.

- [ ] `rbac` resolves group membership and shows where each inherited assignment comes from (resource group, subscription, management group)
- [ ] Flag stale principals (deleted or disabled users and orphaned service principals)
- [ ] Report user-assigned identities, their role assignments and the apps sharing them
- [ ] Check Key Vault references resolve with the app identity and flag over-broad vault roles
- [ ] Registry pull checks: admin credentials versus managed identity for ACR
- [ ] Container Apps jobs coverage alongside apps

**Done when:** each new check has demo data, tests and a documented flag.

## Phase 5: Policy (v0.6.0)

**Goal:** Let teams tune acasentry to their own rules without forking it.

- [ ] Config file (`acasentry.toml`) for severity overrides, allowed roles and trusted CIDRs
- [ ] Suppressions with a required reason and optional expiry date
- [ ] More dry-run first fixes: switch registry pulls to managed identity, enforce auth on public apps
- [ ] `--apply` writes a JSON change log of what was changed

**Done when:** a team can encode its exceptions in config and every fix stays dry-run by default.

## Phase 6: Stable (v1.0.0)

**Goal:** A contract other people can build on.

- [ ] Freeze command names, flags, flag names, JSON and SARIF schema, and exit codes
- [ ] Deprecation policy for anything that changes after `v1.0.0`
- [ ] Published to PyPI with signed releases and provenance
- [ ] Live integration tests against a disposable test subscription
- [ ] Docs for required Azure and Graph permissions per command

**Done when:** the contract is documented, tested and released to PyPI.

## Out of scope

- A GUI, web dashboard or hosted service. acasentry is CLI-only.
- Continuous monitoring or alerting. It is a point-in-time review tool, not a SIEM or CSPM.
- Azure services other than Container Apps, beyond the identities, roles, vaults and registries those apps depend on.
- Silent changes. Every fix stays a dry run unless `--apply` is given.

See [CHANGELOG.md](CHANGELOG.md) for release history.
