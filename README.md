# acasentry

CLI-only access and identity governance for Azure Container Apps. It reports who holds which Azure roles on each app and environment, which apps are exposed to the internet, which secrets are stored in plain text, and which apps lack a system-assigned managed identity. Two fix commands (`identity`, `lockdown`) print dry-run plans unless `--apply` is given.

Built on `azure-identity`, `azure-mgmt-appcontainers` and `azure-mgmt-authorization`. Live mode uses `DefaultAzureCredential` (az login, environment variables, or managed identity).

## Install

```
git clone https://github.com/chriswayneh/acasentry.git
cd acasentry
pip install -e .
```

## Quick start (demo mode, no Azure needed)

```
acasentry rbac --demo
acasentry exposure --demo
acasentry secrets --demo
acasentry identity --demo
acasentry lockdown orders-api --demo
acasentry lockdown orders-api --demo --allow-ip 203.0.113.0/24
```

Every command accepts `--demo`, `--csv out.csv`, and `--subscription <id>` (required in live mode). `identity` and `lockdown` accept `--apply`; with `--demo`, `--apply` is simulated and never touches Azure.

## Live mode

```
az login
acasentry exposure --subscription <subscription-guid>
```

- Auth uses `DefaultAzureCredential`, so `az login`, service principal environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`) and managed identity all work.
- The identity needs Reader on the subscription for the report commands and Contributor on the target apps for `--apply`.
- Common failures print a one-line `error:` message with the fix (not signed in, invalid or unknown subscription ID, permission denied) and exit with code 2, without a traceback.
- Every list call is read to the last page.
- Throttling (429) and transient errors (408, 5xx, connection errors) are retried up to 5 attempts with exponential backoff capped at 30 seconds per wait; `Retry-After` is honored within that cap.
- `--allow-ip` must be a valid CIDR; `0.0.0.0/0` and `::/0` are refused.

## Commands

| Command | What it does |
|---|---|
| `rbac` | Role assignments on each environment and app. Flags Owner, Contributor and guest (#EXT#) users. |
| `exposure` | Apps with external ingress. Flags no IP rules and no built-in auth. |
| `secrets` | Secrets not backed by Key Vault references and sensitive-looking env vars with literal values. |
| `identity [--apply]` | Enables system-assigned managed identity where missing. |
| `lockdown <app> [--allow-ip CIDR] [--apply]` | Switches ingress to internal, or sets IP allow rules when `--allow-ip` is given. |

## Sample output

Real output from running each demo command:

```
$ acasentry rbac --demo
SCOPE           PRINCIPAL                                     TYPE              ROLE                 FLAGS
--------------  --------------------------------------------  ----------------  -------------------  -----------------
cae-prod        alice@contoso.com                             User              Owner                OWNER
cae-prod        ops-team                                      Group             Reader               ok
orders-api      bob_partner.com#EXT#@contoso.onmicrosoft.com  User              Contributor          CONTRIBUTOR,GUEST
orders-api      ci-deployer                                   ServicePrincipal  Contributor          CONTRIBUTOR
web-frontend    carol@contoso.com                             User              Reader               ok
billing-worker  dave@contoso.com                              User              ContainerApp Reader  ok

6 row(s).
$ acasentry exposure --demo
APP           INGRESS   IP_RULES  AUTH  FLAGS
------------  --------  --------  ----  -------------------
orders-api    external  0         no    NO_IP_RULES,NO_AUTH
web-frontend  external  1         yes   ok

2 row(s).
$ acasentry secrets --demo
APP             KIND    NAME           FLAG
--------------  ------  -------------  ----------------
orders-api      secret  db-password    PLAINTEXT_SECRET
orders-api      env     API_TOKEN      PLAINTEXT_ENV
billing-worker  secret  smtp-pass      PLAINTEXT_SECRET
billing-worker  env     SMTP_PASSWORD  PLAINTEXT_ENV

4 row(s).
$ acasentry identity --demo
APP             CURRENT       PLANNED
--------------  ------------  ---------------------------
orders-api      None          SystemAssigned
billing-worker  UserAssigned  SystemAssigned,UserAssigned

2 row(s). DRY RUN: no changes made. Re-run with --apply to execute.
$ acasentry lockdown orders-api --demo
APP         SETTING   CURRENT  PLANNED
----------  --------  -------  -------
orders-api  external  True     False

1 row(s). DRY RUN: no changes made. Re-run with --apply to execute.
```

## Development

```
pip install -e ".[dev]"
pytest
```

## License

MIT
