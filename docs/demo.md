# Terminal demo

The README GIF replays actual output captured from the published
`acasentry` **v0.2.3** package on 2026-11-05 (America/Chicago), using only the
built-in `--demo` mock data. Timing is adjusted for README readability. It is a
recorded replay, not a live Azure session.

## What it shows

1. Confirm the installed version (`0.2.3`).
2. `acasentry exposure --demo` — fictional apps with public ingress and missing
   IP rules or auth.
3. `acasentry secrets --demo` — inline secrets and plaintext env names (values
   are never shown; the tool prints placeholders).
4. `acasentry identity --demo` — dry-run plan to enable system-assigned managed
   identity (no `--apply`, so nothing changes).

## Run it yourself

Use Python 3.10 or newer in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install "git+https://github.com/chriswayneh/acasentry.git@v0.2.3"

.venv/bin/acasentry --version
.venv/bin/acasentry exposure --demo
.venv/bin/acasentry secrets --demo
.venv/bin/acasentry identity --demo
```

`--demo` uses built-in mock data only. No Azure account, tenant, subscription,
or credential is required. Do not set `AZURE_*` / `ARM_*` variables for this
walkthrough, and do not pass `--apply`.

## Re-record the GIF

Requires [vhs](https://github.com/charmbracelet/vhs) (and `ttyd`) plus a
monospace font such as JetBrains Mono:

```bash
./scripts/record-demo.sh
```

That script stages a throwaway directory with `mktemp -d`, installs v0.2.3 into
a temporary venv, records `docs/assets/demo.gif` from `scripts/demo.tape`, and
starts no Docker containers. It never passes credentials on the command line.

## Text alternative

The [Quick start](../README.md#quick-start) section shows `acasentry exposure --demo`
in text.
