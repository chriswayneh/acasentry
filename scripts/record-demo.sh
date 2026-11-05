#!/usr/bin/env bash
# Re-record docs/assets/demo.gif from the published acasentry v0.2.3 package (--demo only).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/acasentry-demo-XXXXXX")"
VENV="$STAGE/venv"
WORK="$STAGE/work"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

command -v vhs >/dev/null || { echo "vhs is required" >&2; exit 1; }
command -v ttyd >/dev/null || { echo "ttyd is required by vhs" >&2; exit 1; }

mkdir -p "$WORK"
cp "$ROOT/scripts/demo.tape" "$WORK/demo.tape"

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install -q "git+https://github.com/chriswayneh/acasentry.git@v0.2.3"

export ACASENTRY_BIN_DIR="$VENV/bin"
export ACASENTRY_DEMO_HOME="$WORK"
export PATH="$ACASENTRY_BIN_DIR:$PATH"

# Offline sanity: --demo must work with no Azure credentials.
unset AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID \
  ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID || true
"$VENV/bin/acasentry" --version >/dev/null
"$VENV/bin/acasentry" exposure --demo >/dev/null

( cd "$WORK" && vhs demo.tape )

mkdir -p "$ROOT/docs/assets"
cp "$WORK/demo.gif" "$ROOT/docs/assets/demo.gif"
echo "Wrote $ROOT/docs/assets/demo.gif"
