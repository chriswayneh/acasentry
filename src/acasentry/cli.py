"""acasentry command line interface."""
import argparse
import sys

from . import checks, demo
from .output import table, write_csv

HEADERS = {
    "rbac": ["SCOPE", "PRINCIPAL", "TYPE", "ROLE", "FLAGS"],
    "exposure": ["APP", "INGRESS", "IP_RULES", "AUTH", "FLAGS"],
    "secrets": ["APP", "KIND", "NAME", "FLAG"],
    "identity": ["APP", "CURRENT", "PLANNED"],
    "lockdown": ["APP", "SETTING", "CURRENT", "PLANNED"],
}


def _sub(args):
    if not args.subscription:
        sys.exit("error: --subscription is required unless --demo is used")
    return args.subscription


def _apps(args, check_auth=False):
    if args.demo:
        return demo.APPS
    from . import azure_live
    return azure_live.load_apps(_sub(args), check_auth=check_auth)


def run(args):
    cmd = args.command
    note = ""
    if cmd == "rbac":
        if args.demo:
            data = demo.ROLE_ASSIGNMENTS
        else:
            from . import azure_live
            data = azure_live.load_role_assignments(_sub(args))
        rows = checks.rbac_rows(data)
    elif cmd == "exposure":
        rows = checks.exposure_rows(_apps(args, check_auth=True))
    elif cmd == "secrets":
        rows = checks.secrets_rows(_apps(args))
    elif cmd == "identity":
        apps = _apps(args)
        rows = checks.identity_rows(apps)
        note = _apply(args, rows, lambda a: _live().enable_system_identity(args.subscription, a), apps)
    elif cmd == "lockdown":
        apps = _apps(args)
        match = [a for a in apps if a["name"] == args.app]
        if not match:
            sys.exit(f"error: app '{args.app}' not found")
        rows = checks.lockdown_plan(match[0], args.allow_ip)
        note = _apply(args, rows, lambda a: _live().apply_lockdown(args.subscription, a, args.allow_ip), match)
    print(table(HEADERS[cmd], rows))
    print(f"\n{len(rows)} row(s).{note}")
    if args.csv:
        write_csv(args.csv, HEADERS[cmd], rows)
        print(f"Wrote {args.csv}")
    return 0


def _live():
    from . import azure_live
    return azure_live


def _apply(args, rows, fn, apps):
    if not args.apply:
        return " DRY RUN: no changes made. Re-run with --apply to execute."
    if args.demo:
        return " DEMO MODE: --apply simulated, Azure was not touched."
    by_name = {a["name"]: a for a in apps}
    for r in rows:
        fn(by_name[r[0]])
    return f" Applied {len(rows)} change(s)."


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--demo", action="store_true", help="use built-in mock data (no Azure needed)")
    common.add_argument("--csv", metavar="FILE", help="also write results to a CSV file")
    common.add_argument("--subscription", help="Azure subscription ID (live mode)")
    p = argparse.ArgumentParser(prog="acasentry", description="Azure Container Apps access and identity governance")
    sp = p.add_subparsers(dest="command", required=True)
    sp.add_parser("rbac", parents=[common], help="role assignments per app/environment")
    sp.add_parser("exposure", parents=[common], help="externally exposed apps")
    sp.add_parser("secrets", parents=[common], help="plain-text secrets and env vars")
    i = sp.add_parser("identity", parents=[common], help="enable system-assigned managed identity")
    i.add_argument("--apply", action="store_true")
    l = sp.add_parser("lockdown", parents=[common], help="make ingress internal or add IP restrictions")
    l.add_argument("app")
    l.add_argument("--allow-ip", action="append", metavar="CIDR", default=[])
    l.add_argument("--apply", action="store_true")
    return p


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
