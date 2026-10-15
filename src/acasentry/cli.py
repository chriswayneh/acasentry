"""acasentry command line interface."""

import argparse
import ipaddress
import sys

from . import __version__, checks, demo
from .output import table, write_csv
from .resilience import AcasentryError, first_line, translate, validate_subscription

HEADERS = {
    "rbac": ["SCOPE", "PRINCIPAL", "TYPE", "ROLE", "FLAGS", "SCOPE_ID", "PRINCIPAL_ID"],
    "exposure": ["APP", "REACHABILITY", "IP_RULES", "AUTH", "FLAGS"],
    "secrets": ["APP", "KIND", "CONTAINER", "NAME", "VALUE", "FLAG"],
    "identity": ["APP", "RESOURCE_GROUP", "CURRENT", "PLANNED"],
    "lockdown": ["APP", "RESOURCE_GROUP", "SETTING", "CURRENT", "PLANNED"],
}


def _sub(args):
    return validate_subscription(args.subscription)


def _apps(args, check_auth=False):
    if args.demo:
        apps = demo.APPS
    else:
        from . import azure_live

        apps = azure_live.load_apps(_sub(args), check_auth=check_auth)
    rg = getattr(args, "resource_group", None)
    if rg and args.command == "identity":
        apps = [
            a for a in apps if (a.get("resource_group") or "").lower() == rg.lower()
        ]
    return apps


def _emit(args, rows, note=""):
    print(table(HEADERS[args.command], rows))
    print(f"\n{len(rows)} row(s).{note}")
    if args.csv:
        # Written before any --apply change, so a CSV failure stops the run with nothing applied.
        try:
            write_csv(args.csv, HEADERS[args.command], rows)
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            raise AcasentryError(f"cannot write CSV to {args.csv}: {reason}") from None
        print(f"Wrote {args.csv}")


def run(args):
    cmd = args.command
    if cmd == "rbac":
        if args.demo:
            data = demo.ROLE_ASSIGNMENTS
        else:
            from . import azure_live

            data = azure_live.load_role_assignments(_sub(args))
        _emit(args, checks.rbac_rows(data))
        return 0
    if cmd == "exposure":
        _emit(args, checks.exposure_rows(_apps(args, check_auth=True)))
        return 0
    if cmd == "secrets":
        _emit(args, checks.secrets_rows(_apps(args)))
        return 0
    apps = _apps(args)
    if cmd == "identity":
        targets = [a for a in apps if checks.needs_identity(a)]
        rows = checks.identity_rows(targets)
        action = lambda a: _live().enable_system_identity(args.subscription, a)
    else:
        try:
            app = checks.select_app(apps, args.app, args.resource_group)
            rows = checks.lockdown_plan(app, args.allow_ip)
        except (LookupError, ValueError) as exc:
            raise AcasentryError(str(exc))
        warn_broad(args.allow_ip)
        targets = [app] if rows else []
        action = lambda a: _live().apply_lockdown(args.subscription, a, args.allow_ip)
    return _plan_and_apply(args, rows, targets, action)


def _live():
    from . import azure_live

    return azure_live


def _plan_and_apply(args, rows, targets, action):
    """Print the plan first, then (with --apply) execute per resource and report each outcome."""
    if not targets:
        _emit(args, rows, " Nothing to change.")
        return 0
    if not args.apply:
        _emit(args, rows, " DRY RUN: no changes made. Re-run with --apply to execute.")
        return 0
    if args.demo:
        _emit(args, rows, " DEMO MODE: --apply simulated, Azure was not touched.")
        return 0
    _emit(args, rows, " Applying...")
    failed = done = 0
    for app in targets:
        try:
            action(app)
            done += 1
            print(f"OK      {app['id']}")
        except KeyboardInterrupt:
            print(
                f"\nINTERRUPTED: {done} of {len(targets)} change(s) applied before stopping; "
                f"{app['id']} may be mid-update.",
                file=sys.stderr,
            )
            return 130
        except AcasentryError as exc:
            failed += 1
            print(f"FAILED  {app['id']}: {exc}")
        except Exception as exc:  # noqa: BLE001 - record per-resource outcome, never hide it
            failed += 1
            err = translate(exc, args.subscription)
            print(
                f"FAILED  {app['id']}: {err or type(exc).__name__ + ': ' + first_line(exc)}"
            )
    if failed and not done:
        print(f"\nFAILED: nothing applied, {failed} change(s) failed.", file=sys.stderr)
        return 2
    if failed:
        print(
            f"\nPARTIAL: {done} of {len(targets)} change(s) applied, {failed} failed.",
            file=sys.stderr,
        )
        return 1
    print(f"\nApplied {done} change(s).")
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--demo", action="store_true", help="use built-in mock data (no Azure needed)"
    )
    common.add_argument(
        "--csv", metavar="FILE", help="also write results to a CSV file"
    )
    common.add_argument("--subscription", help="Azure subscription ID (live mode)")
    p = argparse.ArgumentParser(
        prog="acasentry",
        description="Azure Container Apps access and identity governance",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sp = p.add_subparsers(dest="command", required=True)
    sp.add_parser("rbac", parents=[common], help="role assignments per app/environment")
    sp.add_parser("exposure", parents=[common], help="externally exposed apps")
    sp.add_parser(
        "secrets",
        parents=[common],
        help="secrets not backed by Key Vault and literal secret-looking env vars",
    )
    i = sp.add_parser(
        "identity", parents=[common], help="enable system-assigned managed identity"
    )
    i.add_argument("--apply", action="store_true")
    i.add_argument("--resource-group", help="only consider apps in this resource group")
    l = sp.add_parser(
        "lockdown",
        parents=[common],
        help="make ingress internal or add IP restrictions",
    )
    l.add_argument("app", help="app name, or full resource ID")
    l.add_argument(
        "--resource-group", help="resource group of the app (needed when names collide)"
    )
    l.add_argument(
        "--allow-ip", action="append", metavar="CIDR", default=[], type=_cidr
    )
    l.add_argument("--apply", action="store_true")
    return p


def _cidr(value):
    if "/" not in value and not (value.count(".") == 3 or ":" in value):
        raise argparse.ArgumentTypeError(
            f"invalid CIDR: {value} (use e.g. 203.0.113.0/24 or 203.0.113.7)"
        )
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid CIDR: {value}")
    if net.prefixlen == 0:
        raise argparse.ArgumentTypeError(f"{value} allows the whole internet; refusing")
    return str(net)


def warn_broad(cidrs):
    """Warn about very broad ranges. Called only after every argument and the target app validated."""
    for c in cidrs:
        net = ipaddress.ip_network(c)
        if net.prefixlen <= broad_prefix_limit(net):
            print(
                f"warning: --allow-ip {net} is very broad ({net.num_addresses:,} addresses); "
                "double-check this is intended.",
                file=sys.stderr,
            )


def broad_prefix_limit(net):
    """Prefixes at or below this are warned as very broad: /8 for IPv4, /32 for IPv6
    (a /32 is a whole ISP-sized allocation)."""
    return 8 if net.version == 4 else 32


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if not args.demo:
            validate_subscription(args.subscription)
        return run(args)
    except AcasentryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        err = translate(exc, args.subscription)
        if err is None:
            raise
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
