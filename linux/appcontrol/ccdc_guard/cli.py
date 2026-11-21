"""
CLI entry point — argparse dispatch for all ccdc-guard commands.
"""

import argparse
import os
import sys

from . import VERSION
from .logger import info, warn, error, critical, ccdc_log, GREEN, YELLOW, RED, BLUE, NC


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # type: () -> int
    parser = argparse.ArgumentParser(
        prog="ccdc-guard",
        description="CCDC application control via fapolicyd (v{})".format(VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  baseline              Inventory packages + executables, generate trust DB
  audit                 Enable fapolicyd in permissive/audit mode
  enforce               Enable fapolicyd enforcement (auto-rollback on failure)
  status                Show enforcement state, trust counts, recent denials
  denials               Show recent execution denials from fapolicyd log
  approve <file>        Add file to user trust (trust=2)
  update  <file>        Re-hash and update trust record for a modified file
  revoke  <file>        Remove file from user trust
  harden  <service>     Preview systemd drop-in security restrictions
  rollback              Restore previous fapolicyd configuration
""",
    )
    parser.add_argument(
        "--version", action="version",
        version="ccdc-guard {}".format(VERSION),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # baseline
    p_baseline = subparsers.add_parser("baseline", help="Build trust baseline")
    p_baseline.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-file output",
    )

    # audit
    subparsers.add_parser("audit", help="Enable permissive/audit mode")

    # enforce
    subparsers.add_parser("enforce", help="Enable enforcement mode")

    # status
    subparsers.add_parser("status", help="Show current state")

    # denials
    p_denials = subparsers.add_parser("denials", help="Show recent execution denials")
    p_denials.add_argument(
        "--count", "-n", type=int, default=50,
        help="Number of denial entries to show (default: 50)",
    )

    # approve
    p_approve = subparsers.add_parser("approve", help="Add file to user trust")
    p_approve.add_argument("file", help="Path to file to approve")
    p_approve.add_argument("--notes", default="", help="Optional notes")

    # update
    p_update = subparsers.add_parser("update", help="Update trust record for changed file")
    p_update.add_argument("file", help="Path to file to update")
    p_update.add_argument("--notes", default="", help="Optional notes")

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Remove file from user trust")
    p_revoke.add_argument("file", help="Path to file to revoke")

    # harden
    p_harden = subparsers.add_parser("harden", help="Preview systemd security drop-in")
    p_harden.add_argument("service", help="Systemd service name (with or without .service)")

    # rollback
    subparsers.add_parser("rollback", help="Restore previous fapolicyd config")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # Root check for most commands
    write_commands = {"baseline", "audit", "enforce", "approve",
                      "update", "revoke", "rollback"}
    if args.command in write_commands and os.geteuid() != 0:
        error("'ccdc-guard {}' must be run as root".format(args.command))
        return 1

    return _dispatch(args)


def _dispatch(args):
    # type: (...) -> int
    cmd = args.command

    if cmd == "baseline":
        return _cmd_baseline(args)
    elif cmd == "audit":
        return _cmd_audit(args)
    elif cmd == "enforce":
        return _cmd_enforce(args)
    elif cmd == "status":
        return _cmd_status(args)
    elif cmd == "denials":
        return _cmd_denials(args)
    elif cmd == "approve":
        return _cmd_approve(args)
    elif cmd == "update":
        return _cmd_update(args)
    elif cmd == "revoke":
        return _cmd_revoke(args)
    elif cmd == "harden":
        return _cmd_harden(args)
    elif cmd == "rollback":
        return _cmd_rollback(args)
    else:
        error("Unknown command: {}".format(cmd))
        return 1


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def _cmd_baseline(args):
    from .trust import build_baseline
    from .enforcement import write_trust_file

    info("Starting baseline inventory…")
    verbose = not getattr(args, "quiet", False)
    summary = build_baseline(verbose=verbose)

    info("Baseline complete:")
    print("  Package-managed : {}".format(summary["package_managed"]))
    print("  Custom/unpackaged: {}".format(summary["custom"]))
    print("  Errors          : {}".format(summary["errors"]))

    # Write the trust file so fapolicyd can use it immediately
    write_trust_file()
    info("Run 'ccdc-guard audit' or 'ccdc-guard enforce' to activate.")
    return 0


def _cmd_audit(args):
    from .enforcement import enable_audit_mode

    info("Enabling audit (permissive) mode…")
    ok = enable_audit_mode()
    if ok:
        info("{}Audit mode active.{} Use 'ccdc-guard denials' to monitor.".format(GREEN, NC))
        return 0
    else:
        error("Failed to enable audit mode")
        return 1


def _cmd_enforce(args):
    from .enforcement import enable_enforce_mode

    warn("{}Enabling ENFORCEMENT mode.{} Untrusted executables will be BLOCKED.".format(
        YELLOW, NC))
    warn("Auto-rollback is active — run 'ccdc-guard rollback' to revert manually.")

    ok = enable_enforce_mode()
    if ok:
        info("{}Enforcement is now ACTIVE.{}".format(GREEN, NC))
        return 0
    else:
        error("Enforcement failed or was rolled back — check output above")
        return 1


def _cmd_status(args):
    from .monitoring import show_status

    show_status()
    return 0


def _cmd_denials(args):
    from .monitoring import show_denials

    count = getattr(args, "count", 50)
    show_denials(count=count)
    return 0


def _cmd_approve(args):
    from .trust import approve_file
    from .enforcement import write_trust_file, reload_fapolicyd, fapolicyd_is_active

    ok = approve_file(args.file, notes=getattr(args, "notes", ""))
    if not ok:
        return 1
    # Rewrite trust file and reload fapolicyd if it's running
    write_trust_file()
    if fapolicyd_is_active():
        reload_fapolicyd()
    return 0


def _cmd_update(args):
    from .trust import update_file
    from .enforcement import write_trust_file, reload_fapolicyd, fapolicyd_is_active

    ok = update_file(args.file, notes=getattr(args, "notes", ""))
    if not ok:
        return 1
    write_trust_file()
    if fapolicyd_is_active():
        reload_fapolicyd()
    return 0


def _cmd_revoke(args):
    from .trust import revoke_file
    from .enforcement import write_trust_file, reload_fapolicyd, fapolicyd_is_active

    ok = revoke_file(args.file)
    if not ok:
        return 1
    write_trust_file()
    if fapolicyd_is_active():
        reload_fapolicyd()
    return 0


def _cmd_harden(args):
    from .hardening import show_harden_preview

    show_harden_preview(args.service)
    return 0


def _cmd_rollback(args):
    from .recovery import do_rollback

    warn("Rolling back fapolicyd configuration to last snapshot…")
    ok = do_rollback()
    if ok:
        info("{}Rollback complete.{}".format(GREEN, NC))
        return 0
    else:
        error("Rollback failed")
        return 1
