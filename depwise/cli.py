"""
cli.py — command line interface for depwise
"""

import sys
import argparse
from pathlib import Path

from depwise.scanner  import scan_directory
from depwise.checker  import check_all
from depwise.reporter import (
    print_header, print_results, print_fix_commands,
    print_error, print_no_files, print_offline_warning,
)


def cmd_scan(args):
    """Main scan command."""
    directory = args.directory or "."

    # Validate directory
    if not Path(directory).exists():
        print_error(f"directory not found: {directory}")
        sys.exit(1)

    # Scan for dependency files
    scan = scan_directory(directory)

    print_header(scan)

    if not scan["packages"] and not scan["files"]:
        print_no_files()
        sys.exit(0)

    if scan["errors"]:
        for err in scan["errors"]:
            print_error(err)

    if not scan["packages"]:
        print_error("no packages found in dependency files")
        sys.exit(0)

    # Show package count
    count = len(scan["packages"])
    ecosystem = scan.get("ecosystem", "PyPI")
    print(f"  scanning {count} packages...\n")

    # Check all packages
    try:
        results = check_all(scan["packages"], ecosystem)
    except KeyboardInterrupt:
        print("\n  cancelled")
        sys.exit(0)
    except Exception as e:
        print_offline_warning()
        results = []

    # Print results
    print_results(results)
    print_fix_commands(results, ecosystem)

    # Exit code: 1 if issues found (useful for CI/CD)
    has_issues = any(r["status"] != "ok" for r in results)
    sys.exit(1 if has_issues and args.strict else 0)


def cmd_why(args):
    """Explain a specific package's issues."""
    from depwise.checker import check_package

    name      = args.package
    version   = args.version or ""
    ecosystem = args.ecosystem or "PyPI"

    print(f"\n  checking {name}@{version or 'any'}...\n")

    result = check_package(name, version, ecosystem)

    if result["status"] == "ok":
        print(f"  {name}@{version} — no known issues\n")
        return

    if result["vulns"]:
        print(f"  {name}@{version} — {len(result['vulns'])} vulnerabilities\n")
        for v in result["vulns"]:
            print(f"  {v['id']}")
            print(f"    {v['summary']}")
            if v.get("fixed_in"):
                print(f"    fixed in: {v['fixed_in']}")
            print()

    if result["abandonment"].get("abandoned"):
        print(f"  abandoned: {result['abandonment']['reason']}")
        days = result["abandonment"].get("days_since_update")
        if days:
            print(f"  last update: {days} days ago")
        print()


def cmd_list(args):
    """List all packages found in the current project."""
    directory = args.directory or "."
    scan      = scan_directory(directory)

    if not scan["packages"]:
        print_no_files()
        return

    print(f"\n  {len(scan['packages'])} packages in {directory}\n")
    for pkg in sorted(scan["packages"], key=lambda p: p["name"].lower()):
        name    = pkg["name"]
        version = pkg.get("version") or "unpinned"
        pinned  = "  (unpinned)" if not pkg.get("pinned") else ""
        print(f"  {name}=={version}{pinned}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="depwise",
        description="dependency health scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  depwise                    scan current directory
  depwise scan ./myproject   scan a specific directory
  depwise why requests       explain issues with a package
  depwise list               list all packages found
  depwise scan --strict      exit code 1 if issues found (for CI)
        """
    )

    parser.add_argument("--version", action="version", version="depwise 0.1.0")
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="scan dependencies")
    scan_parser.add_argument(
        "directory", nargs="?", default=".",
        help="directory to scan (default: current)"
    )
    scan_parser.add_argument(
        "--strict", action="store_true",
        help="exit with code 1 if any issues found (useful for CI/CD)"
    )
    scan_parser.set_defaults(func=cmd_scan)

    # why command
    why_parser = subparsers.add_parser("why", help="explain a package's issues")
    why_parser.add_argument("package", help="package name")
    why_parser.add_argument("--version", "-v", help="package version")
    why_parser.add_argument(
        "--ecosystem", "-e", default="PyPI",
        choices=["PyPI", "npm"],
        help="package ecosystem (default: PyPI)"
    )
    why_parser.set_defaults(func=cmd_why)

    # list command
    list_parser = subparsers.add_parser("list", help="list all packages found")
    list_parser.add_argument(
        "directory", nargs="?", default=".",
        help="directory to scan (default: current)"
    )
    list_parser.set_defaults(func=cmd_list)

    args = parser.parse_args()

    # Default to scan if no command given
    if args.command is None:
        args.directory = "."
        args.strict    = False
        cmd_scan(args)
        return

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
