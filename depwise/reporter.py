"""
reporter.py — formats scan results into clean terminal output
No drama. No AI language. Just facts.
"""

import sys


# ANSI colors — disabled automatically if not a TTY
def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


COLOR = _supports_color()

RED    = "\033[91m" if COLOR else ""
YELLOW = "\033[93m" if COLOR else ""
GREEN  = "\033[92m" if COLOR else ""
GRAY   = "\033[90m" if COLOR else ""
BOLD   = "\033[1m"  if COLOR else ""
RESET  = "\033[0m"  if COLOR else ""


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": RED,
        "HIGH":     RED,
        "MEDIUM":   YELLOW,
        "LOW":      GRAY,
        "UNKNOWN":  GRAY,
        "NONE":     GREEN,
    }.get(severity, "")


ORANGE = "\033[38;5;208m" if COLOR else ""


def _status_label(result: dict) -> str:
    status = result["status"]
    if status == "vulnerable":
        sev = result["worst_severity"]
        col = _severity_color(sev)
        return f"{col}{sev.lower()}{RESET}"
    if status == "abandoned":
        return f"{YELLOW}abandoned{RESET}"
    if status == "unpinned":
        return f"{GRAY}unpinned{RESET}"
    if status == "check_failed":
        return f"{ORANGE}unknown (check failed){RESET}"
    return f"{GREEN}ok{RESET}"


def print_header(scan_result: dict):
    venv = scan_result.get("venv")
    directory = scan_result.get("directory", ".")
    files = scan_result.get("files", {})

    print()
    print(f"{BOLD}depwise{RESET} — dependency health scanner")
    print()

    if venv:
        print(f"  venv     {venv}")
    else:
        print(f"  dir      {directory}")

    file_list = list(files.keys())
    if file_list:
        print(f"  reading  {', '.join(file_list)}")
    print()


def print_results(results: list[dict]):
    if not results:
        print(f"  {GREEN}no packages found{RESET}")
        print()
        return

    # Separate into issues and clean
    issues = [r for r in results if r["status"] != "ok"]
    clean  = [r for r in results if r["status"] == "ok"]

    if not issues:
        print(f"  {GREEN}✓{RESET}  {len(clean)} packages — no issues found")
        print()
        return

    # Print issues
    for r in issues:
        name    = r["name"]
        version = r["version"] or "?"
        label   = _status_label(r)
        fix     = r.get("fix", "")
        summary = r.get("summary", "")
        vuln_count = len(r.get("vulns", []))
        days    = r.get("abandonment", {}).get("days_since_update")

        # Main line
        fix_str = f"  fix: {fix}" if fix else ""
        vuln_str = f"  {vuln_count} CVE{'s' if vuln_count != 1 else ''}" if vuln_count else ""
        print(f"  {BOLD}{name}{RESET}@{version}   {label}{vuln_str}{fix_str}")

        # Detail line
        if summary:
            short = summary[:80] + ("..." if len(summary) > 80 else "")
            print(f"  {GRAY}  {short}{RESET}")

        # Abandonment detail
        if r["status"] == "abandoned" and days:
            print(f"  {GRAY}  last update: {days} days ago{RESET}")

        # Show top 2 CVE ids if multiple
        vulns = r.get("vulns", [])
        if len(vulns) > 1:
            ids = [v["id"] for v in vulns[:2]]
            more = f" +{len(vulns)-2} more" if len(vulns) > 2 else ""
            print(f"  {GRAY}  {', '.join(ids)}{more}{RESET}")

        print()

    # Summary line
    vulnerable    = [r for r in issues if r["status"] == "vulnerable"]
    abandoned     = [r for r in issues if r["status"] == "abandoned"]
    unpinned      = [r for r in issues if r["status"] == "unpinned"]
    check_failed  = [r for r in issues if r["status"] == "check_failed"]

    parts = []
    if vulnerable:
        parts.append(f"{RED}{len(vulnerable)} vulnerable{RESET}")
    if abandoned:
        parts.append(f"{YELLOW}{len(abandoned)} abandoned{RESET}")
    if unpinned:
        parts.append(f"{GRAY}{len(unpinned)} unpinned{RESET}")
    if check_failed:
        parts.append(f"{ORANGE}{len(check_failed)} unknown (network check failed){RESET}")
    if clean:
        parts.append(f"{GREEN}{len(clean)} ok{RESET}")

    print(f"  {', '.join(parts)}")
    print()


def print_fix_commands(results: list[dict], ecosystem: str = "PyPI"):
    """Print the commands needed to fix issues."""
    fixable = [r for r in results if r.get("fix") and r["status"] == "vulnerable"]

    if not fixable:
        return

    print(f"  to fix:")

    if ecosystem in ("PyPI", "mixed"):
        py_fixes = [r for r in fixable if r.get("ecosystem", "PyPI") == "PyPI"]
        if py_fixes:
            packages = " ".join(
                f"{r['name']}=={r['fix']}" for r in py_fixes
            )
            print(f"    pip install {packages}")

    npm_fixes = [r for r in fixable if r.get("ecosystem") == "npm"]
    if npm_fixes:
        packages = " ".join(
            f"{r['name']}@{r['fix']}" for r in npm_fixes
        )
        print(f"    npm install {packages}")

    print()


def print_error(message: str):
    print(f"\n  {RED}error:{RESET} {message}\n")


def print_no_files():
    print()
    print("  no dependency files found")
    print()
    print(f"  {GRAY}looking for: requirements.txt, pyproject.toml, package.json{RESET}")
    print()


def print_offline_warning():
    print(f"  {YELLOW}warning:{RESET} could not reach osv.dev — results may be incomplete")
    print()

