"""
checker.py — checks packages against OSV API and GitHub for abandonment
No API key required. No account. Completely free.
"""

import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


OSV_API    = "https://api.osv.dev/v1"
GITHUB_API = "https://api.github.com"

# Ecosystem mapping
ECOSYSTEM_MAP = {
    "pypi":  "PyPI",
    "npm":   "npm",
    "cargo": "crates.io",
    "go":    "Go",
}

# Known abandoned/deprecated packages
# This list is seeded with well-known ones
# Depwise grows this over time
KNOWN_ABANDONED = {
    "request":      "Officially deprecated Feb 2020. No security fixes.",
    "left-pad":     "Archived. Historical incident package.",
    "node-uuid":    "Replaced by uuid package.",
    "jade":         "Renamed to pug. No longer maintained.",
    "bower":        "Deprecated. Use npm/yarn instead.",
    "grunt":        "Largely abandoned. Use webpack/vite.",
    "distutils":    "Removed from Python 3.12+.",
    "nose":         "Not maintained since 2015. Use pytest.",
    "pycrypto":     "Unmaintained since 2014. Use cryptography or pycryptodome.",
    "sha":          "Deprecated. Use hashlib.",
    "md5":          "Deprecated. Use hashlib.",
}


def _http_post(url: str, data: dict, timeout: int = 10) -> dict | None:
    """Simple HTTP POST without external dependencies."""
    try:
        body    = json.dumps(data).encode("utf-8")
        req     = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        return None
    except Exception:
        return None


def _http_get(url: str, timeout: int = 10) -> dict | None:
    """Simple HTTP GET without external dependencies."""
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "depwise/0.1"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def check_osv(name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """
    Query OSV API for known vulnerabilities.
    Returns list of vulnerability dicts.
    """
    if not version:
        # Query without version — get all known vulns for this package
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
    else:
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem}
        }

    result = _http_post(f"{OSV_API}/query", payload)
    if not result:
        return []

    vulns = []
    for vuln in result.get("vulns", []):
        # Extract the most useful fields
        vuln_id   = vuln.get("id", "")
        summary   = vuln.get("summary", "")
        details   = vuln.get("details", "")
        aliases   = vuln.get("aliases", [])
        severity  = _extract_severity(vuln)
        fixed_in  = _extract_fixed_version(vuln, name)
        published = vuln.get("published", "")

        vulns.append({
            "id":        vuln_id,
            "aliases":   aliases,
            "summary":   summary or details[:100] if details else "No description",
            "severity":  severity,
            "fixed_in":  fixed_in,
            "published": published,
        })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda v: severity_order.get(v["severity"], 4))

    return vulns


def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity from a vulnerability."""
    # Check CVSS scores
    for severity_entry in vuln.get("severity", []):
        score_type = severity_entry.get("type", "")
        score      = severity_entry.get("score", "")

        if "CVSS" in score_type and score:
            # Parse CVSS vector for severity
            if "AV:N" in score and ("C:H" in score or "I:H" in score or "A:H" in score):
                return "HIGH"
            if score.startswith("CVSS:3"):
                return "MEDIUM"

    # Check database specific fields
    db_specific = vuln.get("database_specific", {})
    severity    = db_specific.get("severity", "")
    if severity:
        return severity.upper()

    return "UNKNOWN"


def _extract_fixed_version(vuln: dict, package_name: str) -> str:
    """Extract the fixed version from a vulnerability."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue

        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed

    return ""


def check_abandonment(name: str, ecosystem: str = "PyPI") -> dict:
    """
    Check if a package appears abandoned.
    Uses PyPI JSON API for Python packages.
    Returns {abandoned, days_since_update, reason}
    """
    result = {
        "abandoned":          False,
        "days_since_update":  None,
        "reason":             "",
        "deprecated":         False,
    }

    # Check known abandoned list first
    if name.lower() in KNOWN_ABANDONED:
        result["abandoned"] = True
        result["reason"]    = KNOWN_ABANDONED[name.lower()]
        result["deprecated"] = True
        return result

    if ecosystem == "PyPI":
        data = _http_get(f"https://pypi.org/pypi/{name}/json")
        if not data:
            return result

        info = data.get("info", {})

        # Check if explicitly marked as deprecated/inactive
        classifiers = info.get("classifiers", [])
        for classifier in classifiers:
            if "Inactive" in classifier or "Abandoned" in classifier:
                result["abandoned"]  = True
                result["deprecated"] = True
                result["reason"]     = "Marked as inactive/abandoned by maintainer"
                return result

        # Check last release date
        releases = data.get("releases", {})
        if releases:
            latest_date = _get_latest_release_date(releases)
            if latest_date:
                days = (datetime.now(timezone.utc) - latest_date).days
                result["days_since_update"] = days

                if days > 1095:  # 3 years
                    result["abandoned"] = True
                    result["reason"]    = f"No updates in {days // 365} years"
                elif days > 730:  # 2 years
                    result["reason"] = f"No updates in {days // 365} years (watch)"

        # Check if package has a deprecation notice in description
        description = (info.get("description") or "").lower()
        deprecated_signals = [
            "this package is deprecated",
            "no longer maintained",
            "use instead",
            "has been abandoned",
            "not maintained",
            "archived",
        ]
        for signal in deprecated_signals:
            if signal in description:
                result["abandoned"]  = True
                result["deprecated"] = True
                result["reason"]     = "Deprecation notice found in package description"
                break

    elif ecosystem == "npm":
        data = _http_get(f"https://registry.npmjs.org/{name}")
        if not data:
            return result

        # Check if deprecated
        dist_tags = data.get("dist-tags", {})
        latest    = dist_tags.get("latest", "")
        if latest:
            version_data = data.get("versions", {}).get(latest, {})
            if version_data.get("deprecated"):
                result["abandoned"]  = True
                result["deprecated"] = True
                result["reason"]     = version_data["deprecated"]
                return result

        # Check last publish date
        time_data = data.get("time", {})
        if "modified" in time_data:
            try:
                modified = datetime.fromisoformat(
                    time_data["modified"].replace("Z", "+00:00")
                )
                days = (datetime.now(timezone.utc) - modified).days
                result["days_since_update"] = days
                if days > 1095:
                    result["abandoned"] = True
                    result["reason"]    = f"No updates in {days // 365} years"
            except Exception:
                pass

    return result


def _get_latest_release_date(releases: dict) -> datetime | None:
    """Get the date of the most recent release."""
    latest = None
    for version, files in releases.items():
        for f in files:
            upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not upload_time:
                continue
            try:
                dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if latest is None or dt > latest:
                    latest = dt
            except Exception:
                continue
    return latest


def check_package(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Full check for a single package.
    Returns complete health report.
    """
    result = {
        "name":        name,
        "version":     version,
        "ecosystem":   ecosystem,
        "vulns":       [],
        "abandonment": {},
        "unpinned":    not version or version == "",
        "status":      "ok",  # ok, vulnerable, abandoned, unpinned
        "worst_severity": "NONE",
        "fix":         "",
        "summary":     "",
    }

    # Check vulnerabilities
    vulns = check_osv(name, version, ecosystem)
    result["vulns"] = vulns

    # Check abandonment
    abandonment = check_abandonment(name, ecosystem)
    result["abandonment"] = abandonment

    # Determine overall status
    if abandonment.get("abandoned"):
        result["status"] = "abandoned"

    if vulns:
        severities = [v["severity"] for v in vulns]
        if "CRITICAL" in severities:
            result["worst_severity"] = "CRITICAL"
            result["status"] = "vulnerable"
        elif "HIGH" in severities:
            result["worst_severity"] = "HIGH"
            result["status"] = "vulnerable"
        elif "MEDIUM" in severities:
            result["worst_severity"] = "MEDIUM"
            result["status"] = "vulnerable"
        else:
            result["worst_severity"] = "LOW"
            result["status"] = "vulnerable"

        # Get fix version from worst vuln
        result["fix"] = vulns[0].get("fixed_in", "")

        # Build plain english summary
        result["summary"] = vulns[0].get("summary", "")

    elif abandonment.get("abandoned"):
        result["summary"] = abandonment.get("reason", "")

    elif not version:
        result["status"]  = "unpinned"
        result["summary"] = "Version not pinned — cannot audit"

    return result


def check_all(packages: list[dict], ecosystem: str = "PyPI") -> list[dict]:
    """
    Check all packages. Returns results sorted by severity.
    Adds small delay between requests to be polite to OSV API.
    """
    results = []
    for i, pkg in enumerate(packages):
        name    = pkg.get("name", "")
        version = pkg.get("version", "")
        eco     = pkg.get("ecosystem", ecosystem)

        if not name:
            continue

        result = check_package(name, version, eco)
        results.append(result)

        # Small delay every 10 packages
        if i > 0 and i % 10 == 0:
            time.sleep(0.5)

    # Sort: vulnerable first, then abandoned, then unpinned, then ok
    status_order = {"vulnerable": 0, "abandoned": 1, "unpinned": 2, "ok": 3}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

    results.sort(key=lambda r: (
        status_order.get(r["status"], 3),
        severity_order.get(r["worst_severity"], 4)
    ))

    return results
