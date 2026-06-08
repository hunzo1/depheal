"""
scanner.py — reads dependency files and detects active environment
"""

import os
import re
import sys
import subprocess
from pathlib import Path


def find_dependency_files(directory: str = ".") -> dict:
    """
    Find all dependency files in a directory.
    Returns dict of {type: path}
    """
    root = Path(directory).resolve()
    found = {}

    candidates = {
        "requirements.txt":     root / "requirements.txt",
        "requirements-dev.txt": root / "requirements-dev.txt",
        "requirements-prod.txt":root / "requirements-prod.txt",
        "pyproject.toml":       root / "pyproject.toml",
        "setup.py":             root / "setup.py",
        "Pipfile":              root / "Pipfile",
        "package.json":         root / "package.json",
        "package-lock.json":    root / "package-lock.json",
    }

    for name, path in candidates.items():
        if path.exists():
            found[name] = str(path)

    return found


def detect_active_venv() -> str | None:
    """
    Detect the active virtual environment Python interpreter.
    Returns path to python executable or None if no venv active.
    """
    # Check VIRTUAL_ENV env variable (set by activate)
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        python = Path(venv) / "bin" / "python3"
        if python.exists():
            return str(python)
        python = Path(venv) / "bin" / "python"
        if python.exists():
            return str(python)

    # Check CONDA_PREFIX
    conda = os.environ.get("CONDA_PREFIX")
    if conda:
        python = Path(conda) / "bin" / "python3"
        if python.exists():
            return str(python)

    return None


def get_installed_packages(python_path: str = None) -> list[dict]:
    """
    Get list of installed packages from the correct Python environment.
    Returns list of {name, version}
    """
    if python_path is None:
        python_path = detect_active_venv() or sys.executable

    try:
        result = subprocess.run(
            [python_path, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return []

        import json
        packages = json.loads(result.stdout)
        return [{"name": p["name"], "version": p["version"]} for p in packages]

    except Exception:
        return []


def parse_requirements_txt(filepath: str) -> list[dict]:
    """
    Parse requirements.txt file.
    Returns list of {name, version, pinned}
    """
    packages = []
    path = Path(filepath)
    if not path.exists():
        return packages

    with open(filepath, "r") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith("-r"):
            continue

        # Remove inline comments
        line = line.split("#")[0].strip()

        # Parse version specifier
        # Handles: package==1.0, package>=1.0, package~=1.0, package
        match = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([A-Za-z0-9_\-\.]+)?",
            line
        )

        if match:
            name    = match.group(1)
            op      = match.group(2) or ""
            version = match.group(3) or ""
            pinned  = op == "=="
            packages.append({
                "name":    name,
                "version": version,
                "pinned":  pinned,
                "op":      op,
            })
        elif re.match(r"^[A-Za-z0-9_\-\.]+$", line):
            packages.append({
                "name":    line,
                "version": "",
                "pinned":  False,
                "op":      "",
            })

    return packages


def parse_pyproject_toml(filepath: str) -> list[dict]:
    """
    Parse pyproject.toml for dependencies.
    Returns list of {name, version, pinned}
    """
    packages = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return packages

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return packages

    # PEP 621 style: [project] dependencies
    deps = (
        data.get("project", {}).get("dependencies", []) or
        data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    )

    if isinstance(deps, list):
        for dep in deps:
            match = re.match(
                r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)?\s*([A-Za-z0-9_\-\.]+)?",
                dep.strip()
            )
            if match:
                packages.append({
                    "name":    match.group(1),
                    "version": match.group(3) or "",
                    "pinned":  match.group(2) == "==",
                    "op":      match.group(2) or "",
                })

    elif isinstance(deps, dict):
        for name, version in deps.items():
            if name == "python":
                continue
            if isinstance(version, str):
                version = version.lstrip("^~>=<!")
            else:
                version = ""
            packages.append({
                "name":    name,
                "version": version,
                "pinned":  False,
                "op":      "",
            })

    return packages


def parse_package_json(filepath: str) -> list[dict]:
    """
    Parse package.json for npm dependencies.
    Returns list of {name, version, pinned, dev}
    """
    packages = []
    try:
        import json
        with open(filepath) as f:
            data = json.load(f)
    except Exception:
        return packages

    for dep_type in ["dependencies", "devDependencies"]:
        is_dev = dep_type == "devDependencies"
        for name, version in data.get(dep_type, {}).items():
            clean_version = version.lstrip("^~>=<!")
            packages.append({
                "name":    name,
                "version": clean_version,
                "pinned":  not version.startswith(("^", "~", ">=", "*")),
                "op":      version[0] if version and version[0] in "^~" else "",
                "dev":     is_dev,
                "ecosystem": "npm",
            })

    return packages


def scan_directory(directory: str = ".") -> dict:
    """
    Full scan of a directory.
    Returns everything the checker needs.
    """
    result = {
        "directory":   str(Path(directory).resolve()),
        "venv":        detect_active_venv(),
        "files":       {},
        "packages":    [],
        "ecosystem":   "PyPI",
        "errors":      [],
    }

    # Find dependency files
    files = find_dependency_files(directory)
    result["files"] = files

    if not files:
        result["errors"].append("No dependency files found.")
        return result

    # Parse packages from files
    parsed = []

    if "requirements.txt" in files:
        parsed.extend(parse_requirements_txt(files["requirements.txt"]))

    elif "pyproject.toml" in files:
        parsed.extend(parse_pyproject_toml(files["pyproject.toml"]))

    if "package.json" in files:
        npm_packages = parse_package_json(files["package.json"])
        if npm_packages:
            parsed.extend(npm_packages)
            result["ecosystem"] = "mixed"

    # If we have a venv, get installed versions for packages
    # that weren't pinned in the requirements file
    if result["venv"] and parsed:
        installed = {
            p["name"].lower(): p["version"]
            for p in get_installed_packages(result["venv"])
        }
        for pkg in parsed:
            if not pkg.get("version") and pkg["name"].lower() in installed:
                pkg["version"] = installed[pkg["name"].lower()]

    result["packages"] = parsed
    return result
