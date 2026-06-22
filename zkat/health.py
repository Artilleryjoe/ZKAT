"""Repository and runtime health checks for ZKAT."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class HealthCheck:
    """Result from one health check."""

    name: str
    status: str
    detail: str


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_MODULES = ("lxml", "git", "dateutil", "packaging")
OPTIONAL_MODULES = ("jsonschema", "oqs")


def _status(ok: bool) -> str:
    return "ok" if ok else "fail"


def _module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _check_python_version() -> HealthCheck:
    ok = sys.version_info >= (3, 11)
    version = ".".join(str(part) for part in sys.version_info[:3])
    return HealthCheck("python", _status(ok), f"Python {version}; requires >=3.11")


def _check_required_modules() -> HealthCheck:
    missing = [module for module in REQUIRED_MODULES if not _module_available(module)]
    if missing:
        return HealthCheck("required-modules", "fail", f"Missing: {', '.join(missing)}")
    return HealthCheck("required-modules", "ok", f"Available: {', '.join(REQUIRED_MODULES)}")


def _check_optional_modules() -> HealthCheck:
    missing = [module for module in OPTIONAL_MODULES if not _module_available(module)]
    if missing:
        return HealthCheck("optional-modules", "warn", f"Missing optional modules: {', '.join(missing)}")
    return HealthCheck("optional-modules", "ok", f"Available: {', '.join(OPTIONAL_MODULES)}")


def _check_schema() -> HealthCheck:
    schema_path = PROJECT_ROOT / "zkat" / "schema" / "attestation.schema.json"
    try:
        with schema_path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return HealthCheck("schema", "fail", f"Unable to load attestation schema: {exc}")
    if not schema.get("$schema") or schema.get("type") != "object":
        return HealthCheck("schema", "fail", "Attestation schema is missing required top-level metadata")
    return HealthCheck("schema", "ok", str(schema_path))


def _check_program_id() -> HealthCheck:
    program_path = PROJECT_ROOT / "zkat" / "zk" / "artifacts" / "program_id.txt"
    try:
        value = program_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return HealthCheck("zk-program-id", "fail", f"Unable to read program id: {exc}")
    if not value:
        return HealthCheck("zk-program-id", "fail", "Program id is empty")
    if "placeholder" in value.lower():
        return HealthCheck("zk-program-id", "warn", "Prototype placeholder program id is still configured")
    return HealthCheck("zk-program-id", "ok", value)


def _check_nmap_binary(nmap_binary: str) -> HealthCheck:
    resolved = shutil.which(nmap_binary)
    if resolved is None:
        return HealthCheck("nmap", "warn", f"{nmap_binary!r} not found; --nmap-xml fixture mode remains available")
    return HealthCheck("nmap", "ok", resolved)


def _check_git_repository(root: Path) -> HealthCheck:
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        return HealthCheck("git", "fail", "Project root is not inside a Git work tree")
    return HealthCheck("git", "ok", "Project root is inside a Git work tree")


def run_health_checks(*, nmap_binary: str = "nmap", root: Path = PROJECT_ROOT) -> list[HealthCheck]:
    """Run local health checks without mutating repository state."""

    return [
        _check_python_version(),
        _check_required_modules(),
        _check_optional_modules(),
        _check_schema(),
        _check_program_id(),
        _check_nmap_binary(nmap_binary),
        _check_git_repository(root),
    ]


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ZKAT health checks")
    parser.add_argument("--nmap-binary", default="nmap", help="nmap executable name or path to check")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    checks = run_health_checks(nmap_binary=args.nmap_binary)
    if args.json:
        print(json.dumps([asdict(check) for check in checks], indent=2))
    else:
        for check in checks:
            print(f"{check.status.upper():4} {check.name}: {check.detail}")

    if any(check.status == "fail" for check in checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
