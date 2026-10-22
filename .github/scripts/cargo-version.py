"""Prints the version a Cargo manifest declares - the version its binaries report."""

import sys
import tomllib
from pathlib import Path


def declared_version(manifest: dict[str, object]) -> str:
    package = manifest.get("package", {})
    workspace_package = manifest.get("workspace", {}).get("package", {})
    version = package.get("version") if isinstance(package, dict) else None
    # Ex: `version.workspace = true` -> the `[workspace.package]` version; a virtual
    #     workspace manifest has only `[workspace.package]`.
    if version is None or isinstance(version, dict):
        version = workspace_package.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit("The manifest declares no package or workspace.package version")
    return version


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: cargo-version.py <Cargo.toml>")
    manifest = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    # Why print: the version is this script's data output, captured by the workflow.
    print(declared_version(manifest))


if __name__ == "__main__":
    main()
