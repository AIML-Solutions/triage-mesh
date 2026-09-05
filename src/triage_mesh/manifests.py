"""Manifest parsing: repo files in, typed PackageCoordinates out.

Pure functions, used by the repo-reader MCP server. Manifest content is
untrusted (threat T2): anything that doesn't parse as an exact pin is skipped,
never guessed at.
"""

from __future__ import annotations

import json
import re

from triage_mesh.schemas import Ecosystem, PackageCoordinate

# Exact pins only ("name==1.2.3"), optionally with extras. Ranges, editable
# installs, URLs, and anything else are ignored: the inventory only claims
# what it can pin to a version.
_REQUIREMENT_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[A-Za-z0-9.!+*-]+)\s*(?:;.*)?$"
)


def parse_requirements_txt(content: str) -> list[PackageCoordinate]:
    packages: list[PackageCoordinate] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _REQUIREMENT_PIN.match(line)
        if match:
            packages.append(
                PackageCoordinate(
                    ecosystem=Ecosystem.PYPI,
                    name=match.group("name").lower(),
                    version=match.group("version"),
                )
            )
    return packages


def parse_package_lock(content: str) -> list[PackageCoordinate]:
    """npm package-lock.json, lockfileVersion 2/3 ("packages" map)."""
    try:
        lock = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages_map = lock.get("packages")
    if not isinstance(packages_map, dict):
        return []

    packages: list[PackageCoordinate] = []
    for path, entry in packages_map.items():
        if path == "" or not isinstance(entry, dict):
            continue  # "" is the root project itself
        version = entry.get("version")
        # "node_modules/@scope/name" -> "@scope/name"
        name = path.rpartition("node_modules/")[2]
        if not name or not isinstance(version, str):
            continue
        packages.append(
            PackageCoordinate(ecosystem=Ecosystem.NPM, name=name, version=version)
        )
    return packages


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package-lock.json": parse_package_lock,
}


def parse_manifest(filename: str, content: str) -> list[PackageCoordinate]:
    parser = PARSERS.get(filename)
    return parser(content) if parser else []
