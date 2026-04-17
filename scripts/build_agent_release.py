#!/usr/bin/env python3
"""Build signed HostWatch agent release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path


RELEASE_FILES = (
    "hostwatch_agent.py",
    "install.sh",
    "release_signing_public.pem",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build HostWatch agent release assets.")
    parser.add_argument("--version", required=True, help="Release version, for example 2026.4.1")
    parser.add_argument("--repo", required=True, help="GitHub repository in owner/name form")
    parser.add_argument("--output-dir", required=True, help="Output directory for release assets")
    parser.add_argument("--release-notes-file", help="Path to a markdown file with release notes")
    parser.add_argument("--minimum-agent-version", help="Minimum supported current agent version")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    agent_dir = repo_root / "agent"
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    tarball_name = f"hostwatch-agent-{args.version}.tar.gz"
    manifest_name = f"hostwatch-agent-manifest-{args.version}.json"
    tarball_path = output_dir / tarball_name
    manifest_path = output_dir / manifest_name

    with tarfile.open(tarball_path, "w:gz") as archive:
        for filename in RELEASE_FILES:
            archive.add(agent_dir / filename, arcname=filename)

    sha256 = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
    release_notes = ""
    if args.release_notes_file:
        release_notes = Path(args.release_notes_file).read_text(encoding="utf8")

    manifest = {
        "schema": 1,
        "project": "HostWatch",
        "artifact_type": "agent",
        "version": args.version,
        "published_at": datetime.now(timezone.utc).isoformat(),
        "minimum_agent_version": args.minimum_agent_version,
        "breaking_update": False,
        "artifact": {
            "filename": tarball_name,
            "sha256": sha256,
            "size": tarball_path.stat().st_size,
            "url": f"https://github.com/{args.repo}/releases/download/{args.version}/{tarball_name}",
        },
        "release_notes": release_notes,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
