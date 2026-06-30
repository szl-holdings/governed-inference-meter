#!/usr/bin/env python3
"""Drift guard: hash the mirrored kernel tree vs the live HF model repo.

Computes the exact set of files `hf_mirror.py` would push (repo minus VCS/CI cruft),
fetches each from the model's `resolve/main/<path>` URL, and asserts sha256 equality.
Mismatch / missing-live fails the job. Stdlib only (public model repo). This is the
digest-level proof that the Kernel Hub copy equals the GitHub source-of-truth.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import sys
import urllib.request
from pathlib import Path

RESOLVE = "https://huggingface.co/{repo}/resolve/main/{path}"
# Dir components never published to the Kernel Hub; .gitattributes IS kept (LFS).
IGNORE_DIRS = {".git", ".github", "__pycache__", "scripts"}
IGNORE_FILE_GLOBS = [".gitignore", "*.pyc"]


def _ignored(rel: str) -> bool:
    parts = rel.split("/")
    if any(part in IGNORE_DIRS for part in parts):
        return True
    return any(fnmatch.fnmatch(parts[-1], g) for g in IGNORE_FILE_GLOBS)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--repo-id", default="SZLHOLDINGS/governed-inference-meter")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    files = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if _ignored(rel):
            continue
        files.append((rel, p))
    if not files:
        sys.exit("No mirrorable files found.")

    ok = True
    for rel, p in files:
        local = _sha(p.read_bytes())
        url = RESOLVE.format(repo=args.repo_id, path=rel)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                live = _sha(r.read())
        except Exception as e:  # noqa: BLE001
            print(f"MISSING-LIVE  {rel}  ({e})")
            ok = False
            continue
        status = "OK" if local == live else "MISMATCH"
        if status != "OK":
            ok = False
        print(f"{local[:16]}  {live[:16]}  {status}  {rel}")

    if not ok:
        sys.exit("Drift detected: HF model != GitHub mirror set. Run hf-mirror (tag a release).")
    print(f"\nAll {len(files)} files aligned: model/{args.repo_id} == GitHub source.")


if __name__ == "__main__":
    main()
