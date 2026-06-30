#!/usr/bin/env python3
"""Mirror the tracked kernel package to its HF model repo.

governed-inference-meter is an HF `kernels` library: consumers load it via
`get_kernel("SZLHOLDINGS/governed-inference-meter")`, which resolves the compiled
tree from the HF model repo of the same name. GitHub is the source-of-truth; this
pushes the tracked package files there on tag/release so the Kernel Hub copy can
never silently lag the repo. Build artifacts (build/, build.toml), packaging
(pyproject.toml), docs (README/LICENSE) and tests are mirrored; CI/VCS cruft is not.
"""
from __future__ import annotations

import argparse
import sys

from huggingface_hub import HfApi

# Paths NOT part of the published kernel. .gitattributes IS mirrored (LFS config).
IGNORE = [".git/*", ".github/*", "scripts/*", ".gitignore", "*/__pycache__/*", "*.pyc"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--repo-id", default="SZLHOLDINGS/governed-inference-meter")
    ap.add_argument("--token", required=True)
    ap.add_argument("--commit-message", default="mirror: sync kernel from GitHub source-of-truth")
    args = ap.parse_args()

    api = HfApi(token=args.token)
    api.upload_folder(
        repo_id=args.repo_id,
        repo_type="model",
        folder_path=args.repo_root,
        ignore_patterns=IGNORE,
        commit_message=args.commit_message,
    )
    print(f"Mirrored {args.repo_root} -> model/{args.repo_id}")


if __name__ == "__main__":
    main()
    sys.exit(0)
