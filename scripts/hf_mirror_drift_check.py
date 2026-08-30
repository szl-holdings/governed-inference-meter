#!/usr/bin/env python3
"""Anonymous immutable-revision verifier for the closed HF mirror payload."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from hf_mirror import (
    HF_ENDPOINT,
    MirrorContractError,
    _load_event,
    build_source_snapshot,
    canonical_json,
    ensure_credentialless,
    validate_verifier_context,
    verify_locked_client,
    verify_remote,
)


def main() -> int:
    try:
        ensure_credentialless(os.environ)
        event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
        if not event_path.is_file():
            raise MirrorContractError("GITHUB_EVENT_PATH is missing")
        revision = validate_verifier_context(os.environ, _load_event(event_path))
        snapshot = build_source_snapshot(Path(__file__).resolve().parents[1], revision)
        verify_locked_client()
        from huggingface_hub import HfApi

        api = HfApi(endpoint=HF_ENDPOINT, token=False)
        report = verify_remote(api, api.hf_hub_download, snapshot)
        print(canonical_json(report).decode("utf-8"), end="")
        return 0
    except Exception as exc:  # noqa: BLE001 - authoritative fail-closed CLI boundary
        print(f"HF_MIRROR_DRIFT_FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
