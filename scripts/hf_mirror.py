#!/usr/bin/env python3
"""Publish the closed legacy Kernel payload and verify its immutable HF revision.

The publisher is intentionally narrower than a generic ``upload_folder`` helper:
it accepts only a protected-main Git tree, publishes an explicit compatibility
payload with one generated canonical manifest, uses a parent-commit CAS, and
performs anonymous byte-for-byte readback of the returned immutable revision.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SOURCE_REPOSITORY = "szl-holdings/governed-inference-meter"
SOURCE_REF = "refs/heads/main"
SOURCE_BRANCH = "main"
HF_REPOSITORY = "SZLHOLDINGS/governed-inference-meter"
HF_REPO_TYPE = "model"
HF_ENDPOINT = "https://huggingface.co"
HF_CLIENT_VERSION = "1.29.0"
PUBLISH_EVENT = "repository_dispatch"
PUBLISH_ACTION = "hf-mirror-source-bound"
PUBLISH_WORKFLOW_PATH = ".github/workflows/hf-mirror.yml"
DRIFT_WORKFLOW_PATH = ".github/workflows/hf-mirror-drift-check.yml"
MANIFEST_PATH = ".szl-hf-mirror-manifest.json"
MANIFEST_SCHEMA = "szl.hf-mirror.closed-manifest/v1"
HASH_ALGORITHM = "sha256"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_EVENT_BYTES = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

# Complete reviewed compatibility payload. Control-plane additions can never
# silently become executable Hub content.
MIRROR_PATHS = (
    ".devcontainer/devcontainer.json",
    ".editorconfig",
    ".gitattributes",
    "AGENTS.md",
    "CLAUDE.md",
    "DEPRECATED.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "build.toml",
    "build/torch-universal/governed_inference_meter/__init__.py",
    "build/torch-universal/governed_inference_meter/_attest.py",
    "build/torch-universal/governed_inference_meter/_energy.py",
    "build/torch-universal/governed_inference_meter/_policy.py",
    "build/torch-universal/governed_inference_meter/_receipt.py",
    "build/torch-universal/governed_inference_meter/_spine.py",
    "build/torch-universal/governed_inference_meter/metadata.json",
    "pyproject.toml",
    "tests/test_attest.py",
    "tests/test_chain_hardening.py",
    "tests/test_meter.py",
    "tests/test_signing.py",
    "tests/test_spine.py",
)

# Estate governance owns this sidecar independently. It is admitted as one
# exact record and is never overwritten or deleted by this publisher.
EXTERNAL_OWNED = {
    "SZL_ESTATE_MANAGED.json": {
        "schema": "szl.hf-estate-managed/v1",
        "generation": "3c20fe2a6b0c9c56a045265b194a81e952fc949c",
        "size": 690,
        "sha256": "ea8e342de738884b268386f96e4eb2554e13e3d5cc0b3b089e6b16ac3c429b63",
    }
}

# Only manifest-less state admitted for the one-time migration.
LEGACY_HF_REVISION = "52ef72dc6a92aab88d3a50cecb41ddcad941da88"
TOKEN_ENV_NAMES = (
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "HUGGINGFACE_TOKEN",
    "HUGGINGFACEHUB_API_TOKEN",
)


class MirrorContractError(RuntimeError):
    """A source, transaction, or immutable-readback invariant failed."""


@dataclass(frozen=True)
class SourceSnapshot:
    revision: str
    tree: str
    files: tuple[dict[str, Any], ...]
    payload: Mapping[str, bytes]
    manifest: Mapping[str, Any]
    manifest_bytes: bytes


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MirrorContractError(message)


def _validate_sha(value: Any, field: str) -> str:
    _require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{field} must be lowercase 40-hex")
    return value


def _validate_digest(value: Any, field: str) -> str:
    _require(isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None, f"{field} must be lowercase sha256")
    return value


def _validate_path(value: Any) -> str:
    _require(isinstance(value, str) and value != "", "path must be a non-empty string")
    _require(unicodedata.normalize("NFC", value) == value, f"path is not NFC: {value!r}")
    _require(not value.startswith(("/", "\\")), f"absolute/UNC path rejected: {value!r}")
    _require(re.match(r"^[A-Za-z]:", value) is None, f"drive path rejected: {value!r}")
    _require("\\" not in value and "%" not in value, f"encoded or backslash path rejected: {value!r}")
    _require("//" not in value, f"repeated separator rejected: {value!r}")
    _require(all(ord(ch) >= 0x20 and ord(ch) != 0x7F for ch in value), f"control character in path: {value!r}")
    parts = value.split("/")
    _require(all(part not in {"", ".", ".."} for part in parts), f"traversal path rejected: {value!r}")
    _require(all(not part.endswith((".", " ")) for part in parts), f"ambiguous trailing path character: {value!r}")
    return value


def _validate_path_set(paths: Sequence[Any], expected: Sequence[str] | None = None) -> tuple[str, ...]:
    normalized = tuple(_validate_path(path) for path in paths)
    _require(tuple(sorted(normalized)) == normalized, "paths must be deterministically sorted")
    _require(len(set(normalized)) == len(normalized), "duplicate path")
    _require(len({path.casefold() for path in normalized}) == len(normalized), "case-colliding path")
    if expected is not None:
        _require(normalized == tuple(expected), "manifest path set differs from protected policy")
    return normalized


def canonical_json(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MirrorContractError("value is not canonical JSON") from exc
    return encoded + b"\n"


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MirrorContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: bytes, *, require_canonical: bool = False) -> Any:
    _require(len(raw) <= MAX_MANIFEST_BYTES, "JSON document exceeds size limit")
    _require(not raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM rejected")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_float=lambda _value: (_ for _ in ()).throw(MirrorContractError("floating point JSON rejected")),
            parse_constant=lambda _value: (_ for _ in ()).throw(MirrorContractError("non-finite JSON rejected")),
        )
    except MirrorContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MirrorContractError("invalid UTF-8 JSON") from exc
    if require_canonical:
        _require(raw == canonical_json(value), "manifest bytes are not canonical JSON")
    return value


def _closed_object(value: Any, keys: set[str], field: str) -> Mapping[str, Any]:
    _require(isinstance(value, dict), f"{field} must be an object")
    _require(set(value) == keys, f"{field} has missing or unknown fields")
    return value


def _artifact_root(files: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(b"szl.hf-mirror.files.v1\0" + canonical_json(list(files))).hexdigest()


def _git(args: Sequence[str], repo_root: Path) -> bytes:
    executable = os.environ.get("GIT_EXECUTABLE", "git")
    process = subprocess.run(
        [executable, *args],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise MirrorContractError(f"git {' '.join(args)} failed: {detail}")
    return process.stdout


def _parse_tree(raw: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError) as exc:
            raise MirrorContractError("malformed Git tree entry") from exc
        _validate_path(path)
        _require(path not in entries, f"duplicate Git path: {path}")
        entries[path] = (mode, object_type, oid)
    return entries


def build_source_snapshot(repo_root: Path, revision: str) -> SourceSnapshot:
    revision = _validate_sha(revision, "source revision")
    root = repo_root.resolve()
    head = _git(["rev-parse", "HEAD"], root).decode("ascii").strip()
    _require(head == revision, "checked-out HEAD differs from admitted source revision")
    _require(_git(["status", "--porcelain=v1", "--untracked-files=all"], root) == b"", "source tree is dirty")
    tree = _validate_sha(
        _git(["rev-parse", f"{revision}^{{tree}}"], root).decode("ascii").strip(),
        "source tree",
    )
    entries = _parse_tree(_git(["ls-tree", "-r", "-z", "--full-tree", revision], root))
    payload: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []
    total = 0
    for path in MIRROR_PATHS:
        entry = entries.get(path)
        _require(entry is not None, f"required mirror path missing: {path}")
        mode, object_type, _oid = entry
        _require(mode == "100644" and object_type == "blob", f"non-regular Git object rejected: {path}")
        data = _git(["cat-file", "blob", f"{revision}:{path}"], root)
        _require(len(data) <= MAX_FILE_BYTES, f"mirror file exceeds size limit: {path}")
        total += len(data)
        _require(total <= MAX_TOTAL_BYTES, "mirror payload exceeds aggregate size limit")
        payload[path] = data
        records.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    _validate_path_set([record["path"] for record in records], MIRROR_PATHS)
    manifest: dict[str, Any] = {
        "aggregate_sha256": _artifact_root(records),
        "artifact_count": len(records),
        "external_owned": EXTERNAL_OWNED,
        "files": records,
        "hash_algorithm": HASH_ALGORITHM,
        "schema": MANIFEST_SCHEMA,
        "source": {"ref": SOURCE_REF, "repository": SOURCE_REPOSITORY, "revision": revision, "tree": tree},
        "target": {"repository": HF_REPOSITORY, "repository_type": HF_REPO_TYPE},
        "workflow": {"path": PUBLISH_WORKFLOW_PATH, "repository": SOURCE_REPOSITORY, "revision": revision},
    }
    manifest_bytes = canonical_json(manifest)
    validate_manifest(manifest_bytes, expected=manifest)
    return SourceSnapshot(revision, tree, tuple(records), payload, manifest, manifest_bytes)


def validate_manifest(raw: bytes, *, expected: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    value = strict_json_loads(raw, require_canonical=True)
    manifest = _closed_object(
        value,
        {
            "aggregate_sha256",
            "artifact_count",
            "external_owned",
            "files",
            "hash_algorithm",
            "schema",
            "source",
            "target",
            "workflow",
        },
        "manifest",
    )
    _require(manifest["schema"] == MANIFEST_SCHEMA, "unknown manifest schema")
    _require(manifest["hash_algorithm"] == HASH_ALGORITHM, "manifest algorithm must be sha256")
    source = _closed_object(manifest["source"], {"ref", "repository", "revision", "tree"}, "source")
    _require(source["repository"] == SOURCE_REPOSITORY and source["ref"] == SOURCE_REF, "wrong source binding")
    _validate_sha(source["revision"], "manifest source revision")
    _validate_sha(source["tree"], "manifest source tree")
    workflow = _closed_object(manifest["workflow"], {"path", "repository", "revision"}, "workflow")
    _require(
        workflow
        == {"path": PUBLISH_WORKFLOW_PATH, "repository": SOURCE_REPOSITORY, "revision": source["revision"]},
        "wrong workflow binding",
    )
    target = _closed_object(manifest["target"], {"repository", "repository_type"}, "target")
    _require(target == {"repository": HF_REPOSITORY, "repository_type": HF_REPO_TYPE}, "wrong target binding")
    _require(manifest["external_owned"] == EXTERNAL_OWNED, "external-owned policy mismatch")
    _require(isinstance(manifest["artifact_count"], int) and not isinstance(manifest["artifact_count"], bool), "invalid artifact count")
    _require(manifest["artifact_count"] == len(MIRROR_PATHS), "artifact count mismatch")
    _require(isinstance(manifest["files"], list), "files must be an array")
    _require(len(manifest["files"]) == len(MIRROR_PATHS), "file count mismatch")
    paths: list[str] = []
    total = 0
    for index, raw_record in enumerate(manifest["files"]):
        record = _closed_object(raw_record, {"path", "sha256", "size"}, f"files[{index}]")
        paths.append(_validate_path(record["path"]))
        _validate_digest(record["sha256"], f"files[{index}].sha256")
        _require(isinstance(record["size"], int) and not isinstance(record["size"], bool), "file size must be integer")
        _require(0 <= record["size"] <= MAX_FILE_BYTES, "file size outside bounds")
        total += record["size"]
    _require(total <= MAX_TOTAL_BYTES, "manifest aggregate size exceeds limit")
    _validate_path_set(paths, MIRROR_PATHS)
    _validate_digest(manifest["aggregate_sha256"], "aggregate_sha256")
    _require(manifest["aggregate_sha256"] == _artifact_root(manifest["files"]), "aggregate digest mismatch")
    if expected is not None:
        _require(manifest == expected, "manifest differs from exact source snapshot")
    return manifest


def _load_event(path: Path) -> Mapping[str, Any]:
    raw = path.read_bytes()
    _require(len(raw) <= MAX_EVENT_BYTES, "event document exceeds size limit")
    value = strict_json_loads(raw, require_canonical=False)
    _require(isinstance(value, dict), "event document must be an object")
    return value


def validate_publisher_context(env: Mapping[str, str], event: Mapping[str, Any]) -> str:
    sha = _validate_sha(env.get("GITHUB_SHA"), "GITHUB_SHA")
    _require(env.get("GITHUB_REPOSITORY") == SOURCE_REPOSITORY, "wrong GitHub repository")
    _require(env.get("GITHUB_EVENT_NAME") == PUBLISH_EVENT, "wrong publisher event")
    _require(env.get("GITHUB_REF") == SOURCE_REF, "publisher must run on protected main")
    _require(env.get("GITHUB_WORKFLOW_SHA") == sha, "workflow bytes are not source-commit bound")
    expected_ref = f"{SOURCE_REPOSITORY}/{PUBLISH_WORKFLOW_PATH}@{SOURCE_REF}"
    _require(env.get("GITHUB_WORKFLOW_REF") == expected_ref, "wrong publisher workflow ref")
    _require(event.get("action") == PUBLISH_ACTION, "wrong repository_dispatch action")
    repository = event.get("repository")
    _require(isinstance(repository, dict), "event repository missing")
    _require(repository.get("full_name") == SOURCE_REPOSITORY, "event repository mismatch")
    _require(repository.get("default_branch") == SOURCE_BRANCH, "event default branch mismatch")
    _require(event.get("client_payload") == {}, "publisher client_payload must be empty")
    return sha


def validate_verifier_context(env: Mapping[str, str], event: Mapping[str, Any]) -> str:
    sha = _validate_sha(env.get("GITHUB_SHA"), "GITHUB_SHA")
    _require(env.get("GITHUB_REPOSITORY") == SOURCE_REPOSITORY, "wrong GitHub repository")
    _require(env.get("GITHUB_EVENT_NAME") == "schedule", "live verifier runs only on schedule")
    _require(env.get("GITHUB_REF") == SOURCE_REF, "verifier must run on protected main")
    _require(env.get("GITHUB_WORKFLOW_SHA") == sha, "verifier workflow bytes are not source-commit bound")
    expected_ref = f"{SOURCE_REPOSITORY}/{DRIFT_WORKFLOW_PATH}@{SOURCE_REF}"
    _require(env.get("GITHUB_WORKFLOW_REF") == expected_ref, "wrong verifier workflow ref")
    repository = event.get("repository")
    _require(isinstance(repository, dict), "event repository missing")
    _require(repository.get("full_name") == SOURCE_REPOSITORY, "event repository mismatch")
    _require(repository.get("default_branch") == SOURCE_BRANCH, "event default branch mismatch")
    return sha


def ensure_credentialless(env: Mapping[str, str]) -> None:
    for name in TOKEN_ENV_NAMES:
        _require(not env.get(name), f"credentialless verifier rejects {name}")


def verify_locked_client() -> None:
    try:
        version = importlib.metadata.version("huggingface-hub")
    except importlib.metadata.PackageNotFoundError as exc:
        raise MirrorContractError("locked huggingface-hub distribution is not installed") from exc
    _require(version == HF_CLIENT_VERSION, f"unexpected huggingface-hub version: {version}")


def _repo_sha(api: Any, revision: str | None, token: str | bool) -> str:
    info = api.repo_info(
        HF_REPOSITORY,
        repo_type=HF_REPO_TYPE,
        revision=revision,
        files_metadata=True,
        token=token,
    )
    return _validate_sha(getattr(info, "sha", None), "HF revision")


def _remote_files(api: Any, revision: str, token: str | bool) -> tuple[str, ...]:
    values = api.list_repo_files(HF_REPOSITORY, repo_type=HF_REPO_TYPE, revision=revision, token=token)
    _require(isinstance(values, list), "HF file inventory must be a list")
    paths = tuple(sorted(_validate_path(value) for value in values))
    _require(len(paths) == len(set(paths)), "duplicate HF path")
    _require(len(paths) == len({path.casefold() for path in paths}), "case-colliding HF path")
    return paths


def _download_bytes(
    download_file: Callable[..., Any],
    path: str,
    revision: str,
    token: str | bool,
    limit: int,
) -> bytes:
    result = download_file(
        repo_id=HF_REPOSITORY,
        filename=path,
        repo_type=HF_REPO_TYPE,
        revision=revision,
        token=token,
        force_download=True,
    )
    if isinstance(result, bytes):
        data = result
    else:
        local = Path(result)
        _require(local.is_file(), f"download did not produce a file: {path}")
        with local.open("rb") as handle:
            data = handle.read(limit + 1)
    _require(len(data) <= limit, f"download exceeds byte limit: {path}")
    _require(not data.startswith(b"version https://git-lfs.github.com/spec/v1\n"), f"LFS pointer returned: {path}")
    return data


def verify_remote(
    api: Any,
    download_file: Callable[..., Any],
    snapshot: SourceSnapshot,
    *,
    expected_revision: str | None = None,
) -> Mapping[str, Any]:
    head_before = _repo_sha(api, None, False)
    revision = head_before if expected_revision is None else _validate_sha(expected_revision, "expected HF revision")
    _require(head_before == revision, "HF main does not equal the admitted immutable revision")
    _require(_repo_sha(api, revision, False) == revision, "HF immutable revision readback mismatch")
    expected_paths = tuple(sorted((*MIRROR_PATHS, MANIFEST_PATH, *EXTERNAL_OWNED)))
    _require(_remote_files(api, revision, False) == expected_paths, "HF remote path set is not the closed exact union")
    manifest_bytes = _download_bytes(download_file, MANIFEST_PATH, revision, False, MAX_MANIFEST_BYTES)
    validate_manifest(manifest_bytes, expected=snapshot.manifest)
    _require(manifest_bytes == snapshot.manifest_bytes, "remote manifest bytes differ from source manifest")
    for record in snapshot.files:
        path = record["path"]
        data = _download_bytes(download_file, path, revision, False, record["size"])
        _require(len(data) == record["size"], f"remote size mismatch: {path}")
        _require(hashlib.sha256(data).hexdigest() == record["sha256"], f"remote digest mismatch: {path}")
        _require(data == snapshot.payload[path], f"remote bytes differ from exact Git object: {path}")
    external_report: dict[str, Any] = {}
    for path, record in EXTERNAL_OWNED.items():
        data = _download_bytes(download_file, path, revision, False, record["size"])
        _require(len(data) == record["size"], f"external sidecar size mismatch: {path}")
        _require(hashlib.sha256(data).hexdigest() == record["sha256"], f"external sidecar digest mismatch: {path}")
        external_report[path] = {"sha256": record["sha256"], "size": record["size"]}
    head_after = _repo_sha(api, None, False)
    _require(head_after == revision, "HF main advanced during immutable verification")
    return {
        "external_owned": external_report,
        "hf_revision": revision,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "payload_aggregate_sha256": snapshot.manifest["aggregate_sha256"],
        "source_revision": snapshot.revision,
        "source_tree": snapshot.tree,
        "status": "MIRROR_MANAGED_PAYLOAD_EXACT_READBACK_VERIFIED",
    }


def publish_once(
    snapshot: SourceSnapshot,
    read_api: Any,
    write_api: Any,
    download_file: Callable[..., Any],
    add_factory: Callable[..., Any],
    delete_factory: Callable[..., Any],
    token: str,
) -> Mapping[str, Any]:
    _require(isinstance(token, str) and token.strip() != "", "HF_TOKEN is required for the final publisher step")
    parent = _repo_sha(read_api, None, False)
    current_paths = _remote_files(read_api, parent, False)
    legacy_paths = tuple(sorted((*MIRROR_PATHS, *EXTERNAL_OWNED)))
    if MANIFEST_PATH in current_paths:
        prior_bytes = _download_bytes(download_file, MANIFEST_PATH, parent, False, MAX_MANIFEST_BYTES)
        prior = validate_manifest(prior_bytes)
        managed_paths = tuple(record["path"] for record in prior["files"])
        expected_current = tuple(sorted((*managed_paths, MANIFEST_PATH, *EXTERNAL_OWNED)))
        _require(current_paths == expected_current, "current HF tree contains an unknown or missing path")
        if prior_bytes == snapshot.manifest_bytes:
            return {"operation": "NOOP", **verify_remote(read_api, download_file, snapshot, expected_revision=parent)}
    else:
        _require(parent == LEGACY_HF_REVISION, "manifest-less HF state is not the reviewed migration revision")
        _require(current_paths == legacy_paths, "legacy HF tree differs from the reviewed migration inventory")
        managed_paths = MIRROR_PATHS

    stale = tuple(sorted(set(managed_paths) - set(MIRROR_PATHS)))
    _require(not (set(stale) & set(EXTERNAL_OWNED)), "external-owned path cannot be deleted")
    operations: list[Any] = [delete_factory(path_in_repo=path, is_folder=False) for path in stale]
    operations.extend(add_factory(path_in_repo=path, path_or_fileobj=snapshot.payload[path]) for path in MIRROR_PATHS)
    operations.append(add_factory(path_in_repo=MANIFEST_PATH, path_or_fileobj=snapshot.manifest_bytes))
    commit = write_api.create_commit(
        repo_id=HF_REPOSITORY,
        repo_type=HF_REPO_TYPE,
        revision=SOURCE_BRANCH,
        parent_commit=parent,
        operations=operations,
        commit_message=f"mirror: bind protected source {snapshot.revision}",
        commit_description=(
            f"source={SOURCE_REPOSITORY}@{snapshot.revision}\n"
            f"tree={snapshot.tree}\n"
            f"payload_sha256={snapshot.manifest['aggregate_sha256']}"
        ),
        token=token,
        num_threads=1,
    )
    revision = _validate_sha(getattr(commit, "oid", None), "returned HF commit")
    report = verify_remote(read_api, download_file, snapshot, expected_revision=revision)
    return {"operation": "COMMIT", "parent_revision": parent, **report}


def _safe_error(exc: BaseException, secret: str | None) -> str:
    text = f"{type(exc).__name__}: {exc}"
    if secret:
        text = text.replace(secret, "[REDACTED]")
    return text[:1000]


def main() -> int:
    token: str | None = None
    try:
        event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
        _require(event_path.is_file(), "GITHUB_EVENT_PATH is missing")
        revision = validate_publisher_context(os.environ, _load_event(event_path))
        snapshot = build_source_snapshot(Path(__file__).resolve().parents[1], revision)
        verify_locked_client()
        token = os.environ.get("HF_TOKEN")
        _require(token is not None and token.strip() != "", "HF_TOKEN is absent")
        from huggingface_hub import CommitOperationAdd, CommitOperationDelete, HfApi

        read_api = HfApi(endpoint=HF_ENDPOINT, token=False)
        write_api = HfApi(endpoint=HF_ENDPOINT, token=token)
        report = publish_once(
            snapshot,
            read_api,
            write_api,
            read_api.hf_hub_download,
            CommitOperationAdd,
            CommitOperationDelete,
            token,
        )
        print(canonical_json(report).decode("utf-8"), end="")
        return 0
    except Exception as exc:  # noqa: BLE001 - final fail-closed CLI boundary
        print(f"HF_MIRROR_FAILED: {_safe_error(exc, token)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
