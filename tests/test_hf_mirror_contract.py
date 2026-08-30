#!/usr/bin/env python3
"""Executable fail-closed contract for the HF mirror trust boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hf_mirror as mirror  # noqa: E402

SOURCE_SHA = "a" * 40
SOURCE_TREE = "b" * 40
HF_SHA = "c" * 40
NEXT_HF_SHA = "d" * 40
TOKEN_SENTINEL = "hf_secret_sentinel_never_print"


def snapshot() -> mirror.SourceSnapshot:
    payload = {path: (f"payload:{path}\n").encode() for path in mirror.MIRROR_PATHS}
    records = tuple(
        {"path": path, "sha256": hashlib.sha256(payload[path]).hexdigest(), "size": len(payload[path])}
        for path in mirror.MIRROR_PATHS
    )
    manifest = {
        "aggregate_sha256": mirror._artifact_root(records),
        "artifact_count": len(records),
        "external_owned": mirror.EXTERNAL_OWNED,
        "files": list(records),
        "hash_algorithm": mirror.HASH_ALGORITHM,
        "schema": mirror.MANIFEST_SCHEMA,
        "source": {
            "ref": mirror.SOURCE_REF,
            "repository": mirror.SOURCE_REPOSITORY,
            "revision": SOURCE_SHA,
            "tree": SOURCE_TREE,
        },
        "target": {"repository": mirror.HF_REPOSITORY, "repository_type": mirror.HF_REPO_TYPE},
        "workflow": {
            "path": mirror.PUBLISH_WORKFLOW_PATH,
            "repository": mirror.SOURCE_REPOSITORY,
            "revision": SOURCE_SHA,
        },
    }
    return mirror.SourceSnapshot(SOURCE_SHA, SOURCE_TREE, records, payload, manifest, mirror.canonical_json(manifest))


def publisher_env() -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": mirror.PUBLISH_EVENT,
        "GITHUB_REPOSITORY": mirror.SOURCE_REPOSITORY,
        "GITHUB_REF": mirror.SOURCE_REF,
        "GITHUB_SHA": SOURCE_SHA,
        "GITHUB_WORKFLOW_REF": (
            f"{mirror.SOURCE_REPOSITORY}/{mirror.PUBLISH_WORKFLOW_PATH}@{mirror.SOURCE_REF}"
        ),
        "GITHUB_WORKFLOW_SHA": SOURCE_SHA,
    }


def publisher_event() -> dict[str, object]:
    return {
        "action": mirror.PUBLISH_ACTION,
        "client_payload": {},
        "repository": {"default_branch": mirror.SOURCE_BRANCH, "full_name": mirror.SOURCE_REPOSITORY},
    }


class Add:
    def __init__(self, *, path_in_repo: str, path_or_fileobj: bytes):
        self.path = path_in_repo
        self.data = path_or_fileobj


class Delete:
    def __init__(self, *, path_in_repo: str, is_folder: bool):
        self.path = path_in_repo
        self.is_folder = is_folder


class FakeHub:
    def __init__(self, files: dict[str, bytes], head: str = mirror.LEGACY_HF_REVISION):
        self.head = head
        self.history = {head: dict(files)}
        self.commit_calls: list[dict[str, object]] = []
        self.fail_commit: BaseException | None = None
        self.returned_oid = NEXT_HF_SHA
        self.head_reads: list[str] = []

    def repo_info(self, _repo_id: str, *, revision=None, **_kwargs):
        if revision is None:
            if self.head_reads:
                self.head = self.head_reads.pop(0)
            return SimpleNamespace(sha=self.head)
        if revision not in self.history:
            raise AssertionError(f"unknown revision {revision}")
        return SimpleNamespace(sha=revision)

    def list_repo_files(self, _repo_id: str, *, revision: str, **_kwargs):
        return list(self.history[revision])

    def download(self, *, filename: str, revision: str, token, **_kwargs):
        if token is not False:
            raise AssertionError("readback must be anonymous")
        return self.history[revision][filename]

    def create_commit(self, **kwargs):
        self.commit_calls.append(kwargs)
        if self.fail_commit is not None:
            raise self.fail_commit
        if kwargs["parent_commit"] != self.head:
            raise AssertionError("missing parent CAS")
        new_files = dict(self.history[self.head])
        for operation in kwargs["operations"]:
            if isinstance(operation, Delete):
                new_files.pop(operation.path)
            else:
                new_files[operation.path] = operation.data
        self.head = self.returned_oid
        if re.fullmatch(r"[0-9a-f]{40}", self.returned_oid):
            self.history[self.returned_oid] = new_files
        return SimpleNamespace(oid=self.returned_oid)


def legacy_files(item: mirror.SourceSnapshot) -> dict[str, bytes]:
    files = dict(item.payload)
    files.update({path: b"x" * record["size"] for path, record in mirror.EXTERNAL_OWNED.items()})
    for path, record in mirror.EXTERNAL_OWNED.items():
        # The exact fixture bytes are not known here; tests that perform full
        # readback patch the protected sidecar record to their deterministic bytes.
        files[path] = b"e" * record["size"]
    return files


class PathAndJsonTests(unittest.TestCase):
    def test_payload_policy_is_sorted_closed_and_excludes_control_plane(self):
        self.assertEqual(tuple(sorted(mirror.MIRROR_PATHS)), mirror.MIRROR_PATHS)
        self.assertEqual(len(mirror.MIRROR_PATHS), 23)
        for path in (
            mirror.PUBLISH_WORKFLOW_PATH,
            mirror.DRIFT_WORKFLOW_PATH,
            "scripts/hf_mirror.py",
            "scripts/hf_mirror_drift_check.py",
            "requirements/hf-mirror.lock",
            "tests/test_hf_mirror_contract.py",
        ):
            self.assertNotIn(path, mirror.MIRROR_PATHS)

    def test_unsafe_paths_fail(self):
        values = (
            "",
            "/abs",
            "\\\\server\\share",
            "C:/drive",
            "a\\b",
            "a%2fb",
            "a//b",
            "a/./b",
            "a/../b",
            "a/b.",
            "a/b ",
            "a/\x00b",
            "a/\x1fb",
            "e\u0301.txt",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(mirror.MirrorContractError):
                mirror._validate_path(value)

    def test_case_and_duplicate_collisions_fail(self):
        for paths in (("a", "a"), ("A", "a")):
            with self.subTest(paths=paths), self.assertRaises(mirror.MirrorContractError):
                mirror._validate_path_set(paths)

    def test_duplicate_json_key_fails(self):
        with self.assertRaises(mirror.MirrorContractError):
            mirror.strict_json_loads(b'{"a":1,"a":2}\n')

    def test_bom_float_and_noncanonical_json_fail(self):
        for raw in (b"\xef\xbb\xbf{}\n", b'{"a":1.5}\n', b'{ "a":1 }\n', b'{"a":1}\r\n'):
            with self.subTest(raw=raw), self.assertRaises(mirror.MirrorContractError):
                mirror.strict_json_loads(raw, require_canonical=True)

    def test_valid_manifest_round_trips(self):
        item = snapshot()
        self.assertEqual(mirror.validate_manifest(item.manifest_bytes), item.manifest)

    def test_unknown_manifest_field_fails(self):
        item = snapshot()
        value = copy.deepcopy(item.manifest)
        value["unknown"] = True
        with self.assertRaises(mirror.MirrorContractError):
            mirror.validate_manifest(mirror.canonical_json(value))

    def test_boolean_size_fails(self):
        item = snapshot()
        value = copy.deepcopy(item.manifest)
        value["files"][0]["size"] = True
        value["aggregate_sha256"] = mirror._artifact_root(value["files"])
        with self.assertRaises(mirror.MirrorContractError):
            mirror.validate_manifest(mirror.canonical_json(value))

    def test_wrong_schema_source_target_count_and_root_fail(self):
        item = snapshot()
        mutations = (
            ("schema", "unknown/v2"),
            ("artifact_count", 22),
            ("aggregate_sha256", "0" * 64),
        )
        for key, value in mutations:
            changed = copy.deepcopy(item.manifest)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(mirror.MirrorContractError):
                mirror.validate_manifest(mirror.canonical_json(changed))
        for section, key, value in (
            ("source", "repository", "attacker/repo"),
            ("source", "revision", "A" * 40),
            ("target", "repository", "attacker/model"),
            ("workflow", "path", "evil.yml"),
        ):
            changed = copy.deepcopy(item.manifest)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(mirror.MirrorContractError):
                mirror.validate_manifest(mirror.canonical_json(changed))

    def test_one_byte_file_digest_tamper_fails(self):
        item = snapshot()
        for index in (0, len(item.files) - 1):
            changed = copy.deepcopy(item.manifest)
            changed["files"][index]["sha256"] = "0" * 64
            with self.subTest(index=index), self.assertRaises(mirror.MirrorContractError):
                mirror.validate_manifest(mirror.canonical_json(changed), expected=item.manifest)


class AdmissionTests(unittest.TestCase):
    def test_valid_publisher_context(self):
        self.assertEqual(mirror.validate_publisher_context(publisher_env(), publisher_event()), SOURCE_SHA)

    def test_publisher_context_mutations_fail(self):
        mutations = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "attacker/repo",
            "GITHUB_REF": "refs/tags/v1",
            "GITHUB_SHA": "A" * 40,
            "GITHUB_WORKFLOW_SHA": "b" * 40,
            "GITHUB_WORKFLOW_REF": "attacker/repo/.github/workflows/hf-mirror.yml@refs/heads/main",
        }
        for key, value in mutations.items():
            env = publisher_env()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(mirror.MirrorContractError):
                mirror.validate_publisher_context(env, publisher_event())

    def test_event_action_repository_branch_and_payload_mutations_fail(self):
        cases = (
            {"action": "wrong"},
            {"repository": {"full_name": "attacker/repo", "default_branch": "main"}},
            {"repository": {"full_name": mirror.SOURCE_REPOSITORY, "default_branch": "dev"}},
            {"client_payload": {"revision": SOURCE_SHA}},
        )
        for update in cases:
            event = publisher_event()
            event.update(update)
            with self.subTest(update=update), self.assertRaises(mirror.MirrorContractError):
                mirror.validate_publisher_context(publisher_env(), event)

    def test_credentialless_verifier_rejects_every_token_name(self):
        mirror.ensure_credentialless({})
        for name in mirror.TOKEN_ENV_NAMES:
            with self.subTest(name=name), self.assertRaises(mirror.MirrorContractError):
                mirror.ensure_credentialless({name: TOKEN_SENTINEL})

    def test_tree_parser_rejects_malformed_duplicate_and_unsafe_path(self):
        with self.assertRaises(mirror.MirrorContractError):
            mirror._parse_tree(b"malformed\0")
        record = b"100644 blob " + b"0" * 40 + b"\ta\0"
        with self.assertRaises(mirror.MirrorContractError):
            mirror._parse_tree(record + record)
        with self.assertRaises(mirror.MirrorContractError):
            mirror._parse_tree(b"120000 blob " + b"0" * 40 + b"\t../x\0")

    def test_source_snapshot_rejects_symlink_and_submodule_modes(self):
        base = {
            ("rev-parse", "HEAD"): (SOURCE_SHA + "\n").encode(),
            ("status", "--porcelain=v1", "--untracked-files=all"): b"",
            ("rev-parse", f"{SOURCE_SHA}^{{tree}}"): (SOURCE_TREE + "\n").encode(),
        }
        for mode, kind in (("120000", "blob"), ("160000", "commit")):
            entries = []
            for index, path in enumerate(mirror.MIRROR_PATHS):
                entry_mode, entry_kind = (mode, kind) if index == 0 else ("100644", "blob")
                entries.append(f"{entry_mode} {entry_kind} {'0' * 40}\t{path}".encode())
            tree_bytes = b"\0".join(entries) + b"\0"

            def fake_git(args, _root):
                key = tuple(args)
                if key == ("ls-tree", "-r", "-z", "--full-tree", SOURCE_SHA):
                    return tree_bytes
                return base[key]

            with self.subTest(mode=mode), mock.patch.object(mirror, "_git", side_effect=fake_git):
                with self.assertRaises(mirror.MirrorContractError):
                    mirror.build_source_snapshot(ROOT, SOURCE_SHA)


class RemoteAndPublisherTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()
        self.sidecar = b"managed-sidecar-fixture"
        self.external_patch = mock.patch.object(
            mirror,
            "EXTERNAL_OWNED",
            {
                "SZL_ESTATE_MANAGED.json": {
                    "schema": "szl.hf-estate-managed/v1",
                    "generation": "3c20fe2a6b0c9c56a045265b194a81e952fc949c",
                    "size": len(self.sidecar),
                    "sha256": hashlib.sha256(self.sidecar).hexdigest(),
                }
            },
        )
        self.external_patch.start()
        # Rebuild after the protected external record is patched.
        self.snapshot = snapshot()

    def tearDown(self):
        self.external_patch.stop()

    def exact_remote(self) -> dict[str, bytes]:
        return {
            **self.snapshot.payload,
            mirror.MANIFEST_PATH: self.snapshot.manifest_bytes,
            "SZL_ESTATE_MANAGED.json": self.sidecar,
        }

    def test_valid_immutable_readback_is_anonymous_and_scoped(self):
        hub = FakeHub(self.exact_remote(), HF_SHA)
        report = mirror.verify_remote(hub, hub.download, self.snapshot)
        self.assertEqual(report["status"], "MIRROR_MANAGED_PAYLOAD_EXACT_READBACK_VERIFIED")
        self.assertEqual(report["hf_revision"], HF_SHA)

    def test_missing_extra_hash_size_and_lfs_pointer_fail(self):
        cases: list[tuple[str, dict[str, bytes]]] = []
        missing = self.exact_remote()
        missing.pop(mirror.MIRROR_PATHS[0])
        cases.append(("missing", missing))
        extra = self.exact_remote()
        extra["unexpected.txt"] = b"x"
        cases.append(("extra", extra))
        changed = self.exact_remote()
        changed[mirror.MIRROR_PATHS[0]] += b"x"
        cases.append(("changed", changed))
        lfs = self.exact_remote()
        lfs[mirror.MIRROR_PATHS[0]] = b"version https://git-lfs.github.com/spec/v1\n"
        cases.append(("lfs", lfs))
        for name, files in cases:
            with self.subTest(name=name), self.assertRaises(mirror.MirrorContractError):
                hub = FakeHub(files, HF_SHA)
                mirror.verify_remote(hub, hub.download, self.snapshot)

    def test_manifest_one_byte_tamper_fails(self):
        files = self.exact_remote()
        files[mirror.MANIFEST_PATH] = files[mirror.MANIFEST_PATH][:-2] + b"x\n"
        hub = FakeHub(files, HF_SHA)
        with self.assertRaises(mirror.MirrorContractError):
            mirror.verify_remote(hub, hub.download, self.snapshot)

    def test_main_movement_during_readback_fails(self):
        hub = FakeHub(self.exact_remote(), HF_SHA)
        hub.history[NEXT_HF_SHA] = dict(hub.history[HF_SHA])
        hub.head_reads = [HF_SHA, NEXT_HF_SHA]
        with self.assertRaises(mirror.MirrorContractError):
            mirror.verify_remote(hub, hub.download, self.snapshot)

    def test_unknown_extra_aborts_before_mutation(self):
        files = {**self.snapshot.payload, "SZL_ESTATE_MANAGED.json": self.sidecar, "unknown": b"x"}
        hub = FakeHub(files)
        with self.assertRaises(mirror.MirrorContractError):
            mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(hub.commit_calls, [])

    def test_wrong_manifestless_parent_aborts_before_mutation(self):
        files = {**self.snapshot.payload, "SZL_ESTATE_MANAGED.json": self.sidecar}
        hub = FakeHub(files, HF_SHA)
        with self.assertRaises(mirror.MirrorContractError):
            mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(hub.commit_calls, [])

    def test_publication_uses_one_parent_cas_and_exact_operations(self):
        files = {**self.snapshot.payload, "SZL_ESTATE_MANAGED.json": self.sidecar}
        hub = FakeHub(files)
        report = mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(report["operation"], "COMMIT")
        self.assertEqual(len(hub.commit_calls), 1)
        call = hub.commit_calls[0]
        self.assertEqual(call["parent_commit"], mirror.LEGACY_HF_REVISION)
        self.assertEqual(call["repo_id"], mirror.HF_REPOSITORY)
        self.assertEqual(call["repo_type"], mirror.HF_REPO_TYPE)
        self.assertEqual(call["revision"], mirror.SOURCE_BRANCH)
        self.assertEqual(call["num_threads"], 1)
        paths = [operation.path for operation in call["operations"]]
        self.assertEqual(paths, [*mirror.MIRROR_PATHS, mirror.MANIFEST_PATH])
        self.assertNotIn("SZL_ESTATE_MANAGED.json", paths)

    def test_cas_conflict_has_no_retry(self):
        files = {**self.snapshot.payload, "SZL_ESTATE_MANAGED.json": self.sidecar}
        hub = FakeHub(files)
        hub.fail_commit = RuntimeError("CAS conflict")
        with self.assertRaises(RuntimeError):
            mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(len(hub.commit_calls), 1)

    def test_malformed_returned_revision_fails_without_retry(self):
        files = {**self.snapshot.payload, "SZL_ESTATE_MANAGED.json": self.sidecar}
        hub = FakeHub(files)
        hub.returned_oid = "not-a-sha"
        with self.assertRaises(mirror.MirrorContractError):
            mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(len(hub.commit_calls), 1)

    def test_exact_state_is_verified_noop(self):
        hub = FakeHub(self.exact_remote(), HF_SHA)
        report = mirror.publish_once(self.snapshot, hub, hub, hub.download, Add, Delete, TOKEN_SENTINEL)
        self.assertEqual(report["operation"], "NOOP")
        self.assertEqual(hub.commit_calls, [])

    def test_safe_error_redacts_token(self):
        rendered = mirror._safe_error(RuntimeError(f"failed {TOKEN_SENTINEL}"), TOKEN_SENTINEL)
        self.assertNotIn(TOKEN_SENTINEL, rendered)
        self.assertIn("[REDACTED]", rendered)


class WorkflowAndLockTests(unittest.TestCase):
    def setUp(self):
        self.publisher = (ROOT / mirror.PUBLISH_WORKFLOW_PATH).read_text(encoding="utf-8")
        self.drift = (ROOT / mirror.DRIFT_WORKFLOW_PATH).read_text(encoding="utf-8")
        self.lock = (ROOT / "requirements/hf-mirror.lock").read_text(encoding="utf-8")

    def test_publisher_has_no_selected_ref_or_duplicate_release_trigger(self):
        self.assertNotRegex(self.publisher, r"(?m)^  (?:workflow_dispatch|release):")
        self.assertNotRegex(self.publisher, r"(?m)^    tags:")
        self.assertIn("repository_dispatch:", self.publisher)
        self.assertIn("types: [hf-mirror-source-bound]", self.publisher)

    def test_checkout_and_actions_are_immutable(self):
        for workflow in (self.publisher, self.drift):
            uses = re.findall(r"uses:\s+([^\s#]+)", workflow)
            self.assertGreaterEqual(len(uses), 2)
            for value in uses:
                self.assertRegex(value, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
            self.assertIn("persist-credentials: false", workflow)
            self.assertIn("fetch-depth: 1", workflow)
            self.assertIn("ref: ${{ github.sha }}", workflow)
            self.assertNotIn("ubuntu-latest", workflow)
            self.assertIn("timeout-minutes:", workflow)

    def test_secret_appears_once_only_in_final_publisher_step(self):
        needle = "HF_TOKEN: ${{ secrets.HF_TOKEN }}"
        self.assertEqual(self.publisher.count(needle), 1)
        self.assertGreater(self.publisher.index(needle), self.publisher.index("Publish once"))
        self.assertNotIn("secrets.", self.drift)
        self.assertNotIn("--token", self.publisher)

    def test_contract_runs_before_install_and_publish(self):
        contract = self.publisher.index("Verify offline mirror contract")
        install = self.publisher.index("Install the reviewed binary-only HF client closure")
        publish = self.publisher.index("Publish once")
        self.assertLess(contract, install)
        self.assertLess(install, publish)

    def test_drift_has_no_soft_failure_or_manual_ref(self):
        self.assertNotIn("continue-on-error", self.drift)
        self.assertNotIn("workflow_dispatch", self.drift)
        self.assertIn("schedule:", self.drift)

    def test_all_six_authorized_paths_trigger_contract_tests(self):
        for path in (
            mirror.PUBLISH_WORKFLOW_PATH,
            mirror.DRIFT_WORKFLOW_PATH,
            "scripts/hf_mirror.py",
            "scripts/hf_mirror_drift_check.py",
            "requirements/hf-mirror.lock",
            "tests/test_hf_mirror_contract.py",
        ):
            self.assertIn(f'"{path}"', self.drift)

    def test_lock_is_exact_hashed_binary_closure(self):
        requirement_lines = [line for line in self.lock.splitlines() if line and not line.startswith(("#", " "))]
        self.assertEqual(len(requirement_lines), 16)
        names: set[str] = set()
        for line in requirement_lines:
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.-]+) \\", line)
            self.assertIsNotNone(match, line)
            names.add(match.group(1).lower().replace("_", "-"))
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", self.lock)
        self.assertEqual(len(hashes), len(requirement_lines))
        self.assertEqual(len(set(hashes)), len(hashes))
        self.assertIn("huggingface-hub", names)
        self.assertIn("hf-xet", names)
        for forbidden in (">=", "<=", "~=", " @ ", "git+", "http://", "https://", "-e "):
            self.assertNotIn(forbidden, self.lock)

    def test_workflows_install_lock_with_required_flags(self):
        for workflow in (self.publisher, self.drift):
            for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps", "--no-cache-dir"):
                self.assertIn(flag, workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
