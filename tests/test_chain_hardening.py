# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Adversarial hardening tests for the tamper-evident ReceiptChain.

Runs WITHOUT a GPU. These tests attack the audit path directly: they mutate,
delete, renumber, and re-digest records to confirm ``verify()``:

  * never raises out of the audit path on a malformed/tampered record — a
    removed canonical field is reported as a clean break, not a KeyError crash;
  * enforces the monotonic append-only counter (each record's ``seq`` must
    equal its position), catching a re-digested forgery that renumbers or
    reorders records even when its internal digest/prev links are consistent;
  * still passes an untouched chain and still pinpoints an ordinary body edit.

No fabricated energy anywhere; every digest below is a real SHA-256.

Run directly (no pytest needed):  python tests/test_chain_hardening.py
Or with pytest:                    pytest tests/
"""
import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "build", "torch-universal"),
)

import governed_inference_meter as gim  # noqa: E402
from governed_inference_meter._receipt import _digest_body  # noqa: E402


def _chain(n=4):
    ch = gim.ReceiptChain()
    for i in range(n):
        gim.meter(lambda p: p, args=(f"x{i}",), model="t",
                  tokens_in=1, tokens_out=3, chain=ch)
    return ch


def test_clean_chain_verifies():
    ch = _chain(4)
    ok, depth, brk = ch.verify()
    assert ok is True and depth == 4 and brk == -1


def test_missing_field_is_break_not_crash():
    # Deleting a canonical body field is tampering: verify() must report a
    # clean break at that index and must NOT raise KeyError out of the audit.
    ch = _chain(4)
    del ch._records[2]["joules"]  # noqa: SLF001 - white-box attack
    ok, depth, brk = ch.verify()  # must not raise
    assert ok is False and depth == 4 and brk == 2


def test_missing_digest_key_is_break_not_crash():
    ch = _chain(3)
    del ch._records[1]["digest"]  # noqa: SLF001
    ok, _, brk = ch.verify()  # must not raise
    assert ok is False and brk == 1


def test_seq_renumber_with_recomputed_digest_is_caught():
    # A capable adversary re-digests a forged record but violates the
    # monotonic counter. verify() enforces seq == position and catches it,
    # even though the record's own digest and prev links are self-consistent.
    ch = _chain(4)
    rec = ch._records[2]  # noqa: SLF001
    rec["seq"] = 99
    body = {k: rec[k] for k in (
        "seq", "model", "tokens_in", "tokens_out", "mode", "joules",
        "wall_seconds", "tokens_per_joule", "policy_decision",
        "policy_reason", "prev",
    )}
    new_digest = _digest_body(body)
    # Re-link the downstream record so the prev-chain stays internally valid.
    ch._records[3]["prev"] = new_digest  # noqa: SLF001
    down = ch._records[3]  # noqa: SLF001
    down_body = {k: down[k] for k in (
        "seq", "model", "tokens_in", "tokens_out", "mode", "joules",
        "wall_seconds", "tokens_per_joule", "policy_decision",
        "policy_reason", "prev",
    )}
    down["digest"] = _digest_body(down_body)
    rec["digest"] = new_digest
    # Digest & prev links are all self-consistent now; only the counter lies.
    ok, _, brk = ch.verify()
    assert ok is False and brk == 2


def test_ordinary_body_edit_still_pinpointed():
    # Regression: a plain field edit (no re-digest) is still caught at its seq.
    ch = _chain(5)
    ch._records[3]["tokens_out"] = 999  # noqa: SLF001
    ok, _, brk = ch.verify()
    assert ok is False and brk == 3


def test_extra_nonbody_key_does_not_false_positive():
    # Only canonical body fields are hashed; an extra annotation key on a
    # record (e.g. a caller tag) must not be mistaken for tampering.
    ch = _chain(3)
    ch._records[1]["audit_note"] = "reviewed by ops"  # noqa: SLF001
    ok, _, brk = ch.verify()
    assert ok is True and brk == -1


if __name__ == "__main__":
    failures = 0
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            try:
                obj()
                print(f"PASS {name}")
            except AssertionError as e:  # noqa: PERF203
                failures += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{'ALL PASS' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
