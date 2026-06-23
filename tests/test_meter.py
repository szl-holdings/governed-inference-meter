# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Tiny self-test for governed_inference_meter.

Runs WITHOUT a GPU. On a GPU-less build/CI box, energy is honestly
``unmeasured`` and joules/tokens-per-joule are ``None`` — the tests assert
exactly this honest-degrade behavior, plus chain integrity and tamper
detection. No fabricated energy numbers anywhere.

Run directly (no pytest needed):  python tests/test_meter.py
Or with pytest:                    pytest tests/
"""
import os
import sys

# Make the universal-kernel package importable from a source checkout.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "build", "torch-universal"),
)

import governed_inference_meter as gim  # noqa: E402


def test_selfcheck_passes():
    r = gim.selfcheck()
    assert r["passed"] is True, r
    assert r["chain_ok"] is True
    assert r["tamper_detected"] is True
    assert r["allow_call_ran"] is True
    assert r["deny_call_blocked"] is True


def test_honest_degrade_without_gpu():
    # When NVML is unavailable, energy must be unmeasured and NOT fabricated.
    if not gim.nvml_available():
        rec, out = gim.meter(
            lambda p: p.upper(), args=("hi",),
            model="t", tokens_in=1, tokens_out=2,
            chain=gim.ReceiptChain(),
        )
        assert rec["mode"] == gim.MODE_UNMEASURED
        assert rec["joules"] is None
        assert rec["tokens_per_joule"] is None
        assert out == "HI"


def test_deny_does_not_execute():
    ran = {"v": False}

    def fn(_):
        ran["v"] = True
        return "x"

    rec, out = gim.meter(
        fn, args=("p",), model="t", tokens_in=1, tokens_out=1,
        policy=gim.deny_all, chain=gim.ReceiptChain(),
    )
    assert ran["v"] is False  # fail-safe: denied call never executes
    assert out is None
    assert rec["policy_decision"] == gim.DENY


def test_chain_tamper_evident():
    ch = gim.ReceiptChain()
    for i in range(5):
        gim.meter(lambda p: p, args=(f"x{i}",), model="t",
                  tokens_in=1, tokens_out=3, chain=ch)
    ok, depth, brk = ch.verify()
    assert ok and depth == 5 and brk == -1
    # Tamper with a middle record; verify() must flag the exact seq.
    ch._records[2]["tokens_out"] = 999
    ok2, _, brk2 = ch.verify()
    assert (not ok2) and brk2 == 2


def test_tokens_per_joule_only_when_measured():
    # In unmeasured mode tokens_per_joule must be None (never guessed).
    rec, _ = gim.meter(lambda p: p, args=("p",), model="t",
                       tokens_in=1, tokens_out=10, chain=gim.ReceiptChain())
    if rec["mode"] == gim.MODE_UNMEASURED:
        assert rec["tokens_per_joule"] is None


if __name__ == "__main__":
    import json

    print("capability_report:")
    print(json.dumps(gim.capability_report(), indent=2))
    print("\nselfcheck:")
    print(json.dumps(gim.selfcheck(), indent=2))
    # Run each test function.
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
