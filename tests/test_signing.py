# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""ADDITIVE szl-receipt signing layer for governed_inference_meter.

These tests prove the doctrine contract:
  * With a generated ECDSA-P256 key, the emitted receipt carries a DSSE
    signature envelope that verifies via ``szl_receipt.verify_receipt``.
  * Keyless => UNSIGNED-honest (signed=False, honest note); verify returns
    (False, "unsigned-honest"). No signature is ever fabricated.
  * The existing hash chain stays intact and tamper-evident regardless.
"""
import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "build", "torch-universal"),
)

import governed_inference_meter as gim  # noqa: E402
from szl_receipt import generate_keypair, verify_receipt  # noqa: E402


def test_signed_receipt_verifies():
    priv, pub = generate_keypair()
    ch = gim.ReceiptChain()
    rec, _ = gim.meter(
        lambda p: p.upper(), args=("hi",), model="t",
        tokens_in=1, tokens_out=2, chain=ch, sign_key=priv, organ="meter",
    )
    env = rec["signature"]
    assert env["signed"] is True
    assert env["organ"] == "meter"
    ok, why = verify_receipt(env, pub)
    assert ok and why == "ok", (ok, why)

    # Wrong key must NOT verify (real crypto, not a fake pass).
    _, other_pub = generate_keypair()
    bad_ok, _ = verify_receipt(env, other_pub)
    assert bad_ok is False

    # The additive signature must not disturb the hash chain.
    chain_ok, _, brk = ch.verify()
    assert chain_ok and brk == -1


def test_keyless_is_unsigned_honest():
    ch = gim.ReceiptChain()
    rec, _ = gim.meter(
        lambda p: p, args=("x",), model="t",
        tokens_in=1, tokens_out=2, chain=ch,  # no sign_key
    )
    env = rec["signature"]
    assert env["signed"] is False
    assert "UNSIGNED-honest" in env["note"]
    ok, why = verify_receipt(env)
    assert (ok, why) == (False, "unsigned-honest")
