# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Tests for the standards-interop + compliance-evidence attestation layer.

Runs WITHOUT a GPU. On a GPU-less box every receipt is honestly
``unmeasured``; the tests assert the attestation preserves that honesty
(no fabricated joules, energy-dependent controls report ``UNAVAILABLE``) and
that the in-toto Statement is cryptographically bound to its exact receipt.

Run directly (no pytest needed):  python tests/test_attest.py
Or with pytest:                    pytest tests/
"""
import json
import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "build", "torch-universal"),
)

import governed_inference_meter as gim  # noqa: E402


def _one_receipt():
    ch = gim.ReceiptChain()
    rec, _ = gim.meter(
        lambda p: p.upper(), args=("hi",),
        model="attest-stub", tokens_in=1, tokens_out=2, chain=ch,
    )
    return rec


def test_statement_shape_and_binding():
    rec = _one_receipt()
    stmt = gim.to_intoto_statement(rec)
    assert stmt["_type"] == gim.IN_TOTO_STATEMENT_TYPE
    assert stmt["predicateType"] == gim.SZL_PREDICATE_TYPE
    # Subject is bound to the receipt's own digest.
    assert stmt["subject"][0]["digest"]["sha256"] == rec["digest"]
    # SLSA-shaped predicate is present and echoes the call parameters.
    ext = stmt["predicate"]["buildDefinition"]["externalParameters"]
    assert ext["model"] == "attest-stub"
    assert ext["tokens_in"] == 1 and ext["tokens_out"] == 2
    # Verifier confirms the statement is bound to this receipt.
    ok, why = gim.verify_statement(stmt, rec)
    assert ok and why == "ok", (ok, why)


def test_verifier_rejects_wrong_receipt():
    rec = _one_receipt()
    stmt = gim.to_intoto_statement(rec)
    # A different receipt (different seq/model) must NOT verify against stmt.
    ch = gim.ReceiptChain()
    other, _ = gim.meter(
        lambda p: p, args=("x",), model="other", tokens_in=9, tokens_out=9,
        chain=ch,
    )
    ok, why = gim.verify_statement(stmt, other)
    assert ok is False, (ok, why)

    # Tampering with the receipt body must break verification (real digest check).
    tampered = dict(rec)
    tampered["tokens_out"] = rec["tokens_out"] + 1
    bad_ok, bad_why = gim.verify_statement(stmt, tampered)
    assert bad_ok is False and bad_why == "receipt-digest-mismatch", bad_why


def test_energy_honesty_when_unmeasured():
    # On a GPU-less box the receipt is unmeasured; the attestation must NOT
    # invent joules and energy-dependent controls must report UNAVAILABLE.
    if gim.nvml_available():
        return  # only assert the honest-degrade path when there is no GPU
    rec = _one_receipt()
    assert rec["mode"] == gim.MODE_UNMEASURED
    stmt = gim.to_intoto_statement(rec)
    md = stmt["predicate"]["runDetails"]["metadata"]
    assert md["measured"] is False
    assert md["joules"] is None
    assert md["tokens_per_joule"] is None

    ev = gim.compliance_evidence(rec)
    by_id = {c["id"]: c for c in ev["controls"]}
    assert by_id["NIST-AI-RMF-MEASURE-2.x"]["status"] == "UNAVAILABLE"
    # Logging/record-keeping controls are supported regardless of GPU.
    assert by_id["EU-AI-Act-Art-12"]["status"] == "supports"
    assert by_id["EU-AI-Act-Art-19"]["status"] == "supports"


def test_compliance_is_evidence_not_conformity():
    rec = _one_receipt()
    ev = gim.compliance_evidence(rec)
    # Doctrine: every control states what it does NOT establish.
    for c in ev["controls"]:
        assert c["does_not_establish"], c
    assert "not a conformity assessment" in ev["disclaimer"].lower()
    # Art-15 must be explicit that it does not establish model accuracy.
    art15 = next(c for c in ev["controls"] if c["id"] == "EU-AI-Act-Art-15")
    assert "does not establish model accuracy" in art15["does_not_establish"].lower()


def test_statement_is_json_serializable():
    rec = _one_receipt()
    bundle = gim.attest(rec)
    # Must round-trip through canonical JSON (the bytes a DSSE signer covers).
    s = gim.to_intoto_statement(rec)
    from governed_inference_meter._attest import to_json  # noqa: E402
    reparsed = json.loads(to_json(s))
    assert reparsed == s
    assert "statement" in bundle and "compliance" in bundle


if __name__ == "__main__":
    test_statement_shape_and_binding()
    test_verifier_rejects_wrong_receipt()
    test_energy_honesty_when_unmeasured()
    test_compliance_is_evidence_not_conformity()
    test_statement_is_json_serializable()
    print("ok: all attest tests passed")
