# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""PCGI spine fold: a metered inference as ONE canonical szl-receipt.

Proves the doctrine contract for the WAVE-2 spine UNIFY:
  * The canonical receipt binds model id + input digest + output digest +
    governing policy id + energy, using the shared szl-receipt shapes (no new
    receipt shape is invented).
  * Determinism: identical inputs => byte-identical canonical body/digest.
  * A signed receipt verifies; a wrong key does not; tamper is rejected.
  * Energy honesty: MEASURED joules are bound verbatim; unmeasured energy is the
    literal "UNAVAILABLE" sentinel — never a fabricated joule.
  * The in-toto Statement is cryptographically bound to its exact receipt.

Runs WITHOUT a GPU. On a GPU-less box every metered call is honestly unmeasured
and the tests assert exactly that honest-degrade behavior.

Run directly (no pytest needed):  python tests/test_spine.py
Or with pytest:                    pytest tests/
"""
import base64
import json
import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "build", "torch-universal"),
)

import governed_inference_meter as gim  # noqa: E402
from szl_receipt import generate_keypair, verify_receipt  # noqa: E402


def _body(env):
    return json.loads(base64.b64decode(env["payload"]).decode("utf-8"))


def test_binds_the_five_pcgi_fields():
    env = gim.emit_szl_receipt(
        model="llm-7b",
        input="hello",
        output="olleh",
        policy_id="default-allow",
        policy_decision="allow",
        policy_reason="allow_all",
    )
    body = _body(env)
    assert body["model"] == "llm-7b"
    assert body["input_digest"] == "sha256:" + gim.digest("hello")
    assert body["output_digest"] == "sha256:" + gim.digest("olleh")
    assert body["policy"]["id"] == "default-allow"
    assert body["policy"]["decision"] == "allow"
    assert "energy" in body and "joules" in body["energy"]
    # Uses the canonical szl-receipt kind (not a new shape).
    assert env["payloadType"].startswith("application/vnd.szl.receipt")


def test_energy_unavailable_is_honest_not_fabricated():
    # No energy provided => honest UNAVAILABLE, never a fabricated joule.
    env = gim.emit_szl_receipt(model="m", input="i", output="o")
    e = _body(env)["energy"]
    assert e["measured"] is False
    assert e["joules"] == gim.ENERGY_UNAVAILABLE
    assert e["joules"] == "UNAVAILABLE"


def test_energy_measured_is_bound_verbatim():
    # When the meter DID measure, joules are copied verbatim (the one real place).
    env = gim.emit_szl_receipt(
        model="m",
        input="i",
        output="o",
        energy={"mode": gim.MODE_ENERGY_COUNTER, "joules": 12.5},
    )
    e = _body(env)["energy"]
    assert e["measured"] is True
    assert e["mode"] == gim.MODE_ENERGY_COUNTER
    assert e["joules"] == 12.5


def test_determinism_byte_identical_canonical():
    kw = dict(
        model="m", input={"prompt": "x", "n": 3}, output=["a", "b"],
        policy_id="p1", policy_decision="allow", policy_reason="ok",
        energy={"mode": gim.MODE_ENERGY_COUNTER, "joules": 3.25},
    )
    e1 = gim.emit_szl_receipt(**kw)
    e2 = gim.emit_szl_receipt(**kw)
    # Canonical payload + digest are byte-identical for identical inputs.
    assert e1["payload"] == e2["payload"]
    assert e1["digest"] == e2["digest"]
    assert _body(e1) == _body(e2)


def test_signed_receipt_verifies_and_wrong_key_fails():
    priv, pub = generate_keypair()
    env = gim.emit_szl_receipt(
        model="m", input="i", output="o", sign_key=priv, organ="meter",
    )
    assert env["signed"] is True and env["organ"] == "meter"
    ok, why = gim.verify_szl_receipt(env, pub)
    assert ok and why == "ok", (ok, why)
    # Delegation matches the shared library directly.
    assert verify_receipt(env, pub) == (ok, why)
    # Wrong key must NOT verify (real crypto).
    _, other_pub = generate_keypair()
    bad_ok, _ = gim.verify_szl_receipt(env, other_pub)
    assert bad_ok is False


def test_keyless_is_unsigned_honest():
    env = gim.emit_szl_receipt(model="m", input="i", output="o")  # no key
    assert env["signed"] is False
    ok, why = gim.verify_szl_receipt(env)
    assert (ok, why) == (False, "unsigned-honest")


def test_tamper_is_rejected():
    priv, pub = generate_keypair()
    env = gim.emit_szl_receipt(
        model="m", input="i", output="o", sign_key=priv, organ="meter",
    )
    # Tamper the output digest inside the signed payload; signature must fail.
    body = _body(env)
    body["output_digest"] = "sha256:" + "0" * 64
    tampered = dict(env)
    tampered["payload"] = base64.b64encode(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    ok, _ = gim.verify_szl_receipt(tampered, pub)
    assert ok is False


def test_statement_binds_to_exact_receipt():
    env = gim.emit_szl_receipt(
        model="m", input="i", output="o",
        energy={"mode": gim.MODE_ENERGY_COUNTER, "joules": 7.0},
    )
    stmt = gim.to_statement(env)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == gim.PREDICATE_TYPE
    ext = stmt["predicate"]["buildDefinition"]["externalParameters"]
    assert ext["model"] == "m"
    md = stmt["predicate"]["runDetails"]["metadata"]
    assert md["energy_measured"] is True and md["joules"] == 7.0
    ok, why = gim.verify_szl_statement(stmt, env)
    assert ok and why == "ok", (ok, why)
    # A statement for one receipt must not verify against a different receipt.
    other = gim.emit_szl_receipt(model="other", input="x", output="y")
    bad_ok, _ = gim.verify_szl_statement(stmt, other)
    assert bad_ok is False


def test_end_to_end_meter_szl_receipt_honest_degrade():
    priv, pub = generate_keypair()
    env, out = gim.meter_szl_receipt(
        lambda p: p.upper(), args=("hi",), model="t",
        policy_id="default-allow", sign_key=priv, organ="meter",
    )
    assert out == "HI"
    body = _body(env)
    assert body["model"] == "t"
    assert body["input_digest"].startswith("sha256:")
    assert body["output_digest"] == "sha256:" + gim.digest("HI")
    # On a GPU-less box energy must be honest UNAVAILABLE, never fabricated.
    if not gim.nvml_available():
        assert body["energy"]["measured"] is False
        assert body["energy"]["joules"] == "UNAVAILABLE"
    ok, why = gim.verify_szl_receipt(env, pub)
    assert ok and why == "ok", (ok, why)


def test_deny_binds_null_output_and_unavailable_energy():
    env, out = gim.meter_szl_receipt(
        lambda p: p, args=("p",), model="t",
        policy_id="lockdown", policy=gim.deny_all,
    )
    assert out is None
    body = _body(env)
    assert body["policy"]["decision"] == gim.DENY
    assert body["output_digest"] == "sha256:" + gim.digest(None)
    assert body["energy"]["joules"] == "UNAVAILABLE"


def test_from_meter_receipt_fold_preserves_energy_state():
    ch = gim.ReceiptChain()
    rec, out = gim.meter(
        lambda p: p.upper(), args=("hi",), model="foldme",
        tokens_in=1, tokens_out=2, chain=ch,
    )
    env = gim.from_meter_receipt(rec, input="hi", output=out, policy_id="p")
    body = _body(env)
    assert body["model"] == "foldme"
    # Energy binding must mirror the meter receipt's real measured/unmeasured state.
    if rec["mode"] == gim.MODE_UNMEASURED:
        assert body["energy"]["measured"] is False
        assert body["energy"]["joules"] == "UNAVAILABLE"
    else:
        assert body["energy"]["measured"] is True
        assert body["energy"]["joules"] == rec["joules"]


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
