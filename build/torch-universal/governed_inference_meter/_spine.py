# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""PCGI spine fold — a metered inference as ONE canonical szl-receipt.

This is the WAVE-2 spine UNIFY step: it folds a governed-inference metering
result onto the org-canonical ``szl-receipt`` shape so the meter becomes a
first-class *Proof-Carrying Governed Intelligence* (PCGI) receipt producer on
the same spine as every other decision producer (a11oy, yarqa, killinchu, ...).

A canonical receipt binds, in ONE signed record:

  * ``model``          — the model id that produced the output,
  * ``input_digest``   — SHA-256 over the canonical input,
  * ``output_digest``  — SHA-256 over the canonical output,
  * ``policy``         — the governing policy id + advisory decision/reason,
  * ``energy``         — MEASURED joules verbatim, or honest ``UNAVAILABLE``.

It does NOT invent a new receipt shape: it uses ``szl_receipt.Receipt`` +
``szl_receipt.sign_receipt`` for the canonical body + DSSE signing, and
``szl_receipt.build_statement`` / ``slsa_predicate`` / ``verify_statement`` for
the in-toto Statement. The shared library is the ONE source of truth for
canonicalization, signing, and the ecosystem shapes.

HONESTY (Λ = Conjecture 1, advisory — NOT a theorem):
  * Energy is bound VERBATIM only when the meter actually measured it (NVML
    present, ``mode != "unmeasured"``, ``joules`` present). Otherwise the
    ``energy.joules`` field is the literal string ``"UNAVAILABLE"`` and
    ``energy.measured`` is ``False``. A joule figure is NEVER fabricated. This
    meter is the one place in the spine where energy CAN be real — the honest
    counterpart to killinchu's edge ``UNAVAILABLE``.
  * The receipt is EVIDENCE binding a decision (model+input+output+policy+
    energy), NOT a proof that the model's output is correct.
  * Keyless => UNSIGNED-honest (``signed=False``); a signature is never faked.
  * The canonical body is deterministic: given identical inputs it serializes to
    byte-identical canonical JSON (no timestamps / wall-clock in the body).

Import stays zero-hard-dependency: ``szl_receipt`` is imported lazily, so
importing this package never requires it. Producing a canonical receipt does
require it (install extra ``[sign]``), and its absence raises a clear error.
"""
import hashlib
from typing import Any, Callable, Dict, Optional, Sequence, Tuple, Union

# Canonical receipt kind (matches the additive signing layer in _receipt.py).
CANONICAL_KIND = "governed-inference"

# Our OWN predicate type — SLSA-*shaped* for recognizability, NOT a claim of
# official SLSA-provenance conformance (mirrors _attest.SZL_PREDICATE_TYPE).
PREDICATE_TYPE = "https://a-11-oy.com/attest/governed-inference/v0.1"

# Canonical body schema version for the PCGI fold.
SPEC_VERSION = "pcgi-governed-inference/0.1"

# Honest sentinel for energy that was not measured (never a fabricated joule).
ENERGY_UNAVAILABLE = "UNAVAILABLE"

# Default logical signing-authority label stamped onto the envelope.
_ORGAN = "governed-inference-meter"

SPINE_DOCTRINE = (
    "SZL Holdings · PCGI spine · a metered inference as ONE canonical "
    "szl-receipt binding model+input+output+policy+energy · MEASURED joules "
    "verbatim else UNAVAILABLE (never fabricated) · receipt = evidence trail, "
    "NOT a proof the output is correct · Lambda = Conjecture 1 (advisory) · "
    "trust never 100%"
)


def _shared():
    """Lazily import the shared ``szl_receipt`` library (the ONE canonical home).

    Producing a canonical receipt reuses szl-receipt's canonicalization, signing,
    and in-toto shapes. If it is not installed we raise a clear, honest error —
    never a silent, drift-prone local reimplementation.
    """
    try:
        import szl_receipt as _s  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise ImportError(
            "governed_inference_meter canonical szl-receipt output requires the "
            "shared 'szl-receipt' library (pip install "
            "'governed-inference-meter[sign]', or pip install szl-receipt). "
            "Underlying import error: %r" % (exc,)
        ) from exc
    return _s


def _canonical_bytes(obj: Any) -> bytes:
    """Deterministic bytes for *obj*, reusing szl-receipt's canonicalization.

    ``bytes`` are hashed as-is; ``str`` as its UTF-8 bytes; any JSON-serialisable
    object via szl-receipt's ``canonical_json`` (sorted, compact) so digests are
    stable across processes. Non-JSON objects fall back to a stable ``repr`` —
    honest and deterministic, never an exception that would hide the binding.
    """
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("utf-8")
    try:
        # Reuse szl-receipt's ONE canonicalization when available.
        from szl_receipt._canonical import canonical_json  # type: ignore
    except Exception:  # noqa: BLE001 - defensive against version drift
        import json as _json

        def canonical_json(o):  # byte-identical fallback to szl-receipt's
            return _json.dumps(
                o, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")

    try:
        return canonical_json(obj)
    except TypeError:
        # Not JSON-serialisable (e.g. a tensor/handle): bind a stable repr so the
        # digest is still deterministic and honest about what it covers.
        return ("repr::" + repr(obj)).encode("utf-8")


def digest(obj: Any) -> str:
    """SHA-256 hex digest over the canonical bytes of *obj* (see ``_canonical_bytes``)."""
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()


def _energy_binding(energy: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Honest energy binding from a meter ``energy`` dict OR a meter receipt.

    Both an ``EnergyMeter.stop()`` dict and a receipt carry ``mode``/``joules``.
    MEASURED joules are copied verbatim; otherwise ``joules`` is the literal
    ``"UNAVAILABLE"`` sentinel and ``measured`` is ``False``. Never fabricated.
    """
    e = dict(energy or {})
    mode = e.get("mode", "unmeasured")
    joules = e.get("joules", None)
    measured = (mode != "unmeasured") and (joules is not None)
    if measured:
        return {
            "measured": True,
            "mode": str(mode),
            "joules": round(float(joules), 6),  # verbatim measured value
        }
    return {
        "measured": False,
        "mode": str(mode),
        "joules": ENERGY_UNAVAILABLE,  # honest sentinel — no fabricated joule
    }


def canonical_receipt_body(
    *,
    model: str,
    input: Any = None,
    output: Any = None,
    policy_id: str = "unspecified",
    policy_decision: str = "allow",
    policy_reason: str = "",
    energy: Optional[Dict[str, Any]] = None,
    input_digest: Optional[str] = None,
    output_digest: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble the DETERMINISTIC canonical receipt body (the PCGI binding).

    Provide either the raw ``input``/``output`` (they will be digested) or a
    precomputed ``input_digest``/``output_digest``. The body contains no
    timestamp or wall-clock, so identical inputs serialize byte-identically.
    """
    idig = input_digest if input_digest is not None else digest(input)
    odig = output_digest if output_digest is not None else digest(output)
    return {
        "spec_version": SPEC_VERSION,
        "model": str(model),
        "input_digest": "sha256:" + idig,
        "output_digest": "sha256:" + odig,
        "policy": {
            "id": str(policy_id),
            "decision": str(policy_decision),
            "reason": str(policy_reason),
        },
        "energy": _energy_binding(energy),
    }


def emit_szl_receipt(
    *,
    model: str,
    input: Any = None,
    output: Any = None,
    policy_id: str = "unspecified",
    policy_decision: str = "allow",
    policy_reason: str = "",
    energy: Optional[Dict[str, Any]] = None,
    input_digest: Optional[str] = None,
    output_digest: Optional[str] = None,
    sign_key: Optional[Union[str, bytes]] = None,
    organ: str = _ORGAN,
) -> Dict[str, Any]:
    """Produce ONE canonical szl-receipt (DSSE envelope) for a metered inference.

    Binds model id + input digest + output digest + governing policy id + energy
    into a ``szl_receipt.Receipt`` and signs it. With a PEM ECDSA-P256 *sign_key*
    the envelope is signed; keyless it is UNSIGNED-honest (``signed=False``). The
    envelope's ``digest`` is the SHA-256 over the canonical body — byte-stable
    for identical inputs.
    """
    s = _shared()
    body = canonical_receipt_body(
        model=model,
        input=input,
        output=output,
        policy_id=policy_id,
        policy_decision=policy_decision,
        policy_reason=policy_reason,
        energy=energy,
        input_digest=input_digest,
        output_digest=output_digest,
    )
    return s.sign_receipt(s.Receipt(kind=CANONICAL_KIND, body=body), sign_key, organ=organ)


def from_meter_receipt(
    meter_receipt: Dict[str, Any],
    *,
    input: Any = None,
    output: Any = None,
    policy_id: str = "unspecified",
    input_digest: Optional[str] = None,
    output_digest: Optional[str] = None,
    sign_key: Optional[Union[str, bytes]] = None,
    organ: str = _ORGAN,
) -> Dict[str, Any]:
    """Fold an existing meter receipt (from :func:`meter`) onto a canonical receipt.

    Reads ``model``, ``mode``/``joules`` (energy), and ``policy_decision``/
    ``policy_reason`` from the meter receipt, and binds the given ``input``/
    ``output`` (or precomputed digests). Energy honesty is preserved verbatim.
    """
    return emit_szl_receipt(
        model=meter_receipt.get("model", "unspecified"),
        input=input,
        output=output,
        policy_id=policy_id,
        policy_decision=meter_receipt.get("policy_decision", "allow"),
        policy_reason=meter_receipt.get("policy_reason", ""),
        energy={
            "mode": meter_receipt.get("mode", "unmeasured"),
            "joules": meter_receipt.get("joules", None),
        },
        input_digest=input_digest,
        output_digest=output_digest,
        sign_key=sign_key,
        organ=organ,
    )


def meter_szl_receipt(
    fn: Callable[..., Any],
    *,
    args: Sequence[Any] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    model: str = "unspecified",
    policy_id: str = "unspecified",
    policy: Optional[Callable[..., Any]] = None,
    chain: Optional[Any] = None,
    device_index: int = 0,
    sample_hz: float = 100.0,
    sign_key: Optional[Union[str, bytes]] = None,
    organ: str = _ORGAN,
) -> Tuple[Dict[str, Any], Any]:
    """End-to-end: meter ``fn`` AND emit a canonical szl-receipt for the call.

    Runs the standard energy meter + advisory policy gate (so the existing
    tamper-evident chain still records the call), then folds the result onto a
    canonical szl-receipt binding the input (args/kwargs) and output digests.
    Returns ``(envelope, output)``. On a policy DENY, ``fn`` is not executed and
    the receipt binds a ``null`` output digest with energy ``UNAVAILABLE``.
    """
    import governed_inference_meter as _pkg  # package fully loaded by call time

    kwargs = dict(kwargs or {})
    rec, output = _pkg.meter(
        fn,
        args=args,
        kwargs=kwargs,
        model=model,
        policy=policy,
        chain=chain,
        device_index=device_index,
        sample_hz=sample_hz,
    )
    env = from_meter_receipt(
        rec,
        input={"args": list(args), "kwargs": kwargs},
        output=output,
        policy_id=policy_id,
        sign_key=sign_key,
        organ=organ,
    )
    return env, output


def to_statement(
    envelope_or_body: Dict[str, Any],
    *,
    subject_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Render a canonical receipt as an in-toto Statement v1 (SLSA-shaped).

    Accepts either a DSSE envelope (from :func:`emit_szl_receipt`, whose
    ``payload`` is the base64 canonical body) or a raw body dict. The Statement's
    single subject is bound to the receipt body's SHA-256 digest, so the
    attestation is inseparable from the exact record. All energy fields are
    copied verbatim (honest ``"UNAVAILABLE"`` when unmeasured).
    """
    s = _shared()
    body = _body_of(envelope_or_body)
    subject_digest = s.Receipt(kind=CANONICAL_KIND, body=body).digest()
    energy = body.get("energy", {})
    predicate = s.slsa_predicate(
        build_type=PREDICATE_TYPE,
        external_parameters={
            "model": body.get("model"),
            "input_digest": body.get("input_digest"),
            "output_digest": body.get("output_digest"),
        },
        internal_parameters={"policy": body.get("policy")},
        builder_id=PREDICATE_TYPE,
        metadata={
            "energy_measured": bool(energy.get("measured", False)),
            "energy_mode": energy.get("mode"),
            # Verbatim: a float when measured, the "UNAVAILABLE" sentinel else.
            "joules": energy.get("joules"),
        },
        extra={"doctrine": SPINE_DOCTRINE},
    )
    name = subject_name or "governed-inference-receipt/{}".format(subject_digest[:16])
    return s.build_statement(
        subject_name=name,
        subject_digest=subject_digest,
        predicate=predicate,
        predicate_type=PREDICATE_TYPE,
    )


def _body_of(envelope_or_body: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical body from a DSSE envelope or pass a raw body through."""
    if "payload" in envelope_or_body and "payloadType" in envelope_or_body:
        import base64
        import json

        return json.loads(base64.b64decode(envelope_or_body["payload"]).decode("utf-8"))
    return envelope_or_body


def verify_szl_receipt(
    envelope: Dict[str, Any],
    public_key_pem: Optional[Union[str, bytes]] = None,
) -> Tuple[bool, str]:
    """Verify a canonical receipt envelope. Delegates to ``szl_receipt.verify_receipt``.

    Signed => ``(True, "ok")`` with the right key; keyless => the honest
    ``(False, "unsigned-honest")``; tamper/wrong-key => ``(False, ...)``.
    """
    s = _shared()
    return s.verify_receipt(envelope, public_key_pem)


def verify_szl_statement(
    statement: Dict[str, Any],
    envelope_or_body: Dict[str, Any],
) -> Tuple[bool, str]:
    """Confirm *statement* is bound to the exact canonical receipt. ``(ok, reason)``."""
    s = _shared()
    body = _body_of(envelope_or_body)
    expected = s.Receipt(kind=CANONICAL_KIND, body=body).digest()
    return s.verify_statement(
        statement, expected_digest=expected, predicate_type=PREDICATE_TYPE
    )
