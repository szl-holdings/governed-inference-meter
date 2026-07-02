# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Standards-interop + compliance-evidence layer for governed-inference receipts.

A governed-inference receipt (see :mod:`._receipt`) is an honest, tamper-evident,
hash-chained record of one metered inference call. This module lets that record
*speak the wider ecosystem's language* without changing a single measured value:

  1. :func:`to_intoto_statement` renders a receipt as an **in-toto Statement v1**
     — the exact JSON payload that Sigstore / DSSE / IETF SCITT tooling already
     knows how to carry, sign, and store in a transparency log. The predicate is
     laid out in SLSA-v1 provenance shape (``buildDefinition`` / ``runDetails``).
  2. :func:`compliance_evidence` maps the receipt onto the specific **EU AI Act**
     articles and **NIST AI RMF** functions it provides operational evidence for
     and — per the honesty doctrine — states plainly what it does **NOT** establish.
  3. :func:`verify_statement` re-derives the receipt body digest and confirms the
     Statement's subject is bound to that exact receipt.

CONSOLIDATION (the ecosystem shapes + regulator catalogue live in ONE place):
  The in-toto Statement envelope, the SLSA-shaped predicate skeleton, the
  EU AI Act / NIST AI RMF control catalogue, and the subject-digest verifier are
  the SHARED :mod:`szl_receipt.attest` module — the same library that already
  provides receipt signing. This module is a thin, receipt-schema-specific
  adapter over it: it maps this package's receipt fields onto capability flags
  and predicate parameters, then delegates the ecosystem-facing shapes. That
  keeps a single source of truth so the regulator mapping can never drift
  between SZL packages. Attestation is therefore an interop feature that, like
  signing, requires the shared ``szl-receipt`` library (install extra ``[sign]``);
  the import is lazy so importing this package stays zero-hard-dependency.

HONESTY (Λ = Conjecture 1, advisory — NOT a theorem):
  * We emit our OWN predicate type URI. We do NOT claim official SLSA-provenance
    conformance; the shape is SLSA-*inspired* for recognizability only.
  * Energy fields are copied verbatim from the receipt. When the receipt is
    ``mode="unmeasured"`` the energy evidence is reported ``UNAVAILABLE`` — never
    a fabricated joule or efficiency number.
  * A receipt is EVIDENCE toward a control, never a conformity assessment,
    certification, or safety guarantee. Every mapping entry carries an explicit
    ``does_not_establish`` note.
  * Stdlib only in this module. Nothing is written to disk or the network here;
    signing (DSSE/Sigstore) is a separate, out-of-band concern.
"""
import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from ._receipt import _BODY_FIELDS, canonical_json

# In-toto Statement envelope type — the stable, ecosystem-standard URI. Defined
# locally (not imported) so importing this package never requires szl-receipt at
# import time; it mirrors the identical constant in ``szl_receipt.attest``.
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Our OWN predicate type. Honest: this is an SZL predicate, SLSA-*shaped* for
# recognizability — it is NOT a claim of official SLSA-provenance conformance.
SZL_PREDICATE_TYPE = "https://a-11-oy.com/attest/governed-inference/v0.1"

ATTEST_DOCTRINE = (
    "SZL Holdings · in-toto/SLSA-shaped attestation over an honest, hash-chained "
    "governed-inference receipt · MEASURED energy only (else UNAVAILABLE) · "
    "EVIDENCE toward a control, NOT a conformity assessment or safety guarantee · "
    "Lambda = Conjecture 1 (advisory) · trust never 100%"
)


def _shared():
    """Lazily import the shared :mod:`szl_receipt.attest` layer.

    Attestation is an interop feature that reuses the ONE canonical home for the
    ecosystem shapes and the regulator catalogue (the same ``szl-receipt`` library
    used for signing). If it is not installed we raise a clear, honest error —
    never a silent, drift-prone local reimplementation.
    """
    try:
        from szl_receipt import attest as _a  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise ImportError(
            "governed_inference_meter attestation requires the shared 'szl-receipt' "
            "library (pip install 'governed-inference-meter[sign]', or "
            "pip install szl-receipt). Underlying import error: %r" % (exc,)
        ) from exc
    return _a


def _receipt_body(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the exact canonical body (the hashed fields) from a receipt."""
    return {k: receipt[k] for k in _BODY_FIELDS}


def _body_digest(body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _measured(receipt: Dict[str, Any]) -> bool:
    """True only when real energy was measured (mode set and joules present)."""
    return receipt.get("mode") != "unmeasured" and receipt.get("joules") is not None


def to_intoto_statement(
    receipt: Dict[str, Any],
    *,
    subject_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Render *receipt* as an in-toto Statement v1 with an SLSA-shaped predicate.

    The Statement's single subject is the receipt itself, bound by its SHA-256
    body digest, so the attestation is inseparable from the exact record it
    describes. All energy fields are copied verbatim (honest ``null`` when the
    receipt was unmeasured). The returned dict is the *unsigned* payload that a
    DSSE/Sigstore signer would then wrap.
    """
    a = _shared()
    body = _receipt_body(receipt)
    digest = receipt.get("digest") or _body_digest(body)
    measured = _measured(receipt)
    name = subject_name or "governed-inference-receipt/seq-{}".format(
        receipt.get("seq", "?")
    )
    predicate = a.slsa_predicate(
        build_type=SZL_PREDICATE_TYPE,
        external_parameters={
            "model": receipt.get("model"),
            "tokens_in": receipt.get("tokens_in"),
            "tokens_out": receipt.get("tokens_out"),
        },
        internal_parameters={
            "policy_decision": receipt.get("policy_decision"),
            "policy_reason": receipt.get("policy_reason"),
        },
        builder_id=SZL_PREDICATE_TYPE,
        metadata={
            "energy_mode": receipt.get("mode"),
            "measured": measured,
            # Verbatim, honest-null when unmeasured. Never fabricated.
            "joules": receipt.get("joules"),
            "wall_seconds": receipt.get("wall_seconds"),
            "tokens_per_joule": receipt.get("tokens_per_joule"),
        },
        extra={"doctrine": ATTEST_DOCTRINE},
    )
    # Bind the receipt's chain position into the run details (product-specific).
    predicate["runDetails"]["receipt"] = {
        "seq": receipt.get("seq"),
        "prev": receipt.get("prev"),
        "digest": digest,
    }
    return a.build_statement(
        subject_name=name,
        subject_digest=digest,
        predicate=predicate,
        predicate_type=SZL_PREDICATE_TYPE,
    )


def compliance_evidence(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Map *receipt* onto EU AI Act / NIST AI RMF controls it evidences.

    Returns a dict with per-control ``status`` — ``"supports"`` when the receipt
    provides operational evidence for that control, or ``"UNAVAILABLE"`` for an
    energy-dependent control on an unmeasured receipt. Every entry carries an
    explicit ``does_not_establish`` note. This is EVIDENCE, never a conformity
    assessment or certification.
    """
    a = _shared()
    measured = _measured(receipt)
    # A governed-inference receipt always logs (hash chain), is tamper-evident,
    # and records an advisory governance decision; energy is capability-gated.
    capabilities = {
        "logging": True,
        "integrity": True,
        "governance": True,
        "energy": measured,
    }
    ev = a.compliance_evidence(
        capabilities=capabilities,
        subject_digest=receipt.get("digest"),
        extra={
            "receipt_seq": receipt.get("seq"),
            "receipt_digest": receipt.get("digest"),
            "doctrine": ATTEST_DOCTRINE,
        },
    )
    return ev


def attest(
    receipt: Dict[str, Any],
    *,
    subject_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience: the in-toto Statement plus its compliance-evidence mapping."""
    return {
        "statement": to_intoto_statement(receipt, subject_name=subject_name),
        "compliance": compliance_evidence(receipt),
    }


def verify_statement(
    statement: Dict[str, Any],
    receipt: Dict[str, Any],
) -> Tuple[bool, str]:
    """Confirm *statement* is bound to *receipt*. Returns ``(ok, reason)``.

    Re-derives the receipt body digest and checks it matches BOTH the receipt's
    own ``digest`` and the Statement subject digest — so an attestation cannot
    drift from, or be swapped away from, the exact record it claims to describe.
    """
    a = _shared()
    try:
        body = _receipt_body(receipt)
    except KeyError as exc:  # receipt missing a hashed field
        return (False, "receipt-missing-field:{}".format(exc.args[0]))
    recomputed = _body_digest(body)
    if receipt.get("digest") != recomputed:
        return (False, "receipt-digest-mismatch")
    return a.verify_statement(
        statement, expected_digest=recomputed, predicate_type=SZL_PREDICATE_TYPE
    )


def to_json(obj: Dict[str, Any]) -> str:
    """Canonical (sorted, compact) JSON — the bytes a DSSE signer would cover."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
