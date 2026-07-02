# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Standards-interop + compliance-evidence layer for governed-inference receipts.

A governed-inference receipt (see :mod:`._receipt`) is an honest, tamper-evident,
hash-chained record of one metered inference call. This module lets that record
*speak the wider ecosystem's language* without changing a single measured value:

  1. :func:`to_intoto_statement` renders a receipt as an **in-toto Statement v1**
     — the exact JSON payload that Sigstore / DSSE / IETF SCITT tooling already
     knows how to carry, sign, and store in a transparency log. The predicate is
     laid out in SLSA-v1 provenance shape (``buildDefinition`` / ``runDetails``)
     so an auditor recognizes it on sight.
  2. :func:`compliance_evidence` maps the receipt onto the specific **EU AI Act**
     articles and **NIST AI RMF** functions it provides operational evidence for
     (record-keeping, automatic logging, energy transparency), and — per the
     honesty doctrine — states plainly what it does **NOT** establish.
  3. :func:`verify_statement` re-derives the receipt body digest and confirms the
     Statement's subject is bound to that exact receipt, so an attestation can
     never silently drift from the record it claims to describe.

HONESTY (Λ = Conjecture 1, advisory — NOT a theorem):
  * We emit our OWN predicate type URI. We do NOT claim official SLSA-provenance
    conformance; the shape is SLSA-*inspired* for recognizability only.
  * Energy fields are copied verbatim from the receipt. When the receipt is
    ``mode="unmeasured"`` the energy evidence is reported ``UNAVAILABLE`` — never
    a fabricated joule or efficiency number.
  * A receipt is EVIDENCE toward a control, never a conformity assessment,
    certification, or a safety guarantee. Every mapping entry carries an explicit
    ``does_not_establish`` note.
  * Stdlib only. Nothing is written to disk or the network from this module.
    Signing (DSSE/Sigstore) is a separate, out-of-band concern (see
    ``sign_key`` on the receipt layer); this module produces the *unsigned*
    Statement payload that such tooling would then sign.
"""
import hashlib
import json
from typing import Any, Dict, List, Optional

from ._receipt import _BODY_FIELDS, canonical_json

# In-toto Statement envelope type (stable, ecosystem-standard).
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Our OWN predicate type. Honest: this is an SZL predicate, SLSA-*shaped* for
# recognizability — it is NOT a claim of official SLSA-provenance conformance.
SZL_PREDICATE_TYPE = "https://a-11-oy.com/attest/governed-inference/v0.1"

_UNAVAILABLE = "UNAVAILABLE"

ATTEST_DOCTRINE = (
    "SZL Holdings · in-toto/SLSA-shaped attestation over an honest, hash-chained "
    "governed-inference receipt · MEASURED energy only (else UNAVAILABLE) · "
    "EVIDENCE toward a control, NOT a conformity assessment or safety guarantee · "
    "Lambda = Conjecture 1 (advisory) · trust never 100%"
)

# --- Compliance control catalogue -----------------------------------------
# Each entry states what a governed-inference receipt HONESTLY provides evidence
# for, and — doctrine-critical — what it does NOT establish. Energy-dependent
# controls resolve to UNAVAILABLE when the receipt is unmeasured.
_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "EU-AI-Act-Art-12",
        "title": "Record-keeping — automatic recording of events (logs)",
        "kind": "logging",
        "establishes": (
            "Each inference call is automatically recorded in a tamper-evident, "
            "hash-chained log with model id, token counts and the governance "
            "decision — automatic event logging over the system's operation."
        ),
        "does_not_establish": (
            "Does not itself define log retention duration or the risk-management "
            "system those logs feed; that is an operator responsibility."
        ),
    },
    {
        "id": "EU-AI-Act-Art-19",
        "title": "Automatically generated logs — availability & integrity",
        "kind": "logging",
        "establishes": (
            "The SHA-256 chain makes any post-hoc edit or reordering of the logs "
            "detectable, so retained logs are demonstrably intact when produced."
        ),
        "does_not_establish": (
            "Does not enforce the retention period or storage of the logs; the "
            "chain proves integrity, not that logs were kept for the required time."
        ),
    },
    {
        "id": "EU-AI-Act-Art-15",
        "title": "Accuracy, robustness and cybersecurity",
        "kind": "integrity",
        "establishes": (
            "Tamper-evidence contributes to record integrity / resistance to "
            "log manipulation (a cybersecurity-relevant property)."
        ),
        "does_not_establish": (
            "Does NOT establish model accuracy or robustness — it says nothing "
            "about the correctness of the model's outputs."
        ),
    },
    {
        "id": "NIST-AI-RMF-MEASURE-2.x",
        "title": "MEASURE — track quantitative metrics (energy / efficiency)",
        "kind": "energy",
        "establishes": (
            "Measured GPU joules and tokens-per-joule are recorded per call, "
            "giving an auditable quantitative efficiency/energy metric."
        ),
        "does_not_establish": (
            "When energy is unmeasured no efficiency claim is made; and the "
            "metric measures cost/energy, not model quality or safety."
        ),
    },
    {
        "id": "NIST-AI-RMF-MANAGE-4.1",
        "title": "MANAGE — post-deployment monitoring & logging",
        "kind": "logging",
        "establishes": (
            "A continuous, verifiable per-call log supports ongoing monitoring "
            "of a deployed system's inference activity and governance decisions."
        ),
        "does_not_establish": (
            "Does not define incident response or remediation; it is the "
            "monitoring substrate, not the management process itself."
        ),
    },
    {
        "id": "NIST-AI-RMF-GOVERN-1.x",
        "title": "GOVERN — documented, auditable governance decisions",
        "kind": "governance",
        "establishes": (
            "The advisory policy decision (allow/deny) and its reason are recorded "
            "alongside each call, documenting the governance decision made."
        ),
        "does_not_establish": (
            "The gate is ADVISORY and host-enforced; recording a decision is not "
            "proof the decision was enforced by the runtime."
        ),
    },
]


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
    DSSE/Sigstore signer would then wrap — signing is out of scope here.
    """
    body = _receipt_body(receipt)
    digest = receipt.get("digest") or _body_digest(body)
    measured = _measured(receipt)
    name = subject_name or "governed-inference-receipt/seq-{}".format(
        receipt.get("seq", "?")
    )
    predicate = {
        "buildDefinition": {
            "buildType": SZL_PREDICATE_TYPE,
            "externalParameters": {
                "model": receipt.get("model"),
                "tokens_in": receipt.get("tokens_in"),
                "tokens_out": receipt.get("tokens_out"),
            },
            "internalParameters": {
                "policy_decision": receipt.get("policy_decision"),
                "policy_reason": receipt.get("policy_reason"),
            },
        },
        "runDetails": {
            "builder": {"id": SZL_PREDICATE_TYPE},
            "metadata": {
                "energy_mode": receipt.get("mode"),
                "measured": measured,
                # Verbatim, honest-null when unmeasured. Never fabricated.
                "joules": receipt.get("joules"),
                "wall_seconds": receipt.get("wall_seconds"),
                "tokens_per_joule": receipt.get("tokens_per_joule"),
            },
            "receipt": {
                "seq": receipt.get("seq"),
                "prev": receipt.get("prev"),
                "digest": digest,
            },
        },
        "doctrine": ATTEST_DOCTRINE,
    }
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": SZL_PREDICATE_TYPE,
        "predicate": predicate,
    }


def compliance_evidence(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Map *receipt* onto EU AI Act / NIST AI RMF controls it evidences.

    Returns a dict with per-control ``status`` — ``"supports"`` when the receipt
    provides operational evidence for that control, or ``"UNAVAILABLE"`` for an
    energy-dependent control on an unmeasured receipt. Every entry carries an
    explicit ``does_not_establish`` note. This is EVIDENCE, never a conformity
    assessment or certification.
    """
    measured = _measured(receipt)
    controls: List[Dict[str, Any]] = []
    for c in _CONTROLS:
        if c["kind"] == "energy" and not measured:
            status = _UNAVAILABLE
            note = "energy unmeasured on this receipt — no efficiency evidence"
        else:
            status = "supports"
            note = c["establishes"]
        controls.append(
            {
                "id": c["id"],
                "title": c["title"],
                "status": status,
                "evidence": note,
                "does_not_establish": c["does_not_establish"],
            }
        )
    return {
        "receipt_seq": receipt.get("seq"),
        "receipt_digest": receipt.get("digest"),
        "measured_energy": measured,
        "controls": controls,
        "disclaimer": (
            "This is machine-readable EVIDENCE toward the listed controls, not a "
            "conformity assessment, certification, or safety guarantee. A receipt "
            "documents what happened; it does not by itself make a system compliant."
        ),
        "doctrine": ATTEST_DOCTRINE,
    }


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
) -> Any:
    """Confirm *statement* is bound to *receipt*. Returns ``(ok, reason)``.

    Re-derives the receipt body digest and checks it matches BOTH the receipt's
    own ``digest`` and the Statement subject digest — so an attestation cannot
    drift from, or be swapped away from, the exact record it claims to describe.
    """
    try:
        body = _receipt_body(receipt)
    except KeyError as exc:  # receipt missing a hashed field
        return (False, "receipt-missing-field:{}".format(exc.args[0]))
    recomputed = _body_digest(body)
    if receipt.get("digest") != recomputed:
        return (False, "receipt-digest-mismatch")
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        return (False, "not-an-intoto-statement")
    if statement.get("predicateType") != SZL_PREDICATE_TYPE:
        return (False, "unexpected-predicate-type")
    subjects = statement.get("subject") or []
    subj_digests = [s.get("digest", {}).get("sha256") for s in subjects]
    if recomputed not in subj_digests:
        return (False, "subject-digest-not-bound-to-receipt")
    return (True, "ok")


def to_json(obj: Dict[str, Any]) -> str:
    """Canonical (sorted, compact) JSON — the bytes a DSSE signer would cover."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
