# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Tamper-evident, hash-chained energy receipts for governed inference.

Each metered inference call emits a small, deterministic receipt describing
the call — model id, token counts, measured energy (or honest unmeasured
state), tokens-per-joule, and the policy-gate decision — and hash-chains it
to the previous receipt. A sequence of receipts is then independently
auditable without trusting the caller: any edit to any past record breaks
the chain at that point and ``verify()`` reports where.

HONESTY (Λ = Conjecture 1, advisory):
- ``digest`` is a real SHA-256 over the canonical JSON body. It is an
  integrity fingerprint (tamper-evidence), NOT a cryptographic signature —
  it does not prove authorship. DSSE/Sigstore signing is a separate,
  out-of-band concern, intentionally not done here.
- ``tokens_per_joule`` is recorded ONLY when energy was measured. In
  ``unmeasured`` mode it is ``None`` — never a guessed efficiency number.
- Receipts live in an in-process append-only chain. Nothing is written to
  disk or the network from inside this module.
- Stdlib only. No third-party dependencies.
"""
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Union

# Genesis previous-hash for the first receipt in any chain.
_GENESIS = "0" * 64

# Logical signing-authority label stamped onto signature envelopes.
_ORGAN = "governed-inference-meter"


def _maybe_sign(
    body: Dict[str, Any],
    sign_key: Optional[Union[str, bytes]],
    organ: str,
) -> Optional[Dict[str, Any]]:
    """ADDITIVE szl-receipt signature layer over the receipt *body*.

    Returns a DSSE envelope (from ``szl_receipt.sign_receipt``) covering the
    exact canonical body, or ``None`` when szl-receipt is not installed (the
    module then behaves exactly as before — stdlib-only). Doctrine: with no
    *sign_key* the envelope is UNSIGNED-honest (``signed=False``); a signature
    is NEVER fabricated. The chain ``digest`` is computed independently and is
    unaffected — this is a pure add-on alongside the existing tamper-evidence.
    """
    try:
        from szl_receipt import Receipt, sign_receipt
    except Exception:  # noqa: BLE001 - signing is optional; absence is honest
        return None
    env = sign_receipt(Receipt(kind="governed-inference", body=body),
                       sign_key, organ=organ)
    return env

# Canonical field order of the *body* that gets hashed (ts/digest excluded).
_BODY_FIELDS = (
    "seq",
    "model",
    "tokens_in",
    "tokens_out",
    "mode",
    "joules",
    "wall_seconds",
    "tokens_per_joule",
    "policy_decision",
    "policy_reason",
    "prev",
)


def canonical_json(body: Dict[str, Any]) -> str:
    """Deterministic JSON serialization used for hashing (sorted, compact)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _digest_body(body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class ReceiptChain:
    """Append-only, SHA-256 hash-chained log of energy/governance receipts.

    Each receipt body is digested with SHA-256 over its canonical JSON; each
    record stores ``prev`` (the previous record's digest) so the chain is
    tamper-evident. ``verify()`` re-walks and returns
    ``(ok, depth, first_break_seq)``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: List[Dict[str, Any]] = []

    def emit(
        self,
        *,
        model: str,
        tokens_in: int,
        tokens_out: int,
        energy: Dict[str, Any],
        policy_decision: str,
        policy_reason: str,
        sign_key: Optional[Union[str, bytes]] = None,
        organ: str = _ORGAN,
    ) -> Dict[str, Any]:
        """Append one receipt and return it (a copy is safe to share).

        If *sign_key* (a PEM ECDSA-P256 private key) is supplied AND szl-receipt
        is installed, the returned record carries an additive ``signature``
        DSSE envelope. With no key the envelope is UNSIGNED-honest; with no
        szl-receipt the record is unchanged. The hash chain is never altered.
        """
        with self._lock:
            prev = self._records[-1]["digest"] if self._records else _GENESIS
            seq = len(self._records)
            mode = energy.get("mode", "unmeasured")
            joules = energy.get("joules", None)
            wall = energy.get("wall_seconds", None)
            # tokens/joule ONLY when energy was actually measured and positive.
            tpj: Optional[float] = None
            if joules is not None and joules > 0:
                tpj = round(float(tokens_out) / float(joules), 6)
            body = {
                "seq": seq,
                "model": str(model),
                "tokens_in": int(tokens_in),
                "tokens_out": int(tokens_out),
                "mode": str(mode),
                "joules": (round(float(joules), 6) if joules is not None else None),
                "wall_seconds": (round(float(wall), 9) if wall is not None else None),
                "tokens_per_joule": tpj,
                "policy_decision": str(policy_decision),
                "policy_reason": str(policy_reason),
                "prev": prev,
            }
            digest = _digest_body(body)
            rec = dict(body, digest=digest, ts=time.time())
            sig = _maybe_sign(body, sign_key, organ)
            if sig is not None:
                rec["signature"] = sig
            self._records.append(rec)
            return dict(rec)

    def head(self) -> str:
        with self._lock:
            return self._records[-1]["digest"] if self._records else _GENESIS

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def tail(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._records[-n:]]

    def to_jsonl(self) -> str:
        """Export the whole chain as newline-delimited JSON (audit handoff)."""
        with self._lock:
            return "\n".join(canonical_json(r) for r in self._records)

    def verify(self):
        """Re-walk the chain. Returns ``(ok: bool, depth: int, first_break: int)``.

        ``first_break`` is the seq of the first broken record, or ``-1`` if OK.
        """
        with self._lock:
            prev = _GENESIS
            for i, rec in enumerate(self._records):
                body = {k: rec[k] for k in _BODY_FIELDS}
                if rec["prev"] != prev or rec["digest"] != _digest_body(body):
                    return (False, len(self._records), i)
                prev = rec["digest"]
            return (True, len(self._records), -1)


# Module-level default chain (opt-in: only written when you use the default).
_DEFAULT_CHAIN: Optional[ReceiptChain] = None
_chain_lock = threading.Lock()


def default_chain() -> ReceiptChain:
    global _DEFAULT_CHAIN
    with _chain_lock:
        if _DEFAULT_CHAIN is None:
            _DEFAULT_CHAIN = ReceiptChain()
        return _DEFAULT_CHAIN
