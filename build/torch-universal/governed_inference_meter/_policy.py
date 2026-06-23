# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""Pluggable, advisory policy gate for governed inference.

A policy gate is any callable ``(context: dict) -> PolicyResult`` (or a
``(decision, reason)`` tuple, or a plain bool) that the host supplies. It runs
*before* the metered call and its decision is recorded in the receipt.

HONESTY (Λ = Conjecture 1, advisory):
- This gate is ADVISORY. It records a decision into a tamper-evident receipt;
  it does NOT, and cannot, enforce anything by itself. Enforcement is the
  host's responsibility (the host must actually skip the call on "deny").
  This utility never claims to be a safety guarantee.
- The DEFAULT gate is ``allow_all`` — it allows every call and says so. We do
  not pretend to ship a meaningful safety policy out of the box.
- A gate that raises is treated as a hard DENY with the exception text as the
  reason (fail-closed), so a buggy policy cannot silently allow traffic.
"""
from typing import Any, Callable, Dict, Tuple, Union

ALLOW = "allow"
DENY = "deny"

# A gate may return: PolicyResult, (decision, reason), bool, or a bare str.
PolicyReturn = Union["PolicyResult", Tuple[str, str], bool, str]
PolicyGate = Callable[[Dict[str, Any]], PolicyReturn]


class PolicyResult:
    """Normalized result of a policy-gate evaluation."""

    __slots__ = ("decision", "reason")

    def __init__(self, decision: str, reason: str = "") -> None:
        d = str(decision).lower()
        self.decision = ALLOW if d == ALLOW else DENY
        self.reason = str(reason)

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"PolicyResult(decision={self.decision!r}, reason={self.reason!r})"


def allow_all(context: Dict[str, Any]) -> PolicyResult:
    """Default gate: allow everything, honestly labeled as a no-op policy."""
    return PolicyResult(ALLOW, "default allow_all gate (no policy configured)")


def deny_all(context: Dict[str, Any]) -> PolicyResult:
    """Convenience gate that denies everything (useful for tests/lockdown)."""
    return PolicyResult(DENY, "deny_all gate")


def normalize(ret: PolicyReturn) -> PolicyResult:
    """Coerce any supported gate return value into a ``PolicyResult``."""
    if isinstance(ret, PolicyResult):
        return ret
    if isinstance(ret, tuple) and len(ret) == 2:
        return PolicyResult(ret[0], ret[1])
    if isinstance(ret, bool):
        return PolicyResult(ALLOW if ret else DENY,
                            "bool gate -> allow" if ret else "bool gate -> deny")
    if isinstance(ret, str):
        return PolicyResult(ret, f"str gate -> {ret}")
    # Unknown return shape: fail closed.
    return PolicyResult(DENY, f"unrecognized policy return: {type(ret).__name__}")


def evaluate(gate: PolicyGate, context: Dict[str, Any]) -> PolicyResult:
    """Run a gate fail-closed: any exception becomes a DENY with the reason."""
    try:
        return normalize(gate(context))
    except Exception as e:  # noqa: BLE001
        return PolicyResult(DENY, f"policy gate raised {type(e).__name__}: {e}")
