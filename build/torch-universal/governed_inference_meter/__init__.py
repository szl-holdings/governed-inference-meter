# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""governed_inference_meter — energy-metered, governed inference receipts.

A lightweight, dependency-light utility (and Hugging Face *universal* kernel)
that wraps an inference call and emits a GOVERNED, ENERGY-METERED RECEIPT:

  * measures GPU energy via NVML (power/energy readback) integrated over
    wall-time -> joules,
  * computes tokens-per-joule,
  * runs a pluggable, advisory policy gate (allow/deny; defaults to allow),
  * and emits a tamper-evident, SHA-256 hash-chained JSON receipt.

It is the energy+governance counterpart to SZL Holdings'
``SZLHOLDINGS/szl-governed-norm`` — provenance at the inference boundary, in
the spirit of the a11oy governed-AI platform (https://a-11-oy.com).

Load from the Hub::

    from kernels import get_kernel
    gim = get_kernel("SZLHOLDINGS/governed-inference-meter")

    print(gim.__version__)
    print(gim.capability_report())   # what energy measurement is possible here

    # Wrap any inference callable. The callable returns the model output;
    # you tell the meter how many tokens went in/out.
    def run(prompt):
        # ... your real model call here ...
        return "the model's response text"

    receipt, output = gim.meter(
        run, args=("hello",),
        model="my-llm-7b",
        tokens_in=2, tokens_out=7,
    )
    print(receipt["mode"], receipt["joules"], receipt["tokens_per_joule"])
    print(receipt["digest"])         # tamper-evident over the whole record
    print(gim.receipt_verify())      # (ok, depth, first_break_seq)

Or as a decorator / context manager — see ``meter`` and ``metered``.

HONESTY (Λ = Conjecture 1, advisory — NOT a theorem):
  * Energy is MEASURED only when NVML is present and grants readback.
    Without it the receipt is ``mode="unmeasured"`` and ``joules=None`` /
    ``tokens_per_joule=None``. We never fabricate joules.
  * The policy gate is ADVISORY and host-enforced. This is a metering +
    receipt utility, NOT a safety guarantee.
  * The receipt digest is an integrity fingerprint (tamper-evidence), not a
    cryptographic signature.

Dependencies: Python stdlib + ``pynvml`` (optional; only used when present).
``torch`` is optional and only used to opportunistically synchronize the GPU
so energy is attributed to the right wall-time window.
"""
import contextlib
import time
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from . import _attest, _energy, _policy, _receipt
from ._attest import (
    IN_TOTO_STATEMENT_TYPE,
    SZL_PREDICATE_TYPE,
    attest,
    compliance_evidence,
    to_intoto_statement,
    verify_statement,
)
from ._energy import (
    MODE_ENERGY_COUNTER,
    MODE_POWER_INTEGRAL,
    MODE_UNMEASURED,
    EnergyMeter,
    capability_report,
    nvml_available,
)
from ._policy import ALLOW, DENY, PolicyResult, allow_all, deny_all, evaluate
from ._receipt import ReceiptChain, default_chain

__all__ = [
    "meter",
    "metered",
    "EnergyMeter",
    "ReceiptChain",
    "PolicyResult",
    "allow_all",
    "deny_all",
    "capability_report",
    "nvml_available",
    "receipt_head",
    "receipt_count",
    "receipt_tail",
    "receipt_verify",
    "selfcheck",
    "attest",
    "to_intoto_statement",
    "compliance_evidence",
    "verify_statement",
    "IN_TOTO_STATEMENT_TYPE",
    "SZL_PREDICATE_TYPE",
    "DOCTRINE_FOOTER",
    "MODE_UNMEASURED",
    "MODE_ENERGY_COUNTER",
    "MODE_POWER_INTEGRAL",
    "ALLOW",
    "DENY",
    "__version__",
]

__version__ = "0.2.0"
DOCTRINE_FOOTER = (
    "SZL Holdings · governed, energy-metered inference receipts · "
    "MEASURED only with NVML · policy gate is advisory (host-enforced) · "
    "Lambda = Conjecture 1 (advisory, NOT a theorem) · trust never 100% · "
    "honesty over checklist"
)


def _maybe_cuda_sync() -> None:
    """Synchronize CUDA if torch+CUDA are present, so energy maps to the call.

    Optional and best-effort: import errors or CPU-only torch are ignored.
    """
    try:  # pragma: no cover - environment dependent
        import torch  # type: ignore

        if torch.cuda.is_available():
            torch.cuda.synchronize()
    except Exception:  # noqa: BLE001
        pass


def meter(
    fn: Callable[..., Any],
    *,
    args: Sequence[Any] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    model: str = "unspecified",
    tokens_in: int = 0,
    tokens_out: int = 0,
    policy: Optional[_policy.PolicyGate] = None,
    chain: Optional[ReceiptChain] = None,
    device_index: int = 0,
    sample_hz: float = 100.0,
    sign_key: Optional[Any] = None,
    organ: str = "governed-inference-meter",
) -> Tuple[Dict[str, Any], Any]:
    """Run ``fn(*args, **kwargs)`` under an energy meter + policy gate.

    Returns ``(receipt, output)``. If the policy gate DENIES, ``fn`` is NOT
    called, ``output`` is ``None``, and the receipt records the denial with
    ``mode="unmeasured"`` (nothing ran, so nothing is measured).

    The receipt is appended to ``chain`` (or the module default chain) and is
    a plain dict with a SHA-256 ``digest`` over its canonical body.
    """
    kwargs = dict(kwargs or {})
    ch = chain if chain is not None else default_chain()
    gate = policy if policy is not None else allow_all

    context = {
        "model": model,
        "tokens_in": int(tokens_in),
        "tokens_out": int(tokens_out),
        "args": args,
        "kwargs": kwargs,
        "ts": time.time(),
    }
    decision = evaluate(gate, context)

    if not decision.allowed:
        # Fail-safe: do not execute on deny. Record an honest unmeasured receipt.
        rec = ch.emit(
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            energy={"mode": MODE_UNMEASURED, "joules": None, "wall_seconds": 0.0},
            policy_decision=decision.decision,
            policy_reason=decision.reason,
            sign_key=sign_key,
            organ=organ,
        )
        return rec, None

    em = EnergyMeter(device_index=device_index, sample_hz=sample_hz)
    _maybe_cuda_sync()
    em.start()
    try:
        output = fn(*args, **kwargs)
    finally:
        _maybe_cuda_sync()
        energy = em.stop()

    rec = ch.emit(
        model=model,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        energy=energy,
        policy_decision=decision.decision,
        policy_reason=decision.reason,
        sign_key=sign_key,
        organ=organ,
    )
    return rec, output


@contextlib.contextmanager
def metered(
    *,
    model: str = "unspecified",
    tokens_in: int = 0,
    tokens_out: int = 0,
    policy: Optional[_policy.PolicyGate] = None,
    chain: Optional[ReceiptChain] = None,
    device_index: int = 0,
    sample_hz: float = 100.0,
    sign_key: Optional[Any] = None,
    organ: str = "governed-inference-meter",
):
    """Context-manager form. Yields a mutable ``state`` dict; on exit it holds
    ``state["receipt"]``. The policy gate is evaluated on entry; on DENY the
    body still runs is the host's choice — for fail-safe semantics use
    :func:`meter`. Here we record the decision and always meter the block.

    You may update ``state["tokens_out"]`` inside the block (e.g. once you know
    how many tokens were generated) and it will be used in the receipt.
    """
    kwargs_ch = chain if chain is not None else default_chain()
    gate = policy if policy is not None else allow_all
    state: Dict[str, Any] = {
        "model": model,
        "tokens_in": int(tokens_in),
        "tokens_out": int(tokens_out),
        "receipt": None,
    }
    decision = evaluate(gate, dict(state, ts=time.time()))
    em = EnergyMeter(device_index=device_index, sample_hz=sample_hz)
    _maybe_cuda_sync()
    em.start()
    try:
        yield state
    finally:
        _maybe_cuda_sync()
        energy = em.stop()
        state["receipt"] = kwargs_ch.emit(
            model=state["model"],
            tokens_in=int(state["tokens_in"]),
            tokens_out=int(state["tokens_out"]),
            energy=energy,
            policy_decision=decision.decision,
            policy_reason=decision.reason,
            sign_key=sign_key,
            organ=organ,
        )


# --- Convenience accessors over the module default chain -------------------

def receipt_head() -> str:
    return default_chain().head()


def receipt_count() -> int:
    return default_chain().count()


def receipt_tail(n: int = 10):
    return default_chain().tail(n)


def receipt_verify():
    return default_chain().verify()


def selfcheck() -> Dict[str, Any]:
    """One-shot end-to-end check on a fresh chain. No GPU required.

    Exercises: a metered allow call, a denied call, tokens/joule honesty, and
    chain verification + tamper detection. Returns a dict of results; this is
    a *functional* check, NOT a benchmark, and emits NO fabricated energy.
    """
    ch = ReceiptChain()

    def fake_infer(prompt: str) -> str:
        # A trivial deterministic stand-in. Sleep a hair so the power-integral
        # path (when a real GPU is present) has a window to sample.
        time.sleep(0.002)
        return prompt[::-1]

    rec1, out1 = meter(
        fake_infer, args=("hello",), model="selfcheck-stub",
        tokens_in=1, tokens_out=5, chain=ch,
    )
    rec2, out2 = meter(
        fake_infer, args=("blocked",), model="selfcheck-stub",
        tokens_in=1, tokens_out=5, chain=ch, policy=deny_all,
    )

    ok, depth, brk = ch.verify()

    # Tamper test: mutate a record and confirm verify() catches it.
    tampered = False
    if ch._records:  # noqa: SLF001 - intentional white-box self-test
        saved = ch._records[0]["tokens_out"]
        ch._records[0]["tokens_out"] = saved + 1
        bad_ok, _, bad_brk = ch.verify()
        tampered = (not bad_ok) and (bad_brk == 0)
        ch._records[0]["tokens_out"] = saved  # restore

    cap = capability_report()
    return {
        "version": __version__,
        "nvml_available": nvml_available(),
        "energy_mode_first_call": rec1["mode"],
        "joules_honest_when_unmeasured": (
            rec1["joules"] is None if rec1["mode"] == MODE_UNMEASURED else True
        ),
        "tpj_honest_when_unmeasured": (
            rec1["tokens_per_joule"] is None
            if rec1["mode"] == MODE_UNMEASURED else True
        ),
        "allow_call_ran": out1 == "olleh",
        "deny_call_blocked": out2 is None and rec2["policy_decision"] == DENY,
        "chain_ok": ok,
        "chain_depth": depth,
        "tamper_detected": tampered,
        "preferred_energy_mode": cap["preferred_mode"],
        "doctrine": DOCTRINE_FOOTER,
        "passed": bool(
            ok and tampered and out1 == "olleh" and out2 is None
            and (rec1["joules"] is None or rec1["mode"] != MODE_UNMEASURED)
        ),
    }
