---
license: apache-2.0
library_name: kernels
tags:
- kernel
- inference
- energy
- nvml
- governance
- provenance
- audit
- receipts
- tokens-per-joule
- sovereign-ai
---

# governed-inference-meter

**Energy-metered, governed inference receipts.** A lightweight, dependency-light
Python utility (and Hugging Face *universal* kernel) that wraps any inference
call and emits a **governed, energy-metered, tamper-evident receipt**:

- **measures GPU energy** via NVIDIA NVML (power/energy readback) integrated
  over wall-time → **joules**,
- computes **tokens-per-joule**,
- runs a pluggable, **advisory policy gate** (allow/deny; defaults to allow),
- and emits a **SHA-256 hash-chained JSON receipt** so a sequence of calls is
  independently auditable.

It is the energy + governance counterpart to
[`SZLHOLDINGS/szl-governed-norm`](https://huggingface.co/SZLHOLDINGS/szl-governed-norm)
— provenance at the inference boundary, in the spirit of the
[a11oy](https://a-11-oy.com) governed-AI platform: **receipts, not capability
claims.**

> **Why this exists.** Browse the [Kernel Hub](https://huggingface.co/models?other=kernel)
> and you find performance kernels — attention, activations, GEMM, norms. There
> is **no energy-metering + governance kernel**. Teams running inference in
> sovereign, regulated, or cost/carbon-sensitive contexts measure tokens/joule
> and keep audit trails *by hand*. This utility does both in one wrapped call,
> and degrades honestly when no GPU energy readback is available.

---

## Honest scope (read this first)

This project follows a strict honesty doctrine. **Λ (the governance trust
quantity) is Conjecture 1 — advisory, not a theorem. Trust is never 100%.**

- **MEASURED only with NVML.** Energy is real **only** when NVML is present and
  grants power/energy readback. Without it the receipt is labeled
  `mode="unmeasured"` and `joules` / `tokens_per_joule` are `null`. **We never
  fabricate a joule figure.**
- **Board-level power.** NVML reports whole-board power (compute die + memory +
  losses). We report what the hardware reports and say so. No modeling, no
  scaling factors.
- **The policy gate is advisory and host-enforced.** It records an allow/deny
  decision into the receipt. It does **not**, and cannot, enforce anything by
  itself — your host must actually skip a denied call. The bundled `meter()`
  wrapper *does* fail-safe (it will not execute a denied call), but downstream
  enforcement is still your responsibility.
- **The receipt digest is an integrity fingerprint, not a signature.** It is a
  SHA-256 over the canonical record body and makes tampering *evident*. It does
  **not** prove authorship. Cryptographic signing (e.g. DSSE/Sigstore) is a
  separate, out-of-band concern, intentionally not done here.
- **This is a metering + receipt utility, not a safety guarantee.**

---

## Install / load

**From the Hugging Face Hub** (universal kernel — runs on CPU and CUDA):

```python
from kernels import get_kernel
gim = get_kernel("SZLHOLDINGS/governed-inference-meter")
```

**From PyPI-style source** (zero hard dependencies; add `pynvml` for real
energy):

```bash
pip install kernels            # to load via get_kernel
# real GPU energy measurement additionally needs NVML bindings:
pip install pynvml
```

---

## Usage

```python
from kernels import get_kernel
gim = get_kernel("SZLHOLDINGS/governed-inference-meter")

print(gim.__version__)
print(gim.capability_report())   # what energy measurement is possible here

# Wrap ANY inference callable. You tell the meter the token counts.
def run(prompt):
    # ... your real model.generate(...) call here ...
    return "the model's response text"

receipt, output = gim.meter(
    run, args=("hello",),
    model="my-llm-7b",
    tokens_in=2, tokens_out=7,
)

print(receipt["mode"])             # 'measured-energy' | 'measured-power-integral' | 'unmeasured'
print(receipt["joules"])           # float, or None when unmeasured
print(receipt["tokens_per_joule"]) # float, or None when unmeasured
print(receipt["policy_decision"])  # 'allow' | 'deny'
print(receipt["digest"])           # SHA-256 over the canonical record body
print(gim.receipt_verify())        # (ok, depth, first_break_seq) over the chain
```

### A custom policy gate (advisory)

```python
def my_gate(ctx):
    # ctx has model, tokens_in, tokens_out, args, kwargs, ts
    if ctx["tokens_in"] > 8192:
        return ("deny", "prompt exceeds governed token budget")
    return ("allow", "within budget")

receipt, output = gim.meter(run, args=("hi",), model="m",
                            tokens_in=2, tokens_out=7, policy=my_gate)
```

A gate may return a `PolicyResult`, a `(decision, reason)` tuple, a bool, or a
string. **It runs fail-closed**: if your gate raises, the call is denied with
the exception text as the reason — a buggy policy can never silently allow.

### Per-request chain (no global-state contention)

```python
chain = gim.ReceiptChain()
gim.meter(run, args=("a",), model="m", tokens_in=1, tokens_out=4, chain=chain)
gim.meter(run, args=("b",), model="m", tokens_in=1, tokens_out=6, chain=chain)
print(chain.verify())              # tamper-evident over YOUR chain only
print(chain.to_jsonl())            # export the chain for offline audit
```

---

## MEASURED vs. `unmeasured` — what you get

| Environment | `mode` | `joules` | `tokens_per_joule` |
|---|---|---|---|
| NVIDIA GPU with energy counter (`nvmlDeviceGetTotalEnergyConsumption`) | `measured-energy` | hardware accumulator delta | computed |
| NVIDIA GPU, power readback only (`nvmlDeviceGetPowerUsage`) | `measured-power-integral` | trapezoidal integral of power samples | computed |
| No GPU / no driver / no permission / no `pynvml` | `unmeasured` | `null` | `null` |

### Sample receipt — `unmeasured` (illustrative; this build env has no GPU)

> **SAMPLE / illustrative.** Produced on a CPU-only box. Because NVML is
> unavailable, energy is honestly `unmeasured` and `joules` is `null` — exactly
> the honest-degrade behavior. **No energy number is invented.**

```json
{
  "seq": 0,
  "model": "my-llm-7b",
  "tokens_in": 2,
  "tokens_out": 7,
  "mode": "unmeasured",
  "joules": null,
  "wall_seconds": 0.004182,
  "tokens_per_joule": null,
  "policy_decision": "allow",
  "policy_reason": "default allow_all gate (no policy configured)",
  "prev": "0000000000000000000000000000000000000000000000000000000000000000",
  "digest": "<sha256 of the canonical body>",
  "ts": 1750000000.0
}
```

On a real NVIDIA GPU the same call would carry e.g.
`"mode": "measured-energy"`, a positive `"joules"`, and a computed
`"tokens_per_joule"`. We do **not** print example GPU numbers here because this
build environment cannot measure them, and inventing them would violate the
honesty doctrine. Run `gim.selfcheck()` on your own hardware to see your numbers.

---

## Self-test

```python
import governed_inference_meter as gim
print(gim.selfcheck())   # functional check (NOT a benchmark); no fabricated energy
```

`selfcheck()` runs a metered allow call, a denied call (verifying it does not
execute), checks tokens/joule honesty, verifies the hash chain, and confirms
that mutating a past record is detected. It requires no GPU.

---

## Attestation & compliance evidence (interop layer)

A receipt is only as useful as the tools that can *carry* it. This module renders
any receipt into the formats the wider ecosystem already understands — without
changing a single measured value.

```python
import governed_inference_meter as gim

rec, out = gim.meter(run, args=("hi",), model="my-llm", tokens_in=2, tokens_out=7)

# 1) The receipt as an in-toto Statement v1 — the exact payload that
#    Sigstore / DSSE / SCITT tooling signs and stores in a transparency log.
stmt = gim.to_intoto_statement(rec)          # SLSA-shaped predicate, our own type URI

# 2) EU AI Act / NIST AI RMF controls this receipt provides EVIDENCE for,
#    with an explicit does_not_establish note per control (honest, not a cert).
ev = gim.compliance_evidence(rec)

# 3) Confirm the Statement is cryptographically bound to this exact receipt.
ok, why = gim.verify_statement(stmt, rec)    # -> (True, "ok")
```

Honest boundaries (doctrine):

- The predicate uses **our own** `predicateType` URI and is only SLSA-*shaped*
  for auditor recognizability — it is **not** a claim of official SLSA
  conformance. Signing (DSSE/Sigstore) is out-of-band; this emits the unsigned
  Statement payload a signer would then cover.
- Energy fields are copied **verbatim**. On an unmeasured receipt, energy-dependent
  controls (e.g. `NIST-AI-RMF-MEASURE-2.x`) report **`UNAVAILABLE`** — never a
  fabricated joule. Logging / record-keeping controls (EU AI Act Art. 12 & 19)
  are supported regardless of GPU.
- A receipt is **evidence** toward a control, never a conformity assessment,
  certification, or safety guarantee.

---

## Canonical PCGI receipt (spine fold)

The meter is also a first-class **Proof-Carrying Governed Intelligence (PCGI)**
receipt producer on the org-canonical [`szl-receipt`](https://huggingface.co/SZLHOLDINGS)
spine. One call folds a metered inference into a single signed receipt that binds
**model id + input digest + output digest + governing policy id + energy** — the
same shape every other decision producer emits, so provenance unifies.

```python
import governed_inference_meter as gim
from szl_receipt import generate_keypair

priv, pub = generate_keypair()   # or sign_key=None for UNSIGNED-honest

# End-to-end: meter the call AND emit ONE canonical szl-receipt for it.
env, out = gim.meter_szl_receipt(
    run, args=("hi",), model="my-llm",
    policy_id="default-allow", sign_key=priv, organ="meter",
)
ok, why = gim.verify_szl_receipt(env, pub)      # -> (True, "ok")
stmt = gim.to_statement(env)                     # in-toto Statement v1, SLSA-shaped
ok2, _ = gim.verify_szl_statement(stmt, env)     # bound to this exact receipt

# Or fold an existing meter receipt you already have:
rec, out = gim.meter(run, args=("hi",), model="my-llm", tokens_in=2, tokens_out=7)
env = gim.from_meter_receipt(rec, input="hi", output=out, policy_id="default-allow")
```

Honest boundaries (doctrine):

- Reuses szl-receipt's **canonicalization + signing + in-toto shapes** — it does
  **not** invent a new receipt shape.
- **Energy** is bound **verbatim** only when the meter actually measured it
  (NVML present). Otherwise `energy.joules` is the literal string
  **`"UNAVAILABLE"`** and `energy.measured` is `False` — the meter is the one
  place in the spine where energy *can* be real, and it is never fabricated.
- The canonical body is **deterministic**: identical inputs serialize to
  byte-identical canonical JSON (no timestamps in the body).
- Keyless => **UNSIGNED-honest** (`signed=False`); a signature is never faked.
- The receipt is **evidence** binding a decision, **not** a proof the model's
  output is correct.

Requires the shared `szl-receipt` library (install extra `[sign]`); the import is
lazy, so importing this package stays zero-hard-dependency.

---

## What's in the repo

```
build.toml                                  # Kernel Hub universal-kernel manifest
build/torch-universal/governed_inference_meter/
  __init__.py     # meter() / metered() wrappers, selfcheck(), accessors
  _energy.py      # NVML energy + power-integral measurement, honest degrade
  _receipt.py     # SHA-256 hash-chained, tamper-evident receipts
  _policy.py      # advisory policy gate (allow_all default, fail-closed)
  _attest.py      # in-toto/SLSA-shaped Statements + EU AI Act / NIST AI RMF evidence
  _spine.py       # PCGI spine fold: metered inference -> ONE canonical szl-receipt
  metadata.json
pyproject.toml                              # also pip-installable from source
tests/test_meter.py                         # runs on CPU, no GPU needed
tests/test_attest.py                        # attestation + compliance, no GPU needed
tests/test_spine.py                         # canonical PCGI receipt fold, no GPU needed
LICENSE                                     # Apache-2.0
```

---

## Doctrine & honesty disclaimer

> SZL Holdings · governed, energy-metered inference receipts · **MEASURED only
> with NVML** · the policy gate is **advisory (host-enforced)** · **Λ =
> Conjecture 1** (advisory, *not* a theorem) · **trust never 100%** · honesty
> over checklist. This is a metering + receipt utility, **not** a safety
> guarantee. No fabricated benchmarks; energy is reported only when physically
> measured.

**License:** Apache-2.0 · **Maintainer:** Stephen Lutar
<stephenlutar2@gmail.com> · **Platform:** [a-11-oy.com](https://a-11-oy.com) — the
governed-inference substrate for hard missions.
