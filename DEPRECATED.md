# DEPRECATED — this repo has been consolidated into `szl-energy-attest`

**Status: DEPRECATED (Wave D consolidation). Canonical home: [`szl-holdings/szl-energy-attest`](https://github.com/szl-holdings/szl-energy-attest).**

`governed-inference-meter` was a duplicate SZL *energy* micro-repo. To keep ONE
canonical energy package, its **unique** code has been **copied (folded) into
the canonical `szl-energy-attest` repo** under the subpackage
[`szl_energy_attest.inference_meter`](https://github.com/szl-holdings/szl-energy-attest/tree/main/szl_energy_attest/inference_meter).

Nothing here was deleted. This repository is **kept intact and reversible** —
**archiving it is a later founder step**, not part of this consolidation.

## What moved (and where)

Only the code the canonical package did **not** already have was folded in — the
**live inference metering** surface:

| This repo (`governed_inference_meter`) | Canonical home (`szl_energy_attest.inference_meter`) |
| --- | --- |
| `EnergyMeter` + `capability_report` + `nvml_available` (`_energy.py`) — NVML **energy-counter** *and* **power-integral (trapezoidal)** estimators | `szl_energy_attest.inference_meter.EnergyMeter` / `capability_report` / `nvml_available` |
| Advisory policy gate: `PolicyResult`, `allow_all`, `deny_all`, `evaluate`, `ALLOW`/`DENY` (`_policy.py`) | same names under `szl_energy_attest.inference_meter` |
| `ReceiptChain` + `meter()` / `metered()` wrappers with tokens-per-joule (`_receipt.py`, `__init__.py`) | `szl_energy_attest.inference_meter.ReceiptChain` / `meter` / `metered` |
| `selfcheck`, `receipt_head/count/tail/verify` | same names under `szl_energy_attest.inference_meter` |
| `test_meter.py` | `szl-energy-attest/tests/test_inference_meter.py` |

### What was NOT re-copied (deduped)

The canonical `szl-energy-attest` package **already provided** these, so the
duplicates here were intentionally *not* copied (to avoid drift):

- the attestable, hash-chained energy **receipt schema** + offline verifier,
- the **in-toto / SLSA-shaped** attestation + EU-AI-Act / NIST-AI-RMF mapping
  (`_attest.py`),
- the canonical **PCGI szl-receipt** binding / spine fold (`_spine.py`),
- the DSSE/HMAC **signing** layer.

## Migration

```python
# Before
import governed_inference_meter as gim
receipt, output = gim.meter(run, args=("hello",), model="m", tokens_in=2, tokens_out=7)

# After (canonical)
from szl_energy_attest import inference_meter as gim
receipt, output = gim.meter(run, args=("hello",), model="m", tokens_in=2, tokens_out=7)
```

## Honesty note (unchanged)

The doctrine labels are preserved verbatim in the folded copy: energy is
**MEASURED only** with NVML (else `mode="unmeasured"`, `joules=None` — never a
fabricated joule), the policy gate is **advisory** (host-enforced, not a safety
guarantee), the receipt digest is tamper-evidence (not a signature), and
**Λ = Conjecture 1 (advisory, uniqueness OPEN)** — never upgraded to proven.
