# DEPRECATED — this repo has been consolidated into `szl-energy-attest`

**Status: DEPRECATED (Wave D consolidation). Canonical home:**
[`szl-holdings/szl-energy-attest@4d8d105c`](https://github.com/szl-holdings/szl-energy-attest/tree/4d8d105c3d5ea67b5eb25826e8a2a35ca35f4043).

`governed-inference-meter` was a duplicate SZL *energy* micro-repo. To keep ONE
canonical energy package, its **unique** code has been **copied (folded) into
the canonical `szl-energy-attest` repo** under the subpackage
[`szl_energy_attest.inference_meter`](https://github.com/szl-holdings/szl-energy-attest/tree/4d8d105c3d5ea67b5eb25826e8a2a35ca35f4043/szl_energy_attest/inference_meter).

Nothing here was deleted. This repository is **kept intact and reversible** —
**archiving it is a later founder step**, not part of this consolidation.

## What moved (and where)

The fold contains the **live inference metering** surface plus the legacy
meter-specific compatibility adapters required to preserve public imports:

| This repo (`governed_inference_meter`) | Canonical home (`szl_energy_attest.inference_meter`) |
| --- | --- |
| `EnergyMeter` + `capability_report` + `nvml_available` (`_energy.py`) — NVML **energy-counter** *and* **power-integral (trapezoidal)** estimators | `szl_energy_attest.inference_meter.EnergyMeter` / `capability_report` / `nvml_available` |
| Advisory policy gate: `PolicyResult`, `allow_all`, `deny_all`, `evaluate`, `ALLOW`/`DENY` (`_policy.py`) | same names under `szl_energy_attest.inference_meter` |
| `ReceiptChain` + `meter()` / `metered()` wrappers with tokens-per-joule (`_receipt.py`, `__init__.py`) | `szl_energy_attest.inference_meter.ReceiptChain` / `meter` / `metered` |
| `selfcheck`, `receipt_head/count/tail/verify` | same names under `szl_energy_attest.inference_meter` |
| Meter-specific in-toto/compliance adapter (`_attest.py`) | `attest`, `to_intoto_statement`, `compliance_evidence`, `verify_statement` |
| Meter-specific PCGI spine/signing-facing adapter (`_spine.py`) | `emit_szl_receipt`, `from_meter_receipt`, `meter_szl_receipt`, receipt/statement verifiers |
| `test_meter.py` plus migration invariants | [`test_inference_meter.py`](https://github.com/szl-holdings/szl-energy-attest/blob/4d8d105c3d5ea67b5eb25826e8a2a35ca35f4043/tests/test_inference_meter.py) and [`test_inference_meter_migration.py`](https://github.com/szl-holdings/szl-energy-attest/blob/4d8d105c3d5ea67b5eb25826e8a2a35ca35f4043/tests/test_inference_meter_migration.py) |

### Compatibility surfaces retained with provenance

The canonical `szl-energy-attest` root package already has its own energy-receipt,
attestation, PCGI, and signing surfaces. Those are a distinct receipt schema, not
a drop-in replacement for every legacy meter import. For continuity:

- the meter-specific `_attest.py` adapter is retained with only its package name
  and install guidance rewritten to the canonical successor;
- the meter-specific `_spine.py` adapter is retained with only the package import
  and install guidance rewritten to the canonical successor name;
- the hardened `_receipt.py` chain verifier is retained byte-for-byte;
- signing and statement construction continue to delegate lazily to the shared
  `szl-receipt` library rather than forking cryptography.

The successor's immutable
[`MIGRATION_PROVENANCE.json`](https://github.com/szl-holdings/szl-energy-attest/blob/4d8d105c3d5ea67b5eb25826e8a2a35ca35f4043/MIGRATION_PROVENANCE.json)
records both legacy and successor SHA-256 digests and the bounded `_attest.py` /
`_spine.py` transformations. This preserves import and signing-facing continuity
without claiming that the legacy and root successor receipt schemas are equal,
that a key is configured, or that any receipt is signed.

## Deprecation boundary

- New integrations use `szl_energy_attest.inference_meter` at the verified
  successor revision above.
- This GitHub repository and its Hugging Face kernel remain readable as
  provenance and rollback surfaces; deprecation is not deletion.
- No new capability, install, schema-parity, measured-energy, or signature claim
  is made by this pointer correction.
- Archiving is **not authorized by this document**. It remains an explicit owner
  decision after the GitHub and Hugging Face pointers are live, active inbound
  references are repaired or classified, CI remains green, and rollback evidence
  is retained.

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
