<!--
SPDX-License-Identifier: Apache-2.0
© Stephen P. Lutar Jr. (ORCID 0009-0001-0110-4173) · Doctrine v11 LOCKED
-->

# AGENTS.md — source of truth for AI coding agents (Forge, Claude Code, Cursor, Opus 4.8)

> This file is the doctrine-bearing context every AI coding agent must read **before**
> touching this repo. `CLAUDE.md` points here. When unsure, **prefer the honest label
> and ask before claiming.**

---

## What this repo is

**governed-inference-meter** — a Hugging Face Kernel Hub kernel that meters inference
energy (tokens-per-joule) and emits signed governance receipts. Pure-Python universal
kernel; correctness-verified; provenance-first. See [`README.md`](README.md).

## DOCTRINE — non-negotiable (v11 LOCKED)

Enforced, not aspirational. A diff that breaks one of these is a **doctrine failure**:

- **HONEST LABELS.** Never claim **MEASURED** without a real, fresh exporter delta.
  Unverified = **SAMPLE**; future = **ROADMAP**; design-only = **MODELED**.
  Never fabricate joules, proofs, signatures, or status. *HONESTY OVER CHECKLIST.*
- **NO BANNED TOKENS.** No marketing-hype superlatives; no retired codenames.
- **Λ = Conjecture 1**, never a theorem. Never claim "zero sorry."

## How to work here

- **Language:** Python 3.12. Format on save (ruff). 4-space indent, ≤120 cols.
- **Tests:** run `pytest` under `tests/` before proposing changes. Green required.
- **Build:** `pip install -e .` (see `pyproject.toml` / `build.toml`).
- **Security:** report vulns to security@szlholdings.com (see [`SECURITY.md`](SECURITY.md)).
  Never commit secrets — secret scanning + push protection are enforced org-wide.
- **Commits:** DCO required (`Signed-off-by:`). Changes to `main` go through a reviewed PR.
- **Supply chain:** SLSA L1, cosign keyless signing, CycloneDX SBOM per release.

## Before you claim done

1. Tests pass. 2. No fabricated labels/metrics. 3. No banned tokens.
4. PR opened (not pushed to main). 5. Honest status in the PR description.
