# SPDX-License-Identifier: Apache-2.0
# © 2026 SZL Holdings · Stephen P. Lutar · ORCID 0009-0001-0110-4173
"""NVML-based GPU energy sampling for governed inference metering.

HONESTY (Λ = Conjecture 1, advisory):
- Energy is MEASURED only when NVIDIA NVML is available and grants the
  power-readback capability. We integrate instantaneous power draw (watts)
  sampled over wall-clock time to estimate joules. This is a real,
  reproducible physical measurement of *board* power.
- When NVML is absent (no GPU, no driver, no permission, or import failure)
  we DEGRADE HONESTLY: the meter reports ``mode="unmeasured"`` and
  ``joules=None``. We never fabricate a joule figure.
- Two estimators are offered, labeled honestly:
    * ``mode="measured-energy"`` — uses NVML's total energy counter
      (``nvmlDeviceGetTotalEnergyConsumption``, millijoules) when the device
      exposes it. This is the most accurate: a hardware energy accumulator.
    * ``mode="measured-power-integral"`` — integrates power samples
      (``nvmlDeviceGetPowerUsage``, milliwatts) over wall-time via the
      trapezoidal rule. Used when the energy counter is unavailable.
- Board power includes more than the compute die (memory, fans, losses).
  We report what the hardware reports and say so. No modeling, no scaling.

Stdlib + optional pynvml only. No tensors, no network, no disk writes.
"""
import time
from typing import Any, Dict, List, Optional, Tuple

# Honest capability probe: import pynvml lazily and record *why* if it fails.
_NVML_IMPORT_ERROR: Optional[str] = None
try:  # pragma: no cover - environment dependent
    import pynvml as _pynvml  # type: ignore
except Exception as _e:  # noqa: BLE001 - we want any failure reason
    _pynvml = None  # type: ignore
    _NVML_IMPORT_ERROR = f"{type(_e).__name__}: {_e}"

# Mode string constants (the only labels this module ever emits).
MODE_UNMEASURED = "unmeasured"
MODE_ENERGY_COUNTER = "measured-energy"
MODE_POWER_INTEGRAL = "measured-power-integral"


def nvml_available() -> bool:
    """True only if pynvml imported AND nvmlInit() succeeds. Never raises."""
    if _pynvml is None:
        return False
    try:
        _pynvml.nvmlInit()
        return True
    except Exception:  # noqa: BLE001
        return False


def capability_report() -> Dict[str, Any]:
    """Describe, honestly, what energy measurement is possible right now."""
    rep: Dict[str, Any] = {
        "pynvml_importable": _pynvml is not None,
        "import_error": _NVML_IMPORT_ERROR,
        "nvml_init_ok": False,
        "device_count": 0,
        "has_energy_counter": False,
        "has_power_readback": False,
        "preferred_mode": MODE_UNMEASURED,
    }
    if _pynvml is None:
        return rep
    try:
        _pynvml.nvmlInit()
        rep["nvml_init_ok"] = True
        rep["device_count"] = int(_pynvml.nvmlDeviceGetCount())
        if rep["device_count"] > 0:
            h = _pynvml.nvmlDeviceGetHandleByIndex(0)
            try:
                _pynvml.nvmlDeviceGetTotalEnergyConsumption(h)
                rep["has_energy_counter"] = True
            except Exception:  # noqa: BLE001
                rep["has_energy_counter"] = False
            try:
                _pynvml.nvmlDeviceGetPowerUsage(h)
                rep["has_power_readback"] = True
            except Exception:  # noqa: BLE001
                rep["has_power_readback"] = False
        if rep["has_energy_counter"]:
            rep["preferred_mode"] = MODE_ENERGY_COUNTER
        elif rep["has_power_readback"]:
            rep["preferred_mode"] = MODE_POWER_INTEGRAL
    except Exception as e:  # noqa: BLE001
        rep["import_error"] = rep["import_error"] or f"{type(e).__name__}: {e}"
    return rep


class EnergyMeter:
    """Measures GPU energy across a code region. Honest, never fabricating.

    Usage::

        m = EnergyMeter(device_index=0)
        m.start()
        ... run inference ...
        result = m.stop()   # dict: mode, joules|None, watt_seconds, samples...

    ``result["mode"]`` is one of ``measured-energy``,
    ``measured-power-integral``, or ``unmeasured``. When ``unmeasured``,
    ``result["joules"]`` is ``None`` — never a guessed number.
    """

    def __init__(self, device_index: int = 0, sample_hz: float = 100.0) -> None:
        self.device_index = int(device_index)
        # Sampling cadence used only for the power-integral fallback.
        self.sample_interval = 1.0 / float(sample_hz) if sample_hz > 0 else 0.01
        self._handle = None
        self._mode = MODE_UNMEASURED
        self._t0: Optional[float] = None
        self._energy_mj0: Optional[int] = None  # NVML energy counter at start
        self._samples: List[Tuple[float, float]] = []  # (t, watts) for integral
        self._ready = False
        self._init()

    def _init(self) -> None:
        if _pynvml is None:
            return
        try:
            _pynvml.nvmlInit()
            if int(_pynvml.nvmlDeviceGetCount()) <= self.device_index:
                return
            self._handle = _pynvml.nvmlDeviceGetHandleByIndex(self.device_index)
            # Prefer the hardware energy accumulator when present.
            try:
                _pynvml.nvmlDeviceGetTotalEnergyConsumption(self._handle)
                self._mode = MODE_ENERGY_COUNTER
                self._ready = True
                return
            except Exception:  # noqa: BLE001
                pass
            try:
                _pynvml.nvmlDeviceGetPowerUsage(self._handle)
                self._mode = MODE_POWER_INTEGRAL
                self._ready = True
            except Exception:  # noqa: BLE001
                self._ready = False
        except Exception:  # noqa: BLE001
            self._ready = False

    @property
    def mode(self) -> str:
        return self._mode if self._ready else MODE_UNMEASURED

    def start(self) -> None:
        self._t0 = time.perf_counter()
        self._samples = []
        if not self._ready or self._handle is None:
            return
        if self._mode == MODE_ENERGY_COUNTER:
            try:
                self._energy_mj0 = int(
                    _pynvml.nvmlDeviceGetTotalEnergyConsumption(self._handle)
                )
            except Exception:  # noqa: BLE001
                self._mode = MODE_POWER_INTEGRAL  # fall back if counter vanishes
        if self._mode == MODE_POWER_INTEGRAL:
            self._sample_power()

    def sample(self) -> None:
        """Take one power sample (power-integral mode only). Safe to over-call."""
        if self._ready and self._mode == MODE_POWER_INTEGRAL:
            self._sample_power()

    def _sample_power(self) -> None:
        try:
            mw = int(_pynvml.nvmlDeviceGetPowerUsage(self._handle))
            self._samples.append((time.perf_counter(), mw / 1000.0))
        except Exception:  # noqa: BLE001
            pass

    def stop(self) -> Dict[str, Any]:
        t1 = time.perf_counter()
        wall = (t1 - self._t0) if self._t0 is not None else 0.0
        out: Dict[str, Any] = {
            "mode": MODE_UNMEASURED,
            "joules": None,
            "wall_seconds": round(wall, 9),
            "device_index": self.device_index,
            "n_power_samples": 0,
            "note": None,
        }
        if not self._ready or self._handle is None:
            out["note"] = (
                "NVML unavailable: no GPU/driver/permission. Energy is "
                "unmeasured; no joules fabricated."
            )
            return out

        if self._mode == MODE_ENERGY_COUNTER and self._energy_mj0 is not None:
            try:
                mj1 = int(_pynvml.nvmlDeviceGetTotalEnergyConsumption(self._handle))
                joules = max(0.0, (mj1 - self._energy_mj0) / 1000.0)
                out.update(
                    mode=MODE_ENERGY_COUNTER,
                    joules=round(joules, 6),
                    note="Hardware energy accumulator delta (board-level).",
                )
                return out
            except Exception:  # noqa: BLE001
                pass  # fall through to integral if counter read fails

        if self._mode == MODE_POWER_INTEGRAL:
            self._sample_power()  # final sample at stop
            n = len(self._samples)
            out["n_power_samples"] = n
            if n >= 2:
                joules = 0.0
                for (ta, wa), (tb, wb) in zip(self._samples, self._samples[1:]):
                    joules += 0.5 * (wa + wb) * (tb - ta)  # trapezoidal rule
                out.update(
                    mode=MODE_POWER_INTEGRAL,
                    joules=round(max(0.0, joules), 6),
                    note="Trapezoidal integral of NVML power samples (board-level).",
                )
                return out
            out["note"] = (
                "Too few power samples to integrate; region likely shorter than "
                "one sample interval. Energy unmeasured for this call."
            )
            return out

        out["note"] = "NVML present but no usable energy/power readback."
        return out
