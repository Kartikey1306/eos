# Accelerator HAL: tiered profiles for on-device inference

**Status:** Design sketch (Track 1 — tightly-coupled AI). Not yet an ADR; promote to
`docs/adr/` once the backend interface firms up.
**Date:** 2026-10-05
**Cross-links:** `eAI` `docs/track1/runtime-api.md` (inference-service API),
`eosllm` `docs/track1/inference-service.md`, `eIPC`
`docs/track1/zero-copy-tensor-ipc.md`, `ebuild` `docs/quantize.md`.

## 1. Problem

The HAL abstracts peripherals — UART, SPI, timers — behind capability-shaped
interfaces so drivers stay portable across boards. Neural-network accelerators
need the same treatment, but one flat API fails across the range:

- a Cortex-M4 with 520 KB SRAM running int8 CMSIS-NN kernels (arena-allocated,
  no heap, no OS), and
- a Versal-class device with an AI Engine array running ADF graphs through
  VART runners with tile-partition power control.

A single `accel_run(model, input)` signature either starves the small target
(no way to express scratch sizing) or drowns the large one (no way to express
graph partitioning). The HAL needs **tiered profiles**: capability-gated, not
vendor-locked.

## 2. Tiered profiles

| Profile | Class | Compute model | Memory model | Example backends |
|---|---|---|---|---|
| `tiny` | MCU NPU / SIMD | int8 kernels, per-op dispatch | caller-sized SRAM arena, no heap | CMSIS-NN, ESP-NN |
| `large` | AIE / discrete NPU | dataflow graphs, runner API | tiled / partitioned buffers | Versal AIE (VART), Ethos-U |

A board declares the highest profile it implements; the inference service
negotiates down. A `tiny`-only build never links graph-runner code. The
XQRVC1902 (space-grade Versal AI Core, sampling now, flight units H2 2027,
pin-compatible with the commercial VC1902) is the reference `large`-tier part:
one HAL design covers dev boards (cheap commercial parts) and flight units.

## 3. Converged backend interface

Research across CMSIS-NN, ESP-NN, and ExecuTorch-style delegates converges on
three operations. Sketch (names provisional):

```c
typedef struct {
    /* Dispatch one operator. Returns 0 on success, -ENOSYS for
       unsupported op_id (caller falls back to the next backend). */
    int (*dispatch)(uint8_t op_id, const void *params,
                    const eos_tensor_t *in, eos_tensor_t *out);
    /* Scratch bytes needed for (op_id, shape). The caller owns the arena;
       the backend never allocates. */
    size_t (*scratch_bytes)(uint8_t op_id, const eos_tensor_shape_t *shape);
    /* Quantization the backend executes natively: int8 per-tensor,
       int8 per-channel, or w8a16. Drives ebuild's quantize step. */
    eos_quant_desc_t (*quant_format)(void);
} eos_accel_backend_t;
```

Plus a power hook the inference service consults before model selection:

```c
/* Battery/thermal state -> which model tier may run. */
typedef struct { uint8_t battery_pct; int8_t temp_c; } eos_power_hint_t;
```

Power-aware model selection (pick model size by battery state) is a
phase-2 item; the hook reserves the shape now. The Versal AIE power model —
physical tile partitioning (YOLOv8m at 120 fps on 64 of 144 tiles) — is the
existence proof that "number of tiles" is a legitimate power knob to expose.

## 4. Trust tie-in

- **Signed models.** Models ship in the `.eapp` envelope v2 (Ed25519 over
  SHA-256, landed 2026-10-04, Closes #162). The inference service verifies the
  envelope before first inference, same as any other loadable module.
- **Measured boot** extends to ML artifacts: the model hash joins the boot
  measurement log.
- **Capability-scoped inference.** No shipping framework (NNAPI, Core ML)
  scopes per-model peripheral access, so there is no direct precedent to copy.
  The nearest workable pattern is TrustZone secure-peripheral attribution:
  camera marked secure, mic non-secure, the inference service runs in the
  secure partition, and the envelope's capability claims map onto SAU/MPU
  attribution. A model cleared for camera but not mic simply cannot address
  the mic peripheral. Enforcement lives in hardware configuration, not in
  the model loader's good intentions.

## 5. Roadmap

- **Phase 1 (now):** this doc; `ebuild quantize` (`--target cmsis-nn|esp-nn|aie
  --validate`) producing backend-matched artifacts; eosllm as the first
  inference-service implementation against eAI's runtime API.
- **Phase 2:** `tiny`-profile C implementation behind `eos_accel_backend_t`;
  zero-copy tensor transport in eIPC (models as loadable modules with declared
  capabilities); capability-scoped inference via SAU/MPU.
- **Phase 3:** `large`-profile backend; on-device agent runtime; EoSim as the
  sim-to-real training harness (fault injection in sim, deploy to hardware).

## 6. Open question

Zephyr answers the "who owns inference" question with an ExecuTorch-module
pattern (vendor-neutral core, pluggable NPU modules) rather than a bespoke
kernel service. The eAI runtime-API design (`eAI` `docs/track1/runtime-api.md`,
same day) adopts the module pattern; this HAL doc is compatible with either
— the backend table is the seam. Decision recorded there, not here.
