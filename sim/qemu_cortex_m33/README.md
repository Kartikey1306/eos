# EoS on QEMU mps2-an505 (Cortex-M33 with FPU)

Runs the EoS kernel on QEMU's Arm MPS2 AN505 machine: a Cortex-M33 with the single-precision FPU, in secure state.

**Why it exists:** `sim/qemu_cortex_m3` has no FPU, so the FPU half of PendSV is compiled out there. That half saves and restores `s16`–`s31` with lazy stacking, and it is the code path every Cortex-M4F board, the STM32F4 included, depends on. Until this target, no simulation ever executed it.

```sh
sim/qemu_cortex_m33/build.sh fpu.elf sim/qemu_cortex_m33/fpu_context_test.c
qemu-system-arm -M mps2-an505 -nographic -semihosting -kernel fpu.elf
# FPU context test: 20 rounds x 2 tasks, 0 corrupted
# FPU CONTEXT TEST PASSED          (exit status 0)
```

`fpu_context_test.c`: two tasks each write a distinct pattern into `s16`–`s31`, block so the scheduler switches away, and check the pattern survived. With the FPU save in `context_switch.S` removed, the same test reports `39 corrupted` and exits 1, so it does detect a broken path. The kernel scheduler test from the M3 target runs here too.

Or through ebuild: `ebuild sim --platform qemu_cortex_m33`.

**Limits:** Armv8-M rather than Armv7E-M, so this is not cycle- or peripheral-accurate for any STM32. Verified with QEMU 4.2 (Ubuntu 20.04); `mps2-an505` exists in every later QEMU.
