#!/usr/bin/env bash
# Build an EoS image for QEMU mps2-an505 (Cortex-M33 + FPU) from sim.yaml plus
# application sources.
#   sim/qemu_cortex_m33/build.sh OUT.elf app1.c [app2.c ...]
# Run it:  qemu-system-arm -M mps2-an505 -nographic -semihosting -kernel OUT.elf
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
SIM_YAML="$here/sim.yaml" exec "$here/../qemu_cortex_m3/build.sh" "$@"
