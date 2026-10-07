#!/usr/bin/env bash
# Build an EoS image for QEMU lm3s6965evb from sim.yaml plus application sources.
#   sim/qemu_cortex_m3/build.sh OUT.elf app1.c [app2.c ...]
# Run it:  qemu-system-arm -M lm3s6965evb -nographic -semihosting -kernel OUT.elf
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$1; shift
cc=${CC:-arm-none-eabi-gcc}
# SIM_YAML selects another target's sim.yaml (sim/qemu_cortex_m33/build.sh uses it).
python3 - "${SIM_YAML:-$here/sim.yaml}" "$root" "$out" "$cc" "$@" <<'PY'
import os, subprocess, sys, tempfile, yaml
cfg_path, root, out, cc, *apps = sys.argv[1:]
cfg = yaml.safe_load(open(cfg_path))
inc = [f"-I{os.path.join(root, d)}" for d in cfg["includes"]]
srcs = [os.path.join(root, s) for s in cfg["sources"]] + [os.path.abspath(a) for a in apps]
objdir = tempfile.mkdtemp(prefix="eos-qemu-")
objs = []
for i, src in enumerate(srcs):
    obj = os.path.join(objdir, f"{i:02d}_{os.path.basename(src)}.o")
    subprocess.run([cc, *cfg["cflags"], *inc, "-c", src, "-o", obj], check=True)
    objs.append(obj)
subprocess.run([cc, *cfg["ldflags"], "-T", os.path.join(root, cfg["linker_script"]),
                *objs, *cfg["libs"], "-o", out], check=True)
PY
