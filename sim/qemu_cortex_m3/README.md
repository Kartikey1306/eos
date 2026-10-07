# EoS on QEMU Cortex-M3 (`lm3s6965evb`)

Runs the EoS kernel on QEMU's TI Stellaris LM3S6965EVB machine, a Cortex-M3. No hardware is needed. `ebuild sim` uses this target, and so does the `QEMU Boot Test` CI job.

```sh
sudo apt install gcc-arm-none-eabi qemu-system-arm python3-yaml
sim/qemu_cortex_m3/build.sh /tmp/sched.elf sim/qemu_cortex_m3/scheduler_test.c
qemu-system-arm -M lm3s6965evb -nographic -semihosting -kernel /tmp/sched.elf
# scheduler: worker_a=40 worker_b=20
# SCHEDULER TEST PASSED          (QEMU exits with status 0)
```

| File | Purpose |
|---|---|
| `sim.yaml` | Compiler/linker flags, the kernel and HAL sources, and the QEMU command line |
| `build.sh` | Builds an image from `sim.yaml` plus application sources |
| `console.c` | Opens the semihosting stdout before `main()`, linked in with `-Wl,--wrap=main` |
| `scheduler_test.c` | Starts the kernel and checks that SysTick and PendSV switch tasks |

## Limits
- The CPU is a Cortex-M3. There is no FPU and the core is not an STM32F4. Code that touches STM32 registers through the HAL will not behave as it does on hardware.
- Console output goes through ARM semihosting (`-semihosting`), not a UART model.
- `sys_clock_hz: 12000000` matches the SysTick clock of QEMU 4.2–8.x for this machine. Delays track wall-clock time only roughly; QEMU is not cycle accurate.
