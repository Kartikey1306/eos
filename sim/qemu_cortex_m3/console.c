// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
/**
 * @file console.c
 * @brief Semihosting stdout for EoS images run under QEMU (-semihosting).
 *
 * The board startup file branches straight to main(). It never runs newlib's
 * crt0, so nothing opens the semihosting handles and printf() output is
 * dropped. Linking with -Wl,--wrap=main sends that branch here first.
 * stdout is unbuffered, so a line shows up when the guest prints it, not
 * when a buffer fills.
 */
#include <stdio.h>

extern void initialise_monitor_handles(void);
int __real_main(void);

int __wrap_main(void)
{
    initialise_monitor_handles();
    setvbuf(stdout, NULL, _IONBF, 0);
    return __real_main();
}
