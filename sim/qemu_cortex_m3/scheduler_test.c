// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
/**
 * @file scheduler_test.c
 * @brief Proves the Cortex-M port actually schedules: SysTick, PendSV, delays.
 *
 * tests/main_system_test.c exercises the kernel API, but it never calls
 * eos_kernel_start(), so no context switch ever happens in it. This test
 * starts the kernel. Two workers block in eos_task_delay_ms(), and they can
 * only make progress if SysTick ticks and PendSV switches context. A
 * higher-priority monitor checks both counters and then ends QEMU through
 * semihosting with exit status 0 (pass) or 1 (fail).
 */
#include <stdio.h>
#include <stdlib.h>
#include "eos/kernel.h"

static volatile unsigned a_runs, b_runs;

static void worker_a(void *arg) { (void)arg; for (;;) { a_runs++; eos_task_delay_ms(10); } }
static void worker_b(void *arg) { (void)arg; for (;;) { b_runs++; eos_task_delay_ms(20); } }

static void monitor(void *arg)
{
    (void)arg;
    eos_task_delay_ms(400);
    unsigned a = a_runs, b = b_runs;
    printf("scheduler: worker_a=%u worker_b=%u\n", a, b);
    /* 400 ms at 10 ms / 20 ms periods: about 40 and 20. Leave a wide margin for
     * emulator jitter, but require both to have run many times. A scheduler
     * that never switches leaves them at 0 or 1. */
    if (a >= 10 && b >= 5 && a > b) {
        printf("SCHEDULER TEST PASSED\n");
        exit(0);
    }
    printf("SCHEDULER TEST FAILED\n");
    exit(1);
}

int main(void)
{
    if (eos_kernel_init() != EOS_KERN_OK) { printf("kernel init failed\n"); exit(1); }
    eos_task_create("worker_a", worker_a, NULL, 3, 512);
    eos_task_create("worker_b", worker_b, NULL, 3, 512);
    eos_task_create("monitor", monitor, NULL, 1, 1024);
    printf("scheduler: starting kernel\n");
    eos_kernel_start();
    return 1; /* not reached */
}
