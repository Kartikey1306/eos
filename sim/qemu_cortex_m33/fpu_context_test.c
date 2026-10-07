/* Two tasks each park a distinct pattern in s16-s31, block so the scheduler
   switches away, and check the pattern survives. s16-s31 are only preserved
   across a switch by PendSV's lazy-stacking path (vstmdb/vldmia), so a lost
   or swapped register means that path is broken. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "eos/kernel.h"

#define ROUNDS 20
static volatile int failures, done_a, done_b;

static void park(uint32_t base) {
    __asm volatile(
        "vmov s16, %0\n add %0, #1\n vmov s17, %0\n add %0, #1\n vmov s18, %0\n add %0, #1\n vmov s19, %0\n add %0, #1\n"
        "vmov s20, %0\n add %0, #1\n vmov s21, %0\n add %0, #1\n vmov s22, %0\n add %0, #1\n vmov s23, %0\n add %0, #1\n"
        "vmov s24, %0\n add %0, #1\n vmov s25, %0\n add %0, #1\n vmov s26, %0\n add %0, #1\n vmov s27, %0\n add %0, #1\n"
        "vmov s28, %0\n add %0, #1\n vmov s29, %0\n add %0, #1\n vmov s30, %0\n add %0, #1\n vmov s31, %0\n"
        : "+r"(base) :: "s16","s17","s18","s19","s20","s21","s22","s23","s24","s25","s26","s27","s28","s29","s30","s31");
}

static int check(uint32_t base) {
    uint32_t v[16];
    __asm volatile(
        "vmov %0, s16\n vmov %1, s17\n vmov %2, s18\n vmov %3, s19\n vmov %4, s20\n vmov %5, s21\n vmov %6, s22\n vmov %7, s23\n"
        : "=r"(v[0]),"=r"(v[1]),"=r"(v[2]),"=r"(v[3]),"=r"(v[4]),"=r"(v[5]),"=r"(v[6]),"=r"(v[7]));
    __asm volatile(
        "vmov %0, s24\n vmov %1, s25\n vmov %2, s26\n vmov %3, s27\n vmov %4, s28\n vmov %5, s29\n vmov %6, s30\n vmov %7, s31\n"
        : "=r"(v[8]),"=r"(v[9]),"=r"(v[10]),"=r"(v[11]),"=r"(v[12]),"=r"(v[13]),"=r"(v[14]),"=r"(v[15]));
    for (int i = 0; i < 16; i++) if (v[i] != base + (uint32_t)i) return 0;
    return 1;
}

static void worker(void *arg) {
    uint32_t base = (uint32_t)(uintptr_t)arg;
    for (int r = 0; r < ROUNDS; r++) {
        park(base + (uint32_t)r * 0x100u);
        eos_task_delay_ms(3);            /* forces a switch to the other task */
        if (!check(base + (uint32_t)r * 0x100u)) failures++;
    }
    if (base == 0x10000000u) done_a = 1; else done_b = 1;
    for (;;) eos_task_delay_ms(1000);
}

static void monitor(void *arg) {
    (void)arg;
    while (!(done_a && done_b)) eos_task_delay_ms(10);
    printf("FPU context test: %d rounds x 2 tasks, %d corrupted\n", ROUNDS, failures);
    puts(failures ? "FPU CONTEXT TEST FAILED" : "FPU CONTEXT TEST PASSED");
    exit(failures ? 1 : 0);
}

int main(void) {
    eos_kernel_init();
    eos_task_create("fpu_a", worker, (void *)0x10000000u, 2, 1024);
    eos_task_create("fpu_b", worker, (void *)0x20000000u, 2, 1024);
    eos_task_create("monitor", monitor, NULL, 1, 1024);
    eos_kernel_start();
    return 1;
}
