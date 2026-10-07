// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file test_exec_argv.c
 * @brief Regression tests for eos_exec_argv() (issue #172).
 *
 * Issue #172: `eos clean` interpolated workspace.build_dir into a shell
 * command via system(), and the denylist omitted the backtick — so a
 * build_dir like `/tmp/x`touch /tmp/PWNED`` executed the injected command.
 *
 * eos_exec_argv() never invokes a shell: these tests feed hostile
 * arguments and assert they are passed literally (no file created, no
 * substitution) and that normal execution still works.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "exec_argv.h"

#ifndef _WIN32
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void test_hostile_arg_not_interpreted(void) {
    /* If a shell were involved, the backticks would run `touch` and create
       the marker. With argv-form exec, the argument is literal. */
    const char *marker = "/tmp/eos_exec_argv_pwned";
    unlink(marker);
    char hostile[256];
    snprintf(hostile, sizeof(hostile), "x`touch %s`y", marker);
    char *const argv[] = { "echo", hostile, NULL };
    int rc = eos_exec_argv("echo", argv);
    assert(rc == 0);
    assert(!file_exists(marker) && "shell interpreted backticks!");
    printf("PASS: backtick argument passed literally\n");
}

static void test_dollar_paren_not_interpreted(void) {
    const char *marker = "/tmp/eos_exec_argv_pwned2";
    unlink(marker);
    char hostile[256];
    snprintf(hostile, sizeof(hostile), "x$(touch %s)y", marker);
    char *const argv[] = { "echo", hostile, NULL };
    int rc = eos_exec_argv("echo", argv);
    assert(rc == 0);
    assert(!file_exists(marker) && "shell interpreted $()!");
    printf("PASS: $() argument passed literally\n");
}

static void test_rm_dashdash_hostile_dir(void) {
    /* A build_dir starting with '-' must not become an rm flag; the "--"
       in the clean path ends option parsing. Use a hostile name. */
    const char *dir = "/tmp/eos_rm_test_-rf_evil";
    assert(mkdir(dir, 0755) == 0 || errno == EEXIST);
    char f[512];
    snprintf(f, sizeof(f), "%s/f", dir);
    FILE *fp = fopen(f, "w");
    assert(fp != NULL);
    fclose(fp);
    char *const argv[] = { "rm", "-rf", "--", (char *)dir, NULL };
    int rc = eos_exec_argv("rm", argv);
    assert(rc == 0);
    assert(!file_exists(dir) && "hostile dir was not removed");
    printf("PASS: rm -rf -- removed hostile-named dir\n");
}

static void test_exit_code_propagates(void) {
    char *const t[] = { "true", NULL };
    assert(eos_exec_argv("true", t) == 0);
    char *const f[] = { "false", NULL };
    assert(eos_exec_argv("false", f) == 1);
    char *const missing[] = { "definitely-not-a-real-program-eos", NULL };
    assert(eos_exec_argv("definitely-not-a-real-program-eos", missing) == -1 ||
           eos_exec_argv("definitely-not-a-real-program-eos", missing) == 127);
    printf("PASS: exit codes propagate\n");
}
#endif /* _WIN32 */

int main(void) {
#ifdef _WIN32
    /* Windows: _spawnvp path. The no-shell property holds by construction
       (_spawnvp never invokes cmd.exe); POSIX-only probe tests are skipped. */
    char *const argv[] = { "cmd", "/c", "exit", "0", NULL };
    int rc = eos_exec_argv("cmd", argv);
    assert(rc == 0);
    printf("PASS: windows spawn works\n");
#else
    test_hostile_arg_not_interpreted();
    test_dollar_paren_not_interpreted();
    test_rm_dashdash_hostile_dir();
    test_exit_code_propagates();
#endif
    printf("test_exec_argv: all passed\n");
    return 0;
}
