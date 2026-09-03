// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file test_linux_security_paths.c
 * @brief linux_security builds shell commands; these are the inputs it must refuse.
 *
 * Every function here interpolates caller-supplied paths into a string handed
 * to system() or popen(). is_path_safe() is the only thing standing between a
 * path and the shell, and it is static, so it is exercised through the public
 * API: a rejected path makes the call return -1 without building a command.
 */

#include "eos/linux_security.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

/* Print [PASS] only if this function's own checks all held. Printing it
 * unconditionally is the same shape as the defects this file is about: a
 * report that does not depend on the result. */
#define PASS_IF_CLEAN(before, msg) do { \
    if (failures == (before)) printf("[PASS] %s\n", (msg)); \
} while (0)

/* Payloads that a shell reads as syntax. The first two passed the original
 * denylist (";|&><$()\"'") -- it had no backtick and no newline. */
static const char *HOSTILE[] = {
    "/tmp/`touch /tmp/pwned`",      /* command substitution */
    "/tmp/x\ntouch /tmp/pwned",     /* newline starts a second command */
    "/tmp/x\\",                     /* trailing backslash escapes the closing quote */
    "/tmp/a;id",                    /* semicolon */
    "/tmp/$(id)",                   /* dollar-paren */
    "/tmp/a|id",                    /* pipe */
    "/tmp/a&id",                    /* background + second command */
    "/tmp/a>/etc/passwd",           /* redirect */
    "/tmp/a\"b",                    /* closes the quote the format string opens */
    "/tmp/a'b",                     /* single quote */
    "/tmp/a\x01b",                  /* control character */
};

static void test_dmverity_verify_refuses_hostile_paths(void) {
    int f0 = failures;
    for (unsigned i = 0; i < sizeof HOSTILE / sizeof *HOSTILE; i++) {
        EosDmVerity dv;
        eos_dmverity_init(&dv);
        strncpy(dv.hash_device, "/tmp/hash.img", sizeof(dv.hash_device) - 1);
        strncpy(dv.root_hash, "abcdef0123456789", sizeof(dv.root_hash) - 1);
        dv.verified = 1;   /* must not survive a refusal */
        CHECK(eos_dmverity_verify(&dv, HOSTILE[i]) != 0);
        CHECK(dv.verified == 0);
    }
    PASS_IF_CLEAN(f0, "dmverity_verify refuses hostile image paths");
}

/* The two dmverity refusal tests above assert a non-zero return, which does
 * not discriminate on a host without veritysetup: system() returns non-zero
 * either way, so they pass against the unfixed file too. CI installs no
 * veritysetup, so that is every CI run.
 *
 * This one does discriminate anywhere, by watching for the side effect. The
 * injected command creates a sentinel file; if the guard refuses the path the
 * command is never built and the sentinel cannot appear. On the unfixed file
 * the backtick survives is_path_safe(), the shell runs it, and the file
 * exists. */
static void test_injection_does_not_execute(void) {
    int f0 = failures;
    char dir[] = "/tmp/eos_lsp_inj_XXXXXX";
    char sentinel[320], hostile[512];
    EosDmVerity dv;
    EosIma ima;

    if (!mkdtemp(dir)) { fprintf(stderr, "[SKIP] mkdtemp failed\n"); return; }
    snprintf(sentinel, sizeof sentinel, "%s/pwned", dir);

    /* A path carrying a command substitution that would create the sentinel. */
    snprintf(hostile, sizeof hostile, "/tmp/img`touch %s`", sentinel);

    eos_dmverity_init(&dv);
    strncpy(dv.hash_device, "/tmp/hash.img", sizeof(dv.hash_device) - 1);
    strncpy(dv.root_hash, "abcdef0123456789", sizeof(dv.root_hash) - 1);
    (void)eos_dmverity_verify(&dv, hostile);
    CHECK(access(sentinel, F_OK) != 0);

    eos_dmverity_init(&dv);
    (void)eos_dmverity_create(&dv, hostile, "/tmp/hash.img");
    CHECK(access(sentinel, F_OK) != 0);

    eos_ima_init(&ima, EOS_IMA_ENFORCE);
    strncpy(ima.key_file, "/tmp/key.pub", sizeof(ima.key_file) - 1);
    (void)eos_ima_sign_file(&ima, hostile);
    CHECK(access(sentinel, F_OK) != 0);

    if (access(sentinel, F_OK) == 0) {
        fprintf(stderr, "[FAIL] the injected command executed: %s exists\n", sentinel);
        remove(sentinel);
    }
    rmdir(dir);
    PASS_IF_CLEAN(f0, "an injected command substitution never executes");
}

static void test_dmverity_verify_refuses_hostile_hash_device(void) {
    int f0 = failures;
    EosDmVerity dv;
    eos_dmverity_init(&dv);
    strncpy(dv.hash_device, "/tmp/`id`", sizeof(dv.hash_device) - 1);
    strncpy(dv.root_hash, "abcdef", sizeof(dv.root_hash) - 1);
    CHECK(eos_dmverity_verify(&dv, "/tmp/image.img") != 0);
    CHECK(dv.verified == 0);
    PASS_IF_CLEAN(f0, "dmverity_verify refuses a hostile hash device");
}

static void test_dmverity_create_refuses_hostile_paths(void) {
    int f0 = failures;
    EosDmVerity dv;
    eos_dmverity_init(&dv);
    CHECK(eos_dmverity_create(&dv, "/tmp/`id`", "/tmp/hash.img") != 0);
    eos_dmverity_init(&dv);
    CHECK(eos_dmverity_create(&dv, "/tmp/image.img", "/tmp/x\nid") != 0);
    PASS_IF_CLEAN(f0, "dmverity_create refuses hostile paths");
}

static void test_busybox_refuses_hostile_fields(void) {
    int f0 = failures;
    EosBusybox bb;

    eos_busybox_init(&bb);
    strncpy(bb.source_dir, "/tmp/`id`", sizeof(bb.source_dir) - 1);
    CHECK(eos_busybox_build(&bb) != 0);

    /* defconfig and cross_compile are interpolated WITHOUT surrounding quotes,
     * so a bare space is already an injection of an extra make argument. */
    eos_busybox_init(&bb);
    strncpy(bb.source_dir, "/tmp/bb", sizeof(bb.source_dir) - 1);
    strncpy(bb.defconfig, "defconfig CONFIG_X=y", sizeof(bb.defconfig) - 1);
    CHECK(eos_busybox_configure(&bb) != 0);

    eos_busybox_init(&bb);
    strncpy(bb.source_dir, "/tmp/bb", sizeof(bb.source_dir) - 1);
    strncpy(bb.cross_compile, "arm- ;id", sizeof(bb.cross_compile) - 1);
    CHECK(eos_busybox_build(&bb) != 0);

    PASS_IF_CLEAN(f0, "busybox refuses hostile source_dir/defconfig/cross_compile");
}

static void test_ima_sign_refuses_hostile_paths(void) {
    int f0 = failures;
    EosIma ima;
    eos_ima_init(&ima, EOS_IMA_ENFORCE);
    strncpy(ima.key_file, "/tmp/key.pub", sizeof(ima.key_file) - 1);
    CHECK(eos_ima_sign_file(&ima, "/tmp/`id`") != 0);
    PASS_IF_CLEAN(f0, "ima_sign_file refuses a hostile file path");
}

/* A guard that refuses everything would pass every test above, so this is
 * the counter-check: a well-formed source_dir must still reach the shell.
 * Proven by side effect -- a generated Makefile whose target creates a
 * sentinel file. If the sentinel exists, the command was built and run. */
static void test_ordinary_paths_still_reach_the_shell(void) {
    int f0 = failures;
    char dir[] = "/tmp/eos_lsp_XXXXXX";
    char mk[256], sentinel[256];
    FILE *f;
    int fd;
    EosBusybox bb;

    if (!mkdtemp(dir)) { fprintf(stderr, "[SKIP] mkdtemp failed\n"); return; }
    snprintf(mk, sizeof mk, "%s/Makefile", dir);
    snprintf(sentinel, sizeof sentinel, "%s/ran", dir);
    /* open(O_CREAT, 0600) rather than fopen("w"): fopen creates with 0666
     * masked by umask, so on a permissive umask this Makefile would be
     * world-writable -- and it is a file whose contents get executed. */
    fd = open(mk, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    CHECK(fd >= 0);
    if (fd < 0) { rmdir(dir); return; }
    f = fdopen(fd, "w");
    CHECK(f != NULL);
    if (!f) { close(fd); rmdir(dir); return; }
    fprintf(f, "defconfig:\n\t@touch ran\n");
    fclose(f);

    eos_busybox_init(&bb);
    strncpy(bb.source_dir, dir, sizeof(bb.source_dir) - 1);
    strncpy(bb.defconfig, "defconfig", sizeof(bb.defconfig) - 1);
    CHECK(eos_busybox_configure(&bb) == 0);

    /* The sentinel is the whole point: it only exists if the command was
     * constructed and executed rather than refused. */
    CHECK(access(sentinel, F_OK) == 0);

    remove(sentinel); remove(mk); rmdir(dir);
    PASS_IF_CLEAN(f0, "a well-formed source_dir still reaches the shell");
}

/* Finding 1 from the review: the guard ran above the line that populates the
 * field it protects, so the *default* path -- source_dir left empty by
 * eos_busybox_init, which is what a caller gets by not setting it -- built
 * ".eos/build/src/busybox-<version>" from an unvalidated version and handed
 * that to system(). is_path_safe("") returns 1 because its loop never runs,
 * so the guard passed on exactly the input it exists to catch.
 *
 * Watches for the side effect, like test_injection_does_not_execute, because
 * a non-zero return proves nothing here: `make` fails on a nonexistent
 * directory too. */
static void test_the_default_source_dir_path_is_validated(void) {
    int f0 = failures;
    char dir[] = "/tmp/eos_lsp_ver_XXXXXX";
    char sentinel[320], hostile_version[192];
    EosBusybox bb;

    if (!mkdtemp(dir)) { fprintf(stderr, "[SKIP] mkdtemp failed\n"); return; }
    snprintf(sentinel, sizeof sentinel, "%s/pwned", dir);
    snprintf(hostile_version, sizeof hostile_version,
             "1.36.1`touch %s`", sentinel);

    /* The setter must refuse it outright. */
    eos_busybox_init(&bb);
    CHECK(eos_busybox_set_version(&bb, hostile_version) != 0);

    /* And if the field is reached around -- a caller writing the struct
     * directly -- configure() must still refuse, because it now validates
     * the value it actually uses rather than the empty string. */
    eos_busybox_init(&bb);
    strncpy(bb.version, hostile_version, sizeof(bb.version) - 1);
    bb.version[sizeof(bb.version) - 1] = '\0';
    bb.source_dir[0] = '\0';               /* the default path */
    CHECK(eos_busybox_configure(&bb) != 0);

    CHECK(access(sentinel, F_OK) != 0);
    if (access(sentinel, F_OK) == 0) {
        fprintf(stderr, "[FAIL] the default path executed the injection: %s\n",
                sentinel);
        remove(sentinel);
    }
    rmdir(dir);
    PASS_IF_CLEAN(f0, "the default source_dir is validated, not the empty string");
}

/* Finding 2: eos_ima_sign_file() discarded system()'s result and its command
 * ended `|| echo`, so on any host without evmctl it signed nothing and
 * returned 0. This machine has no evmctl, which is precisely the condition
 * the finding is about -- so the assertion is that it now reports failure
 * rather than success. */
static void test_ima_sign_reports_failure_when_evmctl_is_absent(void) {
    int f0 = failures;
    EosIma ima;
    char dir[] = "/tmp/eos_lsp_ima_XXXXXX";
    char target[320];
    FILE *f;

    if (!mkdtemp(dir)) { fprintf(stderr, "[SKIP] mkdtemp failed\n"); return; }
    snprintf(target, sizeof target, "%s/file", dir);
    f = fopen(target, "w");
    if (f) { fputs("x", f); fclose(f); }

    eos_ima_init(&ima, EOS_IMA_ENFORCE);
    strncpy(ima.key_file, "/tmp/key.pub", sizeof(ima.key_file) - 1);

    if (system("command -v evmctl >/dev/null 2>&1") == 0) {
        printf("[SKIP] evmctl is installed; "
               "the absent-tool path cannot be exercised here\n");
    } else {
        CHECK(eos_ima_sign_file(&ima, target) != 0);
        PASS_IF_CLEAN(f0, "ima_sign_file reports failure when evmctl is absent");
    }

    remove(target);
    rmdir(dir);
}

int main(void) {
    test_dmverity_verify_refuses_hostile_paths();
    test_dmverity_verify_refuses_hostile_hash_device();
    test_injection_does_not_execute();
    test_dmverity_create_refuses_hostile_paths();
    test_busybox_refuses_hostile_fields();
    test_ima_sign_refuses_hostile_paths();
    test_the_default_source_dir_path_is_validated();
    test_ima_sign_reports_failure_when_evmctl_is_absent();
    test_ordinary_paths_still_reach_the_shell();

    if (failures) {
        fprintf(stderr, "\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("\nAll linux_security path checks passed\n");
    return 0;
}
