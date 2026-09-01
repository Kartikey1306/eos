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
    for (unsigned i = 0; i < sizeof HOSTILE / sizeof *HOSTILE; i++) {
        EosDmVerity dv;
        eos_dmverity_init(&dv);
        strncpy(dv.hash_device, "/tmp/hash.img", sizeof(dv.hash_device) - 1);
        strncpy(dv.root_hash, "abcdef0123456789", sizeof(dv.root_hash) - 1);
        dv.verified = 1;   /* must not survive a refusal */
        CHECK(eos_dmverity_verify(&dv, HOSTILE[i]) != 0);
        CHECK(dv.verified == 0);
    }
    printf("[PASS] dmverity_verify refuses hostile image paths\n");
}

static void test_dmverity_verify_refuses_hostile_hash_device(void) {
    EosDmVerity dv;
    eos_dmverity_init(&dv);
    strncpy(dv.hash_device, "/tmp/`id`", sizeof(dv.hash_device) - 1);
    strncpy(dv.root_hash, "abcdef", sizeof(dv.root_hash) - 1);
    CHECK(eos_dmverity_verify(&dv, "/tmp/image.img") != 0);
    CHECK(dv.verified == 0);
    printf("[PASS] dmverity_verify refuses a hostile hash device\n");
}

static void test_dmverity_create_refuses_hostile_paths(void) {
    EosDmVerity dv;
    eos_dmverity_init(&dv);
    CHECK(eos_dmverity_create(&dv, "/tmp/`id`", "/tmp/hash.img") != 0);
    eos_dmverity_init(&dv);
    CHECK(eos_dmverity_create(&dv, "/tmp/image.img", "/tmp/x\nid") != 0);
    printf("[PASS] dmverity_create refuses hostile paths\n");
}

static void test_busybox_refuses_hostile_fields(void) {
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

    printf("[PASS] busybox refuses hostile source_dir/defconfig/cross_compile\n");
}

static void test_ima_sign_refuses_hostile_paths(void) {
    EosIma ima;
    eos_ima_init(&ima, EOS_IMA_ENFORCE);
    strncpy(ima.key_file, "/tmp/key.pub", sizeof(ima.key_file) - 1);
    CHECK(eos_ima_sign_file(&ima, "/tmp/`id`") != 0);
    printf("[PASS] ima_sign_file refuses a hostile file path\n");
}

/* A guard that refuses everything would pass every test above, so this is
 * the counter-check: a well-formed source_dir must still reach the shell.
 * Proven by side effect -- a generated Makefile whose target creates a
 * sentinel file. If the sentinel exists, the command was built and run. */
static void test_ordinary_paths_still_reach_the_shell(void) {
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
    printf("[PASS] a well-formed source_dir still reaches the shell\n");
}

int main(void) {
    test_dmverity_verify_refuses_hostile_paths();
    test_dmverity_verify_refuses_hostile_hash_device();
    test_dmverity_create_refuses_hostile_paths();
    test_busybox_refuses_hostile_fields();
    test_ima_sign_refuses_hostile_paths();
    test_ordinary_paths_still_reach_the_shell();

    if (failures) {
        fprintf(stderr, "\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("\nAll linux_security path checks passed\n");
    return 0;
}
