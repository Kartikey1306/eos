// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
// ISO/IEC 25000 | ISO/IEC/IEEE 15288:2023

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "eos/backend.h"
#include "eos/error.h"

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#define getpid _getpid
#define MKDIR(p) _mkdir(p)
#define PATH_SEP "\\"
#else
#include <unistd.h>
#define MKDIR(p) mkdir(p, 0755)
#define PATH_SEP "/"
#endif

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  TEST: %s ... ", #name); \
        name(); \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

/* Unique scratch root per run, under the test's working directory. */
static char g_root[1024];

static void make_dirs(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char save = *p;
            *p = '\0';
            MKDIR(tmp);
            *p = save;
        }
    }
    MKDIR(tmp);
}

static void write_file(const char *path, const char *content) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", path);
    char *sep = strrchr(dir, '/');
    char *bsep = strrchr(dir, '\\');
    if (bsep && (!sep || bsep > sep)) sep = bsep;
    if (sep) {
        *sep = '\0';
        make_dirs(dir);
    }
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
#ifndef _WIN32
    chmod(path, 0755);
#endif
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void join(char *out, size_t n, const char *a, const char *b) {
    snprintf(out, n, "%s%s%s", a, PATH_SEP, b);
}

/* #166: an install step that copies nothing must not report EOS_OK.
 * Each backend's install used to end its shell command in "|| true", so a
 * failed copy (wrong path, missing artifact, permission) still returned
 * EOS_OK and the caller believed the install happened. */

/* --- cargo --- */
static void test_cargo_install_missing_artifacts(void) {
    EosBackend b;
    char build[1024], inst[1024];
    eos_backend_cargo_init(&b);
    join(build, sizeof(build), g_root, "cargo-missing-b");
    join(inst, sizeof(inst), g_root, "cargo-missing-i");
    /* build dir does not exist at all: nothing to install */
    assert(b.install(&b, build, inst) != EOS_OK);
}

static void test_cargo_install_copies_executables(void) {
    EosBackend b;
    char build[1024], inst[1024], artifact[1024], expected[1024];
    eos_backend_cargo_init(&b);
    join(build, sizeof(build), g_root, "cargo-ok-b");
    join(inst, sizeof(inst), g_root, "cargo-ok-i");
    join(artifact, sizeof(artifact), build, "target");
#ifdef _WIN32
    strcat(artifact, "\\release\\app.exe");
#else
    strcat(artifact, "/release/app");
#endif
    write_file(artifact, "fake-binary");
    assert(b.install(&b, build, inst) == EOS_OK);
    join(expected, sizeof(expected), inst, "bin");
#ifdef _WIN32
    strcat(expected, "\\app.exe");
#else
    strcat(expected, "/app");
#endif
    assert(file_exists(expected));
}

/* --- zephyr --- */
static void test_zephyr_install_missing_artifacts(void) {
    EosBackend b;
    char build[1024], inst[1024];
    eos_backend_zephyr_init(&b);
    join(build, sizeof(build), g_root, "zephyr-missing-b");
    join(inst, sizeof(inst), g_root, "zephyr-missing-i");
    assert(b.install(&b, build, inst) != EOS_OK);
}

static void test_zephyr_install_copies_elf_fallback(void) {
    EosBackend b;
    char build[1024], inst[1024], artifact[1024], expected[1024];
    eos_backend_zephyr_init(&b);
    join(build, sizeof(build), g_root, "zephyr-ok-b");
    join(inst, sizeof(inst), g_root, "zephyr-ok-i");
    /* Only the .elf exists: the install must take the fallback, not fail. */
    join(artifact, sizeof(artifact), build, "zephyr");
#ifdef _WIN32
    strcat(artifact, "\\zephyr.bin");
#else
    strcat(artifact, "/zephyr.elf");
#endif
    write_file(artifact, "fake-elf");
    assert(b.install(&b, build, inst) == EOS_OK);
#ifdef _WIN32
    join(expected, sizeof(expected), inst, "firmware.bin");
#else
    join(expected, sizeof(expected), inst, "firmware.elf");
#endif
    assert(file_exists(expected));
}

/* --- buildroot --- */
static void test_buildroot_install_missing_images(void) {
    EosBackend b;
    char build[1024], inst[1024];
    eos_backend_buildroot_init(&b);
    join(build, sizeof(build), g_root, "br-missing-b");
    join(inst, sizeof(inst), g_root, "br-missing-i");
    assert(b.install(&b, build, inst) != EOS_OK);
}

static void test_buildroot_install_copies_images(void) {
    EosBackend b;
    char build[1024], inst[1024], artifact[1024], expected[1024];
    eos_backend_buildroot_init(&b);
    join(build, sizeof(build), g_root, "br-ok-b");
    join(inst, sizeof(inst), g_root, "br-ok-i");
    join(artifact, sizeof(artifact), build, "images");
#ifdef _WIN32
    strcat(artifact, "\\rootfs.bin");
#else
    strcat(artifact, "/rootfs.bin");
#endif
    write_file(artifact, "fake-image");
    assert(b.install(&b, build, inst) == EOS_OK);
    join(expected, sizeof(expected), inst, "rootfs.bin");
    assert(file_exists(expected));
}

/* --- nuttx --- */
static void test_nuttx_install_missing_artifacts(void) {
    EosBackend b;
    char build[1024], inst[1024];
    eos_backend_nuttx_init(&b);
    join(build, sizeof(build), g_root, "nuttx-missing-b");
    join(inst, sizeof(inst), g_root, "nuttx-missing-i");
    assert(b.install(&b, build, inst) != EOS_OK);
}

static void test_nuttx_install_copies_image(void) {
    EosBackend b;
    char build[1024], inst[1024], artifact[1024], expected[1024];
    eos_backend_nuttx_init(&b);
    join(build, sizeof(build), g_root, "nuttx-ok-b");
    join(inst, sizeof(inst), g_root, "nuttx-ok-i");
    join(artifact, sizeof(artifact), build, "nuttx");
#ifdef _WIN32
    strcat(artifact, ".bin");
#endif
    write_file(artifact, "fake-nuttx");
    assert(b.install(&b, build, inst) == EOS_OK);
#ifdef _WIN32
    join(expected, sizeof(expected), inst, "firmware.bin");
#else
    join(expected, sizeof(expected), inst, "firmware.elf");
#endif
    assert(file_exists(expected));
}

/* --- freertos --- */
static void test_freertos_install_missing_artifacts(void) {
    EosBackend b;
    char build[1024], inst[1024];
    eos_backend_freertos_init(&b);
    join(build, sizeof(build), g_root, "freertos-missing-b");
    join(inst, sizeof(inst), g_root, "freertos-missing-i");
    assert(b.install(&b, build, inst) != EOS_OK);
}

static void test_freertos_install_copies_images(void) {
    EosBackend b;
    char build[1024], inst[1024], artifact[1024], expected[1024];
    eos_backend_freertos_init(&b);
    join(build, sizeof(build), g_root, "freertos-ok-b");
    join(inst, sizeof(inst), g_root, "freertos-ok-i");
    join(artifact, sizeof(artifact), build, "app.bin");
    write_file(artifact, "fake-fw");
    assert(b.install(&b, build, inst) == EOS_OK);
    join(expected, sizeof(expected), inst, "app.bin");
    assert(file_exists(expected));
}

int main(void) {
    snprintf(g_root, sizeof(g_root), "test_backend_install_tmp_%ld", (long)getpid());
    make_dirs(g_root);
    printf("backend install tests (issue #166)\n");

    TEST(test_cargo_install_missing_artifacts);
    TEST(test_cargo_install_copies_executables);
    TEST(test_zephyr_install_missing_artifacts);
    TEST(test_zephyr_install_copies_elf_fallback);
    TEST(test_buildroot_install_missing_images);
    TEST(test_buildroot_install_copies_images);
    TEST(test_nuttx_install_missing_artifacts);
    TEST(test_nuttx_install_copies_image);
    TEST(test_freertos_install_missing_artifacts);
    TEST(test_freertos_install_copies_images);

    printf("backend install: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
