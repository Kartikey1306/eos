// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
// ISO/IEC 25000 | ISO/IEC/IEEE 15288:2023

#include "eos/backend.h"
#include "eos/shell_cmd.h"
#include <stdio.h>
#include <string.h>

/* -D<key>=<value> for every option; the key unquoted as one word, the value
 * quoted. A value with spaces used to split into two arguments. */
static void append_defines(EosShellCmd *cmd, const EosKeyValue *options,
                           int option_count, const char *skip_key) {
    for (int i = 0; i < option_count; i++) {
        if (skip_key && strcmp(options[i].key, skip_key) == 0) continue;
        eos_shell_cmd_text(cmd, " -D");
        eos_shell_cmd_word(cmd, options[i].key);
        eos_shell_cmd_text(cmd, "=");
        eos_shell_cmd_arg(cmd, options[i].value);
    }
}

static EosResult freertos_configure(EosBackend *self, const char *src_dir,
                                    const char *build_dir, const char *toolchain_file,
                                    const EosKeyValue *options, int option_count) {
    (void)self;
    EosShellCmd cmd;
    eos_shell_cmd_init(&cmd);
    eos_shell_cmd_text(&cmd, "cmake -S ");
    eos_shell_cmd_arg(&cmd, src_dir);
    eos_shell_cmd_text(&cmd, " -B ");
    eos_shell_cmd_arg(&cmd, build_dir);
    eos_shell_cmd_text(&cmd, " -G Ninja");
    if (toolchain_file && toolchain_file[0]) {
        eos_shell_cmd_text(&cmd, " -DCMAKE_TOOLCHAIN_FILE=");
        eos_shell_cmd_arg(&cmd, toolchain_file);
    }
    /* Pass FREERTOS_KERNEL_PATH and the rest as -D options. */
    append_defines(&cmd, options, option_count, NULL);
    return eos_shell_cmd_run(&cmd, "FreeRTOS configure");
}

static EosResult freertos_build(EosBackend *self, const char *build_dir, int jobs) {
    (void)self;
    EosShellCmd cmd;
    eos_shell_cmd_init(&cmd);
    eos_shell_cmd_text(&cmd, "cmake --build ");
    eos_shell_cmd_arg(&cmd, build_dir);
    eos_shell_cmd_text(&cmd, " -j ");
    eos_shell_cmd_int(&cmd, jobs > 0 ? jobs : 4);
    return eos_shell_cmd_run(&cmd, "FreeRTOS build");
}

static EosResult freertos_install(EosBackend *self, const char *build_dir,
                                  const char *install_dir) {
    (void)self;
    EosShellCmd cmd;
    eos_shell_cmd_init(&cmd);
#ifdef _WIN32
    eos_shell_cmd_text(&cmd, "if not exist ");
    eos_shell_cmd_arg(&cmd, install_dir);
    eos_shell_cmd_text(&cmd, " mkdir ");
    eos_shell_cmd_arg(&cmd, install_dir);
    static const char *const kinds[] = { "bin", "elf", "hex" };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        eos_shell_cmd_text(&cmd, i == 0 ? " && copy /Y " : " & copy /Y ");
        eos_shell_cmd_arg(&cmd, build_dir);
        eos_shell_cmd_text(&cmd, "\\*.");
        eos_shell_cmd_text(&cmd, kinds[i]);
        eos_shell_cmd_text(&cmd, " ");
        eos_shell_cmd_arg(&cmd, install_dir);
        eos_shell_cmd_text(&cmd, "\\ 2>nul");
    }
#else
    eos_shell_cmd_text(&cmd, "mkdir -p ");
    eos_shell_cmd_arg(&cmd, install_dir);
    eos_shell_cmd_text(&cmd, " && find ");
    eos_shell_cmd_arg(&cmd, build_dir);
    eos_shell_cmd_text(&cmd, " -maxdepth 2 \\( -name '*.bin' -o -name '*.elf' -o -name '*.hex' \\) -exec cp {} ");
    eos_shell_cmd_arg(&cmd, install_dir);
    eos_shell_cmd_text(&cmd, "/ \\; 2>/dev/null || true");
#endif
    return eos_shell_cmd_run(&cmd, "FreeRTOS install");
}

static EosResult freertos_clean(EosBackend *self, const char *build_dir) {
    (void)self;
    EosShellCmd cmd;
    eos_shell_cmd_init(&cmd);
    eos_shell_cmd_text(&cmd, "cmake --build ");
    eos_shell_cmd_arg(&cmd, build_dir);
    eos_shell_cmd_text(&cmd, " --target clean");
    return eos_shell_cmd_run(&cmd, "FreeRTOS clean");
}

void eos_backend_freertos_init(EosBackend *b) {
    memset(b, 0, sizeof(*b));
    strncpy(b->name, "freertos", EOS_MAX_NAME - 1);
    b->type = EOS_BUILD_FREERTOS;
    b->configure = freertos_configure;
    b->build = freertos_build;
    b->install = freertos_install;
    b->clean = freertos_clean;
}
