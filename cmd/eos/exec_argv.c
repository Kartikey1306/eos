// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

#include "exec_argv.h"

#ifdef _WIN32

#include <process.h>

int eos_exec_argv(const char *file, char *const argv[]) {
    /* _spawnvp does not invoke a shell: arguments are passed directly to
       the child, so shell metacharacters are inert. */
    int rc = _spawnvp(_P_WAIT, file, (const char *const *)argv);
    /* _spawnvp returns -1 on failure to start; otherwise the exit code. */
    return rc;
}

#else /* POSIX */

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int eos_exec_argv(const char *file, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        /* Child: replace image directly. No shell, so argv entries are
           passed verbatim — even hostile ones. */
        execvp(file, argv);
        _exit(127); /* execvp failed */
    }
    int status = 0;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
    if (w < 0) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1; /* killed by signal or otherwise abnormal */
}

#endif /* _WIN32 */
