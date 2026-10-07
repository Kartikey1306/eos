// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file exec_argv.h
 * @brief Shell-free process execution (argv form, no shell interpretation).
 *
 * Wraps fork+execvp (POSIX) and _spawnvp (Windows) so callers never need
 * system(). Because no shell is involved, metacharacters in arguments
 * (backticks, $(), ;, |, quotes, ...) are passed literally to the child
 * and can never be interpreted — blocklists are unnecessary.
 */

#ifndef EOS_EXEC_ARGV_H
#define EOS_EXEC_ARGV_H

/**
 * @brief Execute a program without invoking a shell.
 *
 * @param file  Program to execute (resolved via PATH).
 * @param argv  NULL-terminated argument vector; argv[0] should be the
 *              program name by convention.
 * @return      The child's exit status on normal exit; -1 if the child
 *              could not be started, was killed by a signal, or could not
 *              be waited for.
 */
int eos_exec_argv(const char *file, char *const argv[]);

#endif /* EOS_EXEC_ARGV_H */
