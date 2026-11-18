// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-exec-shared: a program execed in a child that shares this
//! process's root and working directory, as clone(CLONE_FS) leaves them,
//! while this process waits; it exits as the child did, or with 126 when
//! the child's exec failed.
//!
//!   test-exec-shared <program> [<argument>...]

use core::ffi::{c_char, c_int};

use super::{err, strerror};

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_test_exec_shared(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: main()'s arguments.
    let args = unsafe { crate::ffi::args(argc, argv) };
    if args.len() < 2 {
        let me = args
            .first()
            .map_or("test-exec-shared".into(), |a| a.to_string_lossy());
        err(&format!("usage: {me} <program> [<argument>...]\n"));
        return 2;
    }
    // SAFETY: a child of this one-threaded process in a copy of its
    // memory, sharing its filesystem context; it only execs or exits.
    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_FS | libc::SIGCHLD, 0, 0, 0, 0) };
    if pid < 0 {
        err(&format!("clone: {}\n", strerror(errno())));
        return 2;
    }
    if pid == 0 {
        // SAFETY: the program and the arguments after it, which end in
        // main()'s NULL; the child gone if the exec fails.
        unsafe {
            libc::execv(args[1].as_ptr(), argv.add(1));
            err(&format!(
                "execv {}: {}\n",
                args[1].to_string_lossy(),
                strerror(errno())
            ));
            libc::fflush(core::ptr::null_mut());
            libc::_exit(126);
        }
    }
    let mut status = 0;
    // SAFETY: the child and room for its status.
    if unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) } < 0 {
        err(&format!("waitpid: {}\n", strerror(errno())));
        return 2;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        2
    }
}
