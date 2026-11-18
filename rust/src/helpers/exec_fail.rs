// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-exec-fail: a program execed in a child with a stack limit too
//! small for the argument pointers, so that the exec fails after its
//! point of no return and the child dies by SIGSEGV with a core dump;
//! how the child ended printed.
//!
//!   test-exec-fail <program>

use core::ffi::{CStr, c_char, c_int};

use super::{err, helper_main, out, strerror};

helper_main!(shirudo_helper_test_exec_fail, run);

const EMPTY_ARGS: usize = 2500;
const STACK_LIMIT: libc::rlim_t = 16 * 1024;

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// In the child: the program execed with EMPTY_ARGS empty arguments
/// and no room for them on the stack.
fn exec_without_stack(path: &CStr, argv: &[*const c_char]) -> ! {
    let stack = libc::rlimit {
        rlim_cur: STACK_LIMIT,
        rlim_max: STACK_LIMIT,
    };
    let core = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: this child's limits, then its exec, or its exit.
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
            || libc::setrlimit(libc::RLIMIT_STACK, &stack) != 0
        {
            err(&format!("setrlimit: {}\n", strerror(errno())));
            libc::fflush(core::ptr::null_mut());
            libc::_exit(2);
        }
        libc::execv(path.as_ptr(), argv.as_ptr());
        err(&format!(
            "execv {}: {}\n",
            path.to_string_lossy(),
            strerror(errno())
        ));
        libc::fflush(core::ptr::null_mut());
        libc::_exit(2)
    }
}

fn run(args: &[&CStr]) -> c_int {
    let [_, program] = args else {
        err(&format!(
            "usage: {} <program>\n",
            args.first()
                .map_or("test-exec-fail".into(), |a| a.to_string_lossy())
        ));
        return 2;
    };
    // The arguments, all empty, made before the fork.
    let mut argv = vec![c"".as_ptr(); EMPTY_ARGS + 1];
    argv.push(core::ptr::null());
    // SAFETY: a fork of this one-threaded process; the child execs or
    // exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        err(&format!("fork: {}\n", strerror(errno())));
        return 2;
    }
    if pid == 0 {
        exec_without_stack(program, &argv);
    }
    let mut status = 0;
    // SAFETY: the child and room for its status.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        err(&format!("waitpid: {}\n", strerror(errno())));
        return 2;
    }
    if libc::WIFSIGNALED(status) {
        out(&format!("signal {}\n", libc::WTERMSIG(status)));
    } else {
        out(&format!("exit {}\n", libc::WEXITSTATUS(status)));
    }
    0
}
