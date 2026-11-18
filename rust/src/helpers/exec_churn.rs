// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-exec-churn: as many execs of /bin/true as `workers` processes
//! make in `duration` seconds, each forking and waiting for one at a
//! time, and the rate printed.
//!
//!   test-exec-churn --duration <seconds> --workers <count>

use core::ffi::{CStr, c_int};
use std::time::{Duration, Instant};

use super::{err, helper_main, out};

helper_main!(shirudo_helper_test_exec_churn, run);

/// A count of more than 0.
fn positive(text: &CStr) -> Option<u64> {
    text.to_str().ok()?.parse().ok().filter(|&n| n > 0)
}

/// /bin/true run until `deadline`, one exec at a time; how many exited
/// 0 written to `fd`.
fn worker(deadline: Instant, fd: c_int) -> bool {
    let argv = [c"/bin/true".as_ptr(), core::ptr::null()];
    let mut completed: u64 = 0;
    while Instant::now() < deadline {
        // SAFETY: a fork of this process, one thread; the child only
        // execs or exits.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: a C string and the argument vector ending in NULL.
            unsafe {
                libc::execv(argv[0], argv.as_ptr());
                libc::_exit(127);
            }
        }
        if child < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        let mut status = 0;
        // SAFETY: the child just forked, and room for its status.
        while unsafe { libc::waitpid(child, &mut status, 0) } < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            completed += 1;
        }
    }
    // SAFETY: the count's bytes to the pipe.
    unsafe {
        crate::util::io::write_complete(fd, (&raw const completed).cast(), size_of::<u64>()) == 0
    }
}

fn run(args: &[&CStr]) -> c_int {
    let (mut duration, mut workers) = (0u64, 0u64);
    let mut it = args.iter().skip(1);
    let usage = || {
        let me = args
            .first()
            .map_or("test-exec-churn".into(), |a| a.to_string_lossy());
        err(&format!("usage: {me} --duration SEC --workers COUNT\n"));
        2
    };
    while let Some(arg) = it.next() {
        let slot = match arg.to_bytes() {
            b"--duration" => &mut duration,
            b"--workers" => &mut workers,
            _ => return usage(),
        };
        let Some(text) = it.next() else {
            return usage();
        };
        let Some(value) = positive(text) else {
            return 2;
        };
        *slot = value;
    }
    if duration == 0 || workers == 0 || workers > 1024 {
        return 2;
    }
    let start = Instant::now();
    let Some(deadline) = start.checked_add(Duration::from_secs(duration)) else {
        return 1;
    };
    let mut pipe = [0; 2];
    // SAFETY: room for the pipe's two ends.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return 1;
    }
    let mut failed = false;
    let mut children = Vec::new();
    for _ in 0..workers {
        // SAFETY: a fork of this process, one thread.
        match unsafe { libc::fork() } {
            // SAFETY: the child's copy of the read end, closed, and its
            // exit once the worker is done.
            0 => unsafe {
                libc::close(pipe[0]);
                libc::_exit(c_int::from(!worker(deadline, pipe[1])));
            },
            pid if pid < 0 => {
                failed = true;
                break;
            }
            pid => children.push(pid),
        }
    }
    // SAFETY: the pipe's ends, each closed once; the children waited for
    // and their counts read.
    let completed = unsafe {
        libc::close(pipe[1]);
        let mut completed = 0u64;
        for &child in &children {
            let mut count = 0u64;
            if libc::waitpid(child, core::ptr::null_mut(), 0) < 0 {
                failed = true;
            }
            if libc::read(pipe[0], (&raw mut count).cast(), size_of::<u64>())
                == size_of::<u64>() as isize
            {
                completed += count;
            } else {
                failed = true;
            }
        }
        libc::close(pipe[0]);
        completed
    };
    if failed {
        return 1;
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    let rate = if elapsed > 0 {
        completed as f64 * 1e9 / elapsed as f64
    } else {
        0.0
    };
    out(&format!(
        "execs={completed} elapsed_ns={elapsed} execs_per_sec={rate:.3} workers={workers}\n"
    ));
    0
}
