// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! exec-paths, of the end-to-end tests: every way a process execs that
//! the kernel observation upatch must see, each execing this program
//! again with --payload: fork(), vfork(), clone(), clone3(), a shebang
//! script, fexecve() of one, and a thread other than the leader; or one
//! way a test names.
//!
//!   exec-paths <scratch dir>
//!   exec-paths --replace|--execveat-empty|--fexecve|--drop-euid <program>
//!   exec-paths --execveat-dirfd <dir> <program>

use core::ffi::{CStr, c_char, c_int, c_void};
use std::ffi::CString;

use super::err;

unsafe extern "C" {
    static environ: *const *const c_char;
}

const CLONE_STACK_SIZE: usize = 1024 * 1024;

/// `program --payload`, which exits 0.
fn payload_argv(program: &CStr) -> [*const c_char; 3] {
    [program.as_ptr(), c"--payload".as_ptr(), core::ptr::null()]
}

/// In a child: the program execed with --payload, or the child gone.
fn exec_payload(argv: &[*const c_char; 3]) -> ! {
    // SAFETY: the argument vector, ending in NULL, and the environment.
    unsafe {
        libc::execve(argv[0], argv.as_ptr(), environ);
        libc::_exit(127)
    }
}

fn wait_child(pid: libc::pid_t) -> Result<(), ()> {
    let mut status = 0;
    // SAFETY: the child and room for its status.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(());
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// A child forked to run `child`, which execs or exits, waited for.
fn forked(child: impl FnOnce()) -> Result<(), ()> {
    // SAFETY: a fork; the child runs `child`, and exits should it return.
    match unsafe { libc::fork() } {
        0 => {
            child();
            // SAFETY: the child gone.
            unsafe { libc::_exit(127) }
        }
        pid if pid < 0 => Err(()),
        pid => wait_child(pid),
    }
}

fn fork_exec(program: &CStr) -> Result<(), ()> {
    let argv = payload_argv(program);
    forked(|| exec_payload(&argv))
}

#[allow(deprecated)]
fn vfork_exec(program: &CStr) -> Result<(), ()> {
    let argv = payload_argv(program);
    // SAFETY: a vfork; the child, which shares this stack, does no more
    // than exec or exit.
    match unsafe { libc::vfork() } {
        0 => exec_payload(&argv),
        pid if pid < 0 => Err(()),
        pid => wait_child(pid),
    }
}

extern "C" fn clone_child(data: *mut c_void) -> c_int {
    // SAFETY: the argument vector clone_exec() hands the child.
    exec_payload(unsafe { &*data.cast::<[*const c_char; 3]>() })
}

fn clone_exec(program: &CStr) -> Result<(), ()> {
    let mut argv = payload_argv(program);
    // SAFETY: a stack of its own for the child, unmapped once it is
    // waited for, and the argument vector, which outlives it.
    unsafe {
        let stack = libc::mmap(
            core::ptr::null_mut(),
            CLONE_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            return Err(());
        }
        let pid = libc::clone(
            clone_child,
            stack.cast::<u8>().add(CLONE_STACK_SIZE).cast(),
            libc::SIGCHLD,
            (&raw mut argv).cast(),
        );
        let ret = if pid < 0 { Err(()) } else { wait_child(pid) };
        libc::munmap(stack, CLONE_STACK_SIZE);
        ret
    }
}

fn clone3_exec(program: &CStr) -> Result<(), ()> {
    let argv = payload_argv(program);
    // struct clone_args: exit_signal is its fifth word.
    let mut args = [0u64; 11];
    args[4] = libc::SIGCHLD as u64;
    // SAFETY: clone3(2) of the arguments, of their size; the child
    // copies this process as fork() does, and execs or exits.
    let pid = unsafe { libc::syscall(libc::SYS_clone3, args.as_mut_ptr(), size_of_val(&args)) };
    match pid {
        0 => exec_payload(&argv),
        p if p < 0 => Err(()),
        p => wait_child(p as libc::pid_t),
    }
}

/// In a child: `program` execed by its fd, through fexecve() or
/// execveat() of an empty path.
fn exec_fd(program: &CStr, use_fexecve: bool, argv: &[*const c_char; 2]) -> ! {
    // SAFETY: the program opened and execed by its fd, or the child gone.
    unsafe {
        let fd = libc::open(program.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            libc::_exit(126);
        }
        if use_fexecve {
            libc::fexecve(fd, argv.as_ptr(), environ);
        } else {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                c"".as_ptr(),
                argv.as_ptr(),
                environ,
                libc::AT_EMPTY_PATH,
            );
        }
        libc::_exit(127)
    }
}

fn fd_exec_path(program: &CStr, use_fexecve: bool) -> Result<(), ()> {
    let argv = [program.as_ptr(), core::ptr::null()];
    forked(|| exec_fd(program, use_fexecve, &argv))
}

fn dirfd_exec_path(dir: &CStr, program: &CStr) -> Result<(), ()> {
    let argv = [program.as_ptr(), core::ptr::null()];
    forked(|| {
        // SAFETY: the directory opened and the program execed relative to
        // it, or the child gone.
        unsafe {
            let dirfd = libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            if dirfd < 0 {
                libc::_exit(126);
            }
            libc::syscall(
                libc::SYS_execveat,
                dirfd,
                program.as_ptr(),
                argv.as_ptr(),
                environ,
                0,
            );
            libc::_exit(127)
        }
    })
}

fn drop_euid_exec_path(program: &CStr) -> Result<(), ()> {
    let argv = payload_argv(program);
    forked(|| {
        // SAFETY: this child's ids dropped to nobody's, or the child gone.
        if unsafe { libc::setresuid(65534, 65534, 65534) } != 0 {
            // SAFETY: as above.
            unsafe { libc::_exit(125) };
        }
        exec_payload(&argv)
    })
}

/// A shell script that exits 0, made new as `dir/name`.
fn make_script(dir: &CStr, name: &str) -> Option<CString> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let path = CString::new([dir.to_bytes(), b"/", name.as_bytes()].concat()).ok()?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(std::ffi::OsStr::from_bytes(path.to_bytes()))
        .ok()?;
    f.write_all(b"#!/bin/sh\nexit 0\n").ok()?;
    Some(path)
}

/// This program execed with --payload from a thread other than the
/// leader.
fn thread_exec_path(program: &CStr) -> Result<(), ()> {
    let argv = payload_argv(program);
    // The pointers, which a thread takes as a number.
    let argv = argv.map(|p| p as usize);
    std::thread::spawn(move || exec_payload(&argv.map(|p| p as *const c_char)))
        .join()
        .map_err(|_| ())
}

/// One way of execing, run.
type Case<'a> = dyn Fn() -> Result<(), ()> + 'a;

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_exec_paths(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: main()'s arguments.
    let args = unsafe { crate::ffi::args(argc, argv) };
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    let status = |r: Result<(), ()>| c_int::from(r.is_err());
    match (word(1), args.len()) {
        (Some(b"--payload"), 2) => return 0,
        (Some(b"--replace"), 3) => exec_payload(&payload_argv(args[2])),
        (Some(b"--execveat-empty"), 3) => return status(fd_exec_path(args[2], false)),
        (Some(b"--fexecve"), 3) => return status(fd_exec_path(args[2], true)),
        (Some(b"--execveat-dirfd"), 4) => return status(dirfd_exec_path(args[2], args[3])),
        (Some(b"--drop-euid"), 3) => return status(drop_euid_exec_path(args[2])),
        _ => {}
    }
    let scripts = (args.len() == 2).then(|| {
        (
            make_script(args[1], "exec-script"),
            make_script(args[1], "exec-script-fd"),
        )
    });
    let Some((Some(script), Some(script_fd))) = scripts else {
        err("could not create shebang test executable\n");
        return 1;
    };
    let me = args[0];
    let cases: [(&str, &Case); 7] = [
        ("fork() -> execve()", &|| fork_exec(me)),
        ("vfork() -> execve()", &|| vfork_exec(me)),
        ("clone() -> execve()", &|| clone_exec(me)),
        ("clone3() -> execve()", &|| clone3_exec(me)),
        ("fork() -> shebang execve()", &|| fork_exec(&script)),
        ("fexecve() -> shebang", &|| fd_exec_path(&script_fd, true)),
        ("non-leader thread execve()", &|| thread_exec_path(me)),
    ];
    for (name, case) in cases {
        if case().is_err() {
            err(&format!("{name} case failed\n"));
            return 1;
        }
    }
    0
}
