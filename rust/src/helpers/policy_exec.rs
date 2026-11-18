// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! policy-exec, of the end-to-end policy graph test: copies of it under
//! /tmp/shirudo-policy-exec-graph, labelled with policy bits, exec each
//! other and connect to 127.0.0.1, and the run as exec-1 reports in TAP
//! what the graph allowed and denied. What a copy does goes by the name
//! it runs as.
//!
//!   exec-1 run ok|<anything>
//!   <copy> target | <copy> connect <port>
//!   unlabeled verify | socket-b probe

use core::ffi::{CStr, c_char, c_int};

use super::out;

unsafe extern "C" {
    static environ: *const *const c_char;
}

const EXEC_1: &CStr = c"/tmp/shirudo-policy-exec-graph/exec-1";
const EXEC_2: &CStr = c"/tmp/shirudo-policy-exec-graph/exec-2";
const EXEC_4: &CStr = c"/tmp/shirudo-policy-exec-graph/exec-4";
const EXEC_UNLABELED: &CStr = c"/tmp/shirudo-policy-exec-graph/unlabeled";
const SOCKET_A: &CStr = c"/tmp/shirudo-policy-exec-graph/socket-a";
const SOCKET_B: &CStr = c"/tmp/shirudo-policy-exec-graph/socket-b";

/// `path` execed as `name mode [arg]` in a child: its exit status, 100
/// when the exec was denied with EACCES, 101 when it failed otherwise,
/// or None when it did not exit.
fn exec_child(path: &CStr, name: &CStr, mode: &CStr, arg: Option<&CStr>) -> Option<c_int> {
    let argv = [
        name.as_ptr(),
        mode.as_ptr(),
        arg.map_or(core::ptr::null(), CStr::as_ptr),
        core::ptr::null(),
    ];
    // SAFETY: a fork; the child execs or exits with why it could not.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        // SAFETY: the argument vector, ending in NULL, and the
        // environment; then the child gone.
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), environ);
            let denied = *libc::__errno_location() == libc::EACCES;
            libc::_exit(if denied { 100 } else { 101 });
        }
    }
    let mut status = 0;
    // SAFETY: the child and room for its status.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid || !libc::WIFEXITED(status) {
        return None;
    }
    Some(libc::WEXITSTATUS(status))
}

fn loopback(port: u16) -> libc::sockaddr_in {
    // SAFETY: an address of zeros, set to the loopback and the port.
    let mut a: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    a.sin_port = port.to_be();
    a
}

/// A listener on 127.0.0.1, and its port.
fn listen_loopback() -> Option<(c_int, u16)> {
    let mut a = loopback(0);
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: a socket, bound, listening, and its address read back; or
    // closed.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return None;
        }
        let sa = (&raw mut a).cast::<libc::sockaddr>();
        if libc::bind(fd, sa, len) != 0
            || libc::listen(fd, 1) != 0
            || libc::getsockname(fd, sa, &mut len) != 0
        {
            libc::close(fd);
            return None;
        }
        Some((fd, u16::from_be(a.sin_port)))
    }
}

/// A connection to 127.0.0.1 at `port`: 28 for socket-a and 29 for
/// another when made, 100 for socket-b denied with EACCES, else 101.
fn socket_connect(name: &[u8], port: &CStr) -> c_int {
    let port: u16 = port.to_str().ok().and_then(|p| p.parse().ok()).unwrap_or(0);
    let a = loopback(port);
    // SAFETY: a socket, connected and closed.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return 101;
        }
        let connected = libc::connect(
            fd,
            (&raw const a).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) == 0;
        let errno = *libc::__errno_location();
        libc::close(fd);
        match (connected, name) {
            (true, b"socket-a") => 28,
            (true, _) => 29,
            (false, b"socket-b") if errno == libc::EACCES => 100,
            _ => 101,
        }
    }
}

struct Tap {
    failed: bool,
}

impl Tap {
    fn report(&mut self, number: u32, passed: bool, title: &str) {
        out(&format!(
            "{}ok {number} - {title}\n",
            if passed { "" } else { "not " }
        ));
        self.failed |= !passed;
    }
}

fn run_graph(arg: Option<&CStr>) -> c_int {
    let mut tap = Tap { failed: false };
    tap.report(
        1,
        arg.is_some_and(|a| a.to_bytes() == b"ok"),
        "unlabeled execs to unlabeled and policy 0x1 are allowed",
    );
    tap.report(
        2,
        exec_child(EXEC_2, c"exec-2", c"target", None) == Some(22),
        "policy 0x1 allows exec to policy 0x2",
    );
    tap.report(
        3,
        exec_child(EXEC_4, c"exec-4", c"target", None) == Some(100),
        "policy 0x1 denies exec to policy 0x4",
    );
    tap.report(
        4,
        exec_child(EXEC_UNLABELED, c"unlabeled", c"target", None) == Some(100),
        "policy 0x1 denies unlabeled exec",
    );
    const T5: &str = "policy A connects to 127.0.0.1 using socket policy bits";
    const T6: &str = "policy B denies exec to an unlabeled file";
    const T7: &str = "policy B is denied 127.0.0.1 by socket policy bits";
    match listen_loopback() {
        None => {
            tap.report(5, false, T5);
            tap.report(6, false, T6);
            tap.report(7, false, T7);
        }
        Some((listener, port)) => {
            let port = std::ffi::CString::new(port.to_string()).unwrap_or_default();
            let socket_a = exec_child(SOCKET_A, c"socket-a", c"connect", Some(&port));
            let accepted = if socket_a == Some(28) {
                // SAFETY: the listener, and no room for the peer.
                unsafe { libc::accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) }
            } else {
                -1
            };
            if accepted >= 0 {
                // SAFETY: the connection accepted, closed once.
                unsafe { libc::close(accepted) };
            }
            tap.report(5, socket_a == Some(28) && accepted >= 0, T5);
            tap.report(
                6,
                exec_child(SOCKET_B, c"socket-b", c"probe", None) == Some(0),
                T6,
            );
            tap.report(
                7,
                exec_child(SOCKET_B, c"socket-b", c"connect", Some(&port)) == Some(100),
                T7,
            );
            // SAFETY: the listener, closed once.
            unsafe { libc::close(listener) };
        }
    }
    out("1..7\n");
    c_int::from(tap.failed)
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_policy_exec(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: main()'s arguments.
    let args = unsafe { super::args(argc, argv) };
    let me = args.first().map_or(&b""[..], |a| a.to_bytes());
    let name = me.rsplit(|&c| c == b'/').next().unwrap_or(me);
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    if word(1) == Some(b"target") {
        return match name {
            b"exec-1" => 11,
            b"exec-2" => 22,
            b"exec-4" => 44,
            b"unlabeled" => 45,
            _ => 46,
        };
    }
    if args.len() > 2 && word(1) == Some(b"connect") {
        return socket_connect(name, args[2]);
    }
    if name == b"unlabeled" && word(1) == Some(b"verify") {
        let ok = exec_child(EXEC_UNLABELED, c"unlabeled", c"target", None) == Some(45)
            && exec_child(EXEC_1, c"exec-1", c"target", None) == Some(11);
        return c_int::from(!ok);
    }
    if name == b"socket-b" && word(1) == Some(b"probe") {
        return c_int::from(exec_child(EXEC_UNLABELED, c"unlabeled", c"target", None) != Some(100));
    }
    if name != b"exec-1" || word(1) != Some(b"run") {
        return 47;
    }
    run_graph(args.get(2).copied())
}
