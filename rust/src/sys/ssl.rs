// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libssl calls of the TLS policy, with the values of ssl.h and
//! tls1.h. The controls stand for the macros that send them.

use core::ffi::{c_char, c_int, c_long, c_void};

use super::openssl::X509Store;

/// An `SSL_CTX`.
pub enum SslCtx {}
/// An `SSL` connection.
pub enum Ssl {}

/// The callback of `SSL_CTX_set_info_callback()`.
pub type InfoCallback = unsafe extern "C" fn(ssl: *const Ssl, kind: c_int, val: c_int);

pub const SSL_CB_HANDSHAKE_DONE: c_int = 0x20;
/// `SSL_CTX_set1_groups_list()`.
pub const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
/// `SSL_CTX_set_min_proto_version()`.
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
/// `SSL_get_negotiated_group()`.
pub const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;
pub const TLS1_3_VERSION: c_long = 0x304;
pub const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;
pub const NID_UNDEF: c_int = 0;

unsafe extern "C" {
    pub fn SSL_CTX_ctrl(ctx: *mut SslCtx, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_set_info_callback(ctx: *mut SslCtx, cb: Option<InfoCallback>);
    pub fn SSL_CTX_get_cert_store(ctx: *const SslCtx) -> *mut X509Store;
    pub fn SSL_ctrl(ssl: *mut Ssl, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_group_to_name(ssl: *mut Ssl, id: c_int) -> *const c_char;
    pub fn SSL_get_servername(ssl: *const Ssl, kind: c_int) -> *const c_char;
}
