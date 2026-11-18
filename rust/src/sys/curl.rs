// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The part of libcurl's easy interface shirudo uses, with the values of
//! curl.h. An option takes a `c_long`, a `CurlOff`, a pointer or a
//! callback, as curl_easy_setopt(3) lists it, and nothing else.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

/// A `CURL *` handle.
pub enum Curl {}

/// A `struct curl_slist`, which curl allocates and frees.
pub enum CurlSlist {}

/// A `CURLU *` URL handle.
pub enum CurlU {}

pub type CurlCode = c_int;
pub type CurlOff = i64;
pub type WriteCallback =
    unsafe extern "C" fn(ptr: *mut c_char, size: usize, nmemb: usize, ud: *mut c_void) -> usize;
/// The callback of `CURLOPT_SSL_CTX_FUNCTION`, given the `SSL_CTX`.
pub type SslCtxCallback =
    unsafe extern "C" fn(curl: *mut Curl, ssl_ctx: *mut c_void, userptr: *mut c_void) -> CurlCode;
/// A `CURLUcode`.
pub type CurlUCode = c_int;
/// A `CURLUPart`.
pub type CurlUPart = c_int;

pub const CURLE_OK: CurlCode = 0;
pub const CURL_GLOBAL_DEFAULT: c_long = 3;
pub const CURLE_SSL_CONNECT_ERROR: CurlCode = 35;
pub const CURLE_SSL_CIPHER: CurlCode = 59;
pub const CURLE_FILESIZE_EXCEEDED: CurlCode = 63;
pub const CURLE_SSL_CACERT_BADFILE: CurlCode = 77;
pub const CURL_ERROR_SIZE: usize = 256;

pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLOPT_URL: c_int = 10002;
pub const CURLOPT_ERRORBUFFER: c_int = 10010;
pub const CURLOPT_POSTFIELDS: c_int = 10015;
pub const CURLOPT_LOW_SPEED_LIMIT: c_int = 19;
pub const CURLOPT_LOW_SPEED_TIME: c_int = 20;
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_HEADERDATA: c_int = 10029;
pub const CURLOPT_SSLVERSION: c_int = 32;
pub const CURLOPT_CUSTOMREQUEST: c_int = 10036;
pub const CURLOPT_NOBODY: c_int = 44;
pub const CURLOPT_FAILONERROR: c_int = 45;
pub const CURLOPT_FOLLOWLOCATION: c_int = 52;
pub const CURLOPT_SSL_VERIFYPEER: c_int = 64;
pub const CURLOPT_MAXREDIRS: c_int = 68;
pub const CURLOPT_FORBID_REUSE: c_int = 75;
pub const CURLOPT_CONNECTTIMEOUT: c_int = 78;
pub const CURLOPT_TIMEOUT: c_int = 13;
pub const CURLOPT_HTTPGET: c_int = 80;
pub const CURLOPT_SSL_VERIFYHOST: c_int = 81;
pub const CURLOPT_NOSIGNAL: c_int = 99;
pub const CURLOPT_UNRESTRICTED_AUTH: c_int = 105;
pub const CURLOPT_SSL_CTX_FUNCTION: c_int = 20108;
pub const CURLOPT_SSL_CTX_DATA: c_int = 10109;
pub const CURLOPT_SSL_SESSIONID_CACHE: c_int = 150;
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_HEADERFUNCTION: c_int = 20079;
pub const CURLOPT_MAXFILESIZE_LARGE: c_int = 30117;
pub const CURLOPT_POSTFIELDSIZE_LARGE: c_int = 30120;
pub const CURLOPT_PROTOCOLS_STR: c_int = 10318;
pub const CURLOPT_REDIR_PROTOCOLS_STR: c_int = 10319;
/// The `CURLOPT_SSLVERSION` of TLS 1.3 at least.
pub const CURL_SSLVERSION_TLSV1_3: c_long = 7;
pub const CURLINFO_EFFECTIVE_URL: c_int = 0x100001;
pub const CURLINFO_RESPONSE_CODE: c_int = 0x200002;
pub const CURLUE_OK: CurlUCode = 0;
pub const CURLUPART_URL: CurlUPart = 0;
pub const CURLUPART_SCHEME: CurlUPart = 1;
pub const CURLUPART_HOST: CurlUPart = 5;

// The binaries link libcurl themselves; the crate's tests, which rustc
// links, name it.
#[cfg_attr(test, link(name = "curl"))]
unsafe extern "C" {
    pub fn curl_global_init(flags: c_long) -> CurlCode;
    pub fn curl_global_cleanup();
    pub fn curl_easy_init() -> *mut Curl;
    pub fn curl_easy_setopt(curl: *mut Curl, option: c_int, ...) -> CurlCode;
    pub fn curl_easy_perform(curl: *mut Curl) -> CurlCode;
    pub fn curl_easy_getinfo(curl: *mut Curl, info: c_int, ...) -> CurlCode;
    pub fn curl_easy_cleanup(curl: *mut Curl);
    pub fn curl_easy_strerror(code: CurlCode) -> *const c_char;
    pub fn curl_easy_escape(curl: *mut Curl, s: *const c_char, len: c_int) -> *mut c_char;
    pub fn curl_free(p: *mut c_void);
    pub fn curl_url() -> *mut CurlU;
    pub fn curl_url_cleanup(url: *mut CurlU);
    pub fn curl_url_set(
        url: *mut CurlU,
        what: CurlUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> CurlUCode;
    pub fn curl_url_get(
        url: *const CurlU,
        what: CurlUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> CurlUCode;
    pub fn curl_slist_append(list: *mut CurlSlist, s: *const c_char) -> *mut CurlSlist;
    pub fn curl_slist_free_all(list: *mut CurlSlist);
}

/// A long option, `1L` and its kin in the C.
///
/// # Safety
///
/// `curl` is a live handle and `option` one that takes a long.
pub unsafe fn set_long(curl: *mut Curl, option: c_int, value: c_long) {
    // SAFETY: the caller passes a handle and a long option.
    unsafe { curl_easy_setopt(curl, option, value) };
}

/// A pointer option: a C string, a list, a buffer or callback data.
///
/// # Safety
///
/// `curl` is a live handle, `option` takes a pointer, and what `value`
/// points to outlives the transfers the handle makes.
pub unsafe fn set_ptr<T>(curl: *mut Curl, option: c_int, value: *const T) {
    // SAFETY: the caller passes a handle, a pointer option and a pointer
    // that stays valid.
    unsafe { curl_easy_setopt(curl, option, value.cast::<c_void>()) };
}

/// A `curl_off_t` option.
///
/// # Safety
///
/// `curl` is a live handle and `option` one that takes a curl_off_t.
pub unsafe fn set_off(curl: *mut Curl, option: c_int, value: CurlOff) {
    // SAFETY: the caller passes a handle and a curl_off_t option.
    unsafe { curl_easy_setopt(curl, option, value) };
}

/// A write or header callback.
///
/// # Safety
///
/// `curl` is a live handle and `option` takes a write callback.
pub unsafe fn set_callback(curl: *mut Curl, option: c_int, callback: WriteCallback) {
    // SAFETY: the caller passes a handle and a callback option.
    unsafe { curl_easy_setopt(curl, option, callback) };
}
