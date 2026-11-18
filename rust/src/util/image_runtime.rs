// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image runtime. The authenticated initrd mounts the runtime
//! image its bootstrap names and the config image the activation journal
//! selects, each a dm-verity device the BPF guards observed being made;
//! every later command but a few finds them as they were left, or
//! refuses to run.
//!
//! A command runs on one thread, so the state is the thread's. The
//! journal and what its callbacks reach are kept apart: a callback
//! borrows the state while the journal that calls it is borrowed, and a
//! borrow taken twice panics rather than aliases.

use core::cell::RefCell;
use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::errno::{
    E2BIG, EACCES, EBUSY, EEXIST, EINPROGRESS, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENODEV,
    ENOENT, ENOKEY, ENXIO, EPERM, EPROTO, ESTALE, EUCLEAN, last_errno, text,
};
use crate::heap::xfree;
use crate::sys::identity::{DEVICE_CONFIG, DEVICE_RUNTIME, DeviceAuthority, Identity};
use crate::sys::libc::{
    O_DIRECTORY, O_NOFOLLOW, O_PATH, Statvfs, explicit_bzero, fsetxattr, fstatvfs, fwrite, ioctl,
    stdout, umount2,
};
use crate::text::cstr;
use crate::util::bpf_sys::{bpf_map_get_next_key, bpf_map_lookup_elem, bpf_obj_get};
use crate::util::config::{self, CONF_PATH, Config};
use crate::util::config_image::{self, ConfigImageOpen};
use crate::util::config_update::{
    ConfigUpdate, ConfigUpdateOps, ConfigUpdateRecord, ConfigUpdateTarget, config_update_begin,
    config_update_boot, config_update_check, config_update_clear_staged, config_update_close,
    config_update_complete_boot, config_update_open, config_update_read, config_update_stage,
    config_update_stage_read, config_update_staged,
};
use crate::util::crypto_openssl::{
    key_algorithm, pubkey_digest, verify_detached_x509, x509_from_der,
};
use crate::util::dm_verity::{self, DmVerity, minor};
use crate::util::identity;
use crate::util::image_bootstrap::{self, ImageBootstrap, path_valid};
use crate::util::image_cache::{SEAL_LABEL, XATTR_SEAL, fetch_verified};
use crate::util::image_config;
use crate::util::image_guards::image_guards_ready;
use crate::util::image_keys::{self, RUNTIME_CERT_PATH};
use crate::util::io::{kernel_dev, read_whole};
use crate::util::json::JsonEmit;
use crate::util::keyring;
use crate::util::keys::{KEYS_MAX, TrustedCert, TrustedSet, keys_read_der_fd, members};
use crate::util::seal::seal_label;
use crate::util::tpm::{Tpm, tpm_boot_identity, tpm_close, tpm_open, tpm_pcr_extend, tpm_pcr_read};

const RUNTIME_DIR: &CStr = c"/run/shirudo/runtime";
const RUNTIME_CONF_PATH: &CStr = c"/run/shirudo/runtime/etc/shirudo/shirudo.conf";
const CONFIG_IMAGE_DIR: &CStr = c"/run/shirudo/config";
const CONFIG_CANDIDATE_DIR: &CStr = c"/run/shirudo/config-candidate";
const CONFIG_UPDATE_DIR: &CStr = c"/var/lib/shirudo/config-update";
const IMAGE_CACHE_DIR: &CStr = c"/var/lib/shirudo/images";
const DEVICES_MAP: &CStr = c"/run/shirudo/bpffs/devices";
const RUNTIME_MAPPING: &CStr = c"shirudo-runtime";

const MNT_DETACH: c_int = 2;
const ST_RDONLY: u64 = 1;
const ST_NOSUID: u64 = 2;
const ST_NODEV: u64 = 4;
const ST_NOEXEC: u64 = 8;
/// _IOR(0x12, 128, __u64).
const BLKGETDISKSEQ: core::ffi::c_ulong = 0x8008_1280;

/// Why a config is prepared: for the boot, in the initrd, as a live
/// update, or to stage it for the next boot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prepare {
    Boot,
    Update,
    Stage,
}

/// A config verification certificate of the runtime image, read once
/// from the image the guards watched and kept for the command.
struct ConfigCertificate {
    x509: openssl::x509::X509,
    der: Vec<u8>,
    fingerprint: [u8; 32],
}

/// The largest config root signature the image holds,
/// `CONFIG_IMAGE_SIG_MAX`.
const CONFIG_IMAGE_SIG_MAX: usize = 16384;

/// An ext4 file system's root directory's inode.
const EXT4_ROOT_INO: u64 = 2;

/// What the journal's callbacks reach: everything but the journal.
struct State {
    boot_target: ConfigUpdateTarget,
    boot_runtime: DmVerity,
    candidate: ConfigImageOpen,
    candidate_device: DmVerity,
    bootstrap_config: Config,
    bootstrap: ImageBootstrap,
    tpm: *mut Tpm,
    candidate_fd: Option<OwnedFd>,
    certificates: Vec<ConfigCertificate>,
    /// What current_config() refused status with.
    config_state: c_int,
    loaded: bool,
    boot_keys_open: bool,
    boot_target_valid: bool,
}

impl State {
    fn new() -> Self {
        State {
            // SAFETY: plain C data, for which all-zero bytes are a value.
            boot_target: unsafe { core::mem::zeroed() },
            boot_runtime: DmVerity::empty(),
            candidate: ConfigImageOpen::closed(),
            candidate_device: DmVerity::empty(),
            // SAFETY: as above.
            bootstrap_config: unsafe { core::mem::zeroed() },
            // SAFETY: as above.
            bootstrap: unsafe { core::mem::zeroed() },
            tpm: ptr::null_mut(),
            candidate_fd: None,
            certificates: Vec::new(),
            config_state: 0,
            loaded: false,
            boot_keys_open: false,
            boot_target_valid: false,
        }
    }

    fn candidate_raw(&self) -> c_int {
        self.candidate_fd.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::new());
    static JOURNAL: RefCell<ConfigUpdate> = const { RefCell::new(ConfigUpdate::closed()) };
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with_borrow_mut(f)
}

fn with_journal<R>(f: impl FnOnce(&mut ConfigUpdate) -> R) -> R {
    JOURNAL.with_borrow_mut(f)
}

fn journal_open() -> bool {
    JOURNAL.with_borrow(ConfigUpdate::is_open)
}

fn say(level: fn(&[u8]), text: String) {
    let text = CString::new(text).unwrap_or_default();

    level(text.to_bytes());
}

fn error(text: String) {
    say(crate::log::err, text);
}

fn warn(text: String) {
    say(crate::log::warn, text);
}

fn io_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

fn path(p: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(p.to_bytes()))
}

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout, which the other
    // commands write too.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn zero_record() -> ConfigUpdateRecord {
    ConfigUpdateRecord::zeroed()
}

fn zero_target() -> ConfigUpdateTarget {
    // SAFETY: plain C data, for which all-zero bytes are a value.
    unsafe { core::mem::zeroed() }
}

/// strscpy(): `src` into `dst`, truncated, NUL-terminated.
fn copy_str(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n..].fill(0);
}

/// A root-owned directory no one else can write, made 0700 and sealed
/// if it was not there.
fn mkdir_owned(p: &CStr) -> c_int {
    let created = match DirBuilder::new().mode(0o700).create(path(p)) {
        Ok(()) => true,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => false,
        Err(e) => return io_err(&e),
    };
    let st = match fs::symlink_metadata(path(p)) {
        Ok(st) => st,
        Err(e) => return io_err(&e),
    };
    if !st.is_dir() || st.uid() != 0 || st.mode() & 0o022 != 0 {
        return -EPERM;
    }
    if !created {
        return 0;
    }
    // SAFETY: a C string.
    unsafe { seal_label(p.as_ptr()) }
}

/// The dm name of the config image with this root.
fn mapping_name(root: &[u8; 32]) -> CString {
    let hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
    CString::new(format!("shirudo-config-{hex}")).unwrap_or_default()
}

/// The root of the config image on `device` at `dir` as a descriptor,
/// opened once and checked where it was opened, `bad` when it is not: a
/// path checked first and opened after is root's to swap between the
/// two in a mount namespace of its own, and a directory of the image
/// bound elsewhere has the image's device too, but every relative path
/// read from it lands elsewhere in the image.
fn config_root_open(dir: &CStr, device: u64, bad: c_int) -> Result<OwnedFd, c_int> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_DIRECTORY | O_NOFOLLOW)
        .open(path(dir))
        .map_err(|e| io_err(&e))?;
    let st = f.metadata().map_err(|e| io_err(&e))?;
    if st.dev() == device && st.ino() == EXT4_ROOT_INO {
        Ok(f.into())
    } else {
        Err(bad)
    }
}

/// The DER of the certificate open on `fd`, as keys_read_der_fd() reads
/// it.
fn der_of_fd(fd: c_int) -> Result<Vec<u8>, c_int> {
    let (mut der, mut size) = (ptr::null_mut(), 0usize);
    // SAFETY: the fd and rooms for the bytes keys_read_der_fd() allocates.
    let ret = unsafe { keys_read_der_fd(fd, &mut der, &mut size) };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the size bytes keys_read_der_fd() allocated.
    let bytes = unsafe { crate::ffi::slice(der, size) }.to_vec();
    // SAFETY: the allocation, freed once.
    unsafe { xfree(der.cast(), size) };
    Ok(bytes)
}

/// The config verification certificate the bootstrap names at `index`,
/// from the runtime image on `device`: an ML-DSA-87 key, none named
/// twice.
fn read_config_certificate(s: &mut State, index: usize, device: u64) -> c_int {
    let name = CString::new(cstr(&s.bootstrap.certificates[index])).unwrap_or_default();
    let fd = match open_runtime_file(&name, device) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let der = der_of_fd(fd.as_raw_fd());
    drop(fd);
    let cert = der.and_then(|der| {
        let x509 = x509_from_der(&der)?;
        if key_algorithm(&x509, 32)?.as_bytes() != b"ML-DSA-87" {
            return Err(-EKEYREJECTED);
        }
        let fingerprint = pubkey_digest(&x509)?;
        Ok(ConfigCertificate {
            x509,
            der,
            fingerprint,
        })
    });
    match cert {
        Err(err) => err,
        Ok(c)
            if s.certificates
                .iter()
                .any(|o| o.fingerprint == c.fingerprint) =>
        {
            -EEXIST
        }
        Ok(c) => {
            s.certificates.push(c);
            0
        }
    }
}

/// Whether a config verification certificate signed the root hash of the
/// image `opened`: 0, -ENOKEY without a certificate or a signature,
/// -EKEYREJECTED when none did.
fn verify_config_root(s: &State, opened: &ConfigImageOpen) -> c_int {
    if s.bootstrap.n_certificates == 0 || opened.signature_fd < 0 {
        return -ENOKEY;
    }
    let sig = match read_whole(
        opened.signature_fd,
        c"config root signature",
        CONFIG_IMAGE_SIG_MAX,
    ) {
        Ok(sig) => sig,
        Err(err) => return err,
    };
    let root: String = opened
        .image
        .root_hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let signed = s.certificates[..s.bootstrap.n_certificates.min(s.certificates.len())]
        .iter()
        .any(|c| verify_detached_x509(root.as_bytes(), &sig, &c.x509) == 0);
    if signed { 0 } else { -EKEYREJECTED }
}

/// Whether the BPF guards observed `device`, the dm-verity mapping with
/// `root` when given, being made as `kind`, and this very instance of
/// it: 0 or -EACCES.
fn device_observed(device: u64, root: Option<&[u8; 32]>, kind: u32) -> c_int {
    let node = format!("/dev/dm-{}", minor(device));
    let block = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&node)
    {
        Ok(f) => f,
        Err(e) => return io_err(&e),
    };
    match block.metadata() {
        Ok(st) if st.file_type().is_block_device() && st.rdev() == device => {}
        Ok(_) => return -EPERM,
        Err(e) => return io_err(&e),
    }
    let mut diskseq = 0u64;
    // SAFETY: the open block device and room for its sequence number.
    if unsafe { ioctl(block.as_raw_fd(), BLKGETDISKSEQ, &mut diskseq) } != 0 {
        return last_errno();
    }
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(DEVICES_MAP.as_ptr()) };
    if fd < 0 {
        return last_errno();
    }
    // SAFETY: the map bpf_obj_get() opened, the fd's from here.
    let map = unsafe { OwnedFd::from_raw_fd(fd) };
    let dev = kernel_dev(device);
    let (mut key, mut next) = (0u64, 0u64);
    // SAFETY: the map and room for its first key.
    if unsafe { bpf_map_get_next_key(map.as_raw_fd(), ptr::null(), (&raw mut key).cast()) } != 0 {
        return -EACCES;
    }
    loop {
        let mut entry = DeviceAuthority::zeroed();
        // SAFETY: the map, a key of it and room for its value.
        let found = unsafe {
            bpf_map_lookup_elem(
                map.as_raw_fd(),
                (&raw const key).cast(),
                (&raw mut entry).cast(),
            )
        } == 0;
        if found
            && entry.dev == dev
            && entry.kind == kind
            && entry.diskseq == diskseq
            && root.is_none_or(|r| entry.root == *r)
        {
            return 0;
        }
        // SAFETY: the map, a key of it and room for the next.
        if unsafe {
            bpf_map_get_next_key(
                map.as_raw_fd(),
                (&raw const key).cast(),
                (&raw mut next).cast(),
            )
        } != 0
        {
            return -EACCES;
        }
        key = next;
    }
}

/// Whether the filesystem under `fd` is mounted read-only, nosuid and
/// nodev, and noexec unless `executable`: 0 or -EPERM.
fn mount_flags(fd: c_int, executable: bool) -> c_int {
    let required = ST_RDONLY | ST_NOSUID | ST_NODEV | if executable { 0 } else { ST_NOEXEC };
    // SAFETY: plain C data, filled below.
    let mut st: Statvfs = unsafe { core::mem::zeroed() };
    // SAFETY: the caller's fd and room for its filesystem's state.
    if unsafe { fstatvfs(fd, &mut st) } != 0 {
        return last_errno();
    }
    if st.f_flag & required == required {
        0
    } else {
        -EPERM
    }
}

/// A regular file of the runtime image, on `device`.
fn open_runtime_file(p: &CStr, device: u64) -> Result<OwnedFd, c_int> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path(p))
        .map_err(|e| io_err(&e))?;
    let st = f.metadata().map_err(|e| io_err(&e))?;
    if !st.is_file() || st.dev() != device {
        return Err(-EPERM);
    }
    Ok(f.into())
}

fn runtime_device() -> Result<u64, c_int> {
    fs::metadata(path(RUNTIME_DIR))
        .map(|m| m.dev())
        .map_err(|e| io_err(&e))
}

/// The settings of the mounted runtime image, and its config
/// certificates, read for this command. Outside the initrd the guards
/// must have watched the runtime being mapped.
fn load_runtime_config(s: &mut State, trusted_boot: bool) -> c_int {
    if !trusted_boot {
        let ret = image_guards_ready();
        if ret != 0 {
            return ret;
        }
    }
    let dev = match runtime_device() {
        Ok(dev) => dev,
        Err(err) => return err,
    };
    if !trusted_boot {
        let ret = device_observed(dev, Some(&s.bootstrap.runtime_root), DEVICE_RUNTIME);
        if ret != 0 {
            return ret;
        }
    }
    let conf = match open_runtime_file(RUNTIME_CONF_PATH, dev) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    s.bootstrap.n_certificates = 0;
    let mut ret = image_bootstrap::read_fd(conf.as_raw_fd(), &mut s.bootstrap, false);
    if ret == 0 {
        ret = config::load_fd(&mut s.bootstrap_config, conf.as_raw_fd(), RUNTIME_CONF_PATH);
    }
    drop(conf);
    if ret != 0 {
        return ret;
    }
    if s.bootstrap.config[0] == 0 || s.bootstrap.n_certificates == 0 || !s.bootstrap.have_pcr {
        return -EINVAL;
    }
    let ret = image_config::set(&s.bootstrap_config, -1);
    if ret != 0 {
        return ret;
    }
    s.certificates.clear();
    for i in 0..s.bootstrap.n_certificates {
        let ret = read_config_certificate(s, i, dev);
        if ret != 0 {
            s.certificates.clear();
            return ret;
        }
    }
    match open_runtime_file(RUNTIME_CERT_PATH, dev) {
        Ok(fd) => mount_flags(fd.as_raw_fd(), true),
        Err(err) => err,
    }
}

/// Maps, checks and mounts the runtime image the bootstrap names, or
/// takes the one the guards watched being mounted. The initrd checks it
/// against the root its authenticated UKI carries.
fn mount_runtime(s: &mut State, trusted_boot: bool) -> c_int {
    if !s.loaded {
        return -EINVAL;
    }
    if !trusted_boot {
        if let Ok(dev) = runtime_device() {
            if device_observed(dev, Some(&s.bootstrap.runtime_root), DEVICE_RUNTIME) == 0 {
                return load_runtime_config(s, trusted_boot);
            }
        }
    }
    let mut opened = ConfigImageOpen::closed();
    let mut device = DmVerity::empty();
    let mut created = false;
    let mut step = "open runtime image";
    let mut ret = config_image::place(
        ConfigImageOpen::open(
            CStr::from_bytes_until_nul(&s.bootstrap.runtime).unwrap_or_default(),
            Some(&s.bootstrap.runtime_root),
        ),
        &mut opened,
    );
    if ret == 0 {
        step = "prepare runtime mountpoint";
        ret = mkdir_owned(RUNTIME_DIR);
    }
    if ret == 0 {
        step = "create runtime dm-verity mapping";
        ret = dm_verity::place(dm_verity::create(&opened, RUNTIME_MAPPING), &mut device);
        created = ret == 0;
    }
    if ret == -EEXIST {
        step = "inspect runtime dm-verity mapping";
        ret = dm_verity::place(
            dm_verity::inspect(RUNTIME_MAPPING, &opened.image),
            &mut device,
        );
    }
    if ret == 0 {
        step = "verify runtime image";
        ret = dm_verity::verify(&device, &opened);
    }
    if ret == 0 {
        step = "mount runtime image";
        ret = dm_verity::mount_at(&device, RUNTIME_DIR, true);
    }
    if ret != 0 && created {
        let cleanup = dm_verity::remove(&mut device, false);
        if cleanup != 0 {
            warn(format!(
                "image: cannot remove runtime mapping: {}",
                text(cleanup)
            ));
        }
    }
    dm_verity::close_loops(&mut device);
    if ret == 0 && trusted_boot {
        s.boot_runtime = device;
    }
    opened.close();
    if ret == 0 {
        step = "load runtime config";
        ret = load_runtime_config(s, trusted_boot);
        // SAFETY: a C string.
        if ret != 0 && unsafe { umount2(RUNTIME_DIR.as_ptr(), MNT_DETACH) } != 0 {
            warn(format!(
                "image: cannot unmount the runtime: {}",
                text(last_errno())
            ));
        }
    }
    if ret != 0 {
        error(format!("image: {step}: {}", text(ret)));
    }
    ret
}

unsafe extern "C" fn seal_fd(_: *mut c_void, fd: c_int) -> c_int {
    let label = SEAL_LABEL.to_bytes();
    // SAFETY: the journal's fd, a C string and the label's bytes.
    if unsafe {
        fsetxattr(
            fd,
            XATTR_SEAL.as_ptr(),
            label.as_ptr().cast(),
            label.len(),
            0,
        )
    } != 0
    {
        return last_errno();
    }
    0
}

unsafe extern "C" fn boot_identity(_: *mut c_void, reset: *mut u32, restart: *mut u32) -> c_int {
    let tpm = with_state(|s| s.tpm);
    // SAFETY: the TPM open_update() opened and the journal's rooms.
    unsafe { tpm_boot_identity(tpm, reset, restart) }
}

unsafe extern "C" fn pcr_read(_: *mut c_void, pcr: u32, out: *mut u8) -> c_int {
    let tpm = with_state(|s| s.tpm);
    // SAFETY: the TPM open_update() opened and the journal's room.
    unsafe { tpm_pcr_read(tpm, pcr, out) }
}

unsafe extern "C" fn pcr_extend(_: *mut c_void, pcr: u32, event: *const u8) -> c_int {
    let tpm = with_state(|s| s.tpm);
    // SAFETY: the TPM open_update() opened and the journal's event.
    unsafe { tpm_pcr_extend(tpm, pcr, event) }
}

/// Removes a config mapping the guards watched shirudo make that is not
/// the active config's: a candidate an update or a stage is done with,
/// or one an interrupted update left. One the guards did not watch being
/// made is not shirudo's, and stays.
fn collect_mapping(name: &CStr, device: u64, active: u64) -> c_int {
    if device == active || device_observed(device, None, DEVICE_CONFIG) != 0 {
        return 0;
    }
    let name = name.to_bytes();
    let mut retired = DmVerity::empty();
    if name.len() >= retired.name.len() {
        return -ENAMETOOLONG;
    }
    copy_str(&mut retired.name, name);
    retired.device = device;
    let ret = dm_verity::remove(&mut retired, false);
    if ret != 0 && ret != -EBUSY && ret != -ENXIO && ret != -ENODEV {
        warn(format!(
            "image: cannot remove retired mapping {}: {}",
            String::from_utf8_lossy(name),
            text(ret)
        ));
    }
    0
}

fn collect_mappings(journal_open: bool) {
    if !journal_open {
        return;
    }
    let active = fs::metadata(path(CONFIG_IMAGE_DIR)).map_or(0, |m| m.dev());
    let ret = dm_verity::list(|name, device| collect_mapping(name, device, active));
    if ret != 0 {
        warn(format!(
            "image: cannot collect retired mappings: {}",
            text(ret)
        ));
    }
}

fn close_candidate(s: &mut State, journal_open: bool) {
    s.candidate_fd = None;
    // SAFETY: a C string.
    if journal_open && unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), MNT_DETACH) } != 0 {
        let err = last_errno();
        if err != -EINVAL && err != -ENOENT {
            warn(format!(
                "image: cannot release candidate mount: {}",
                text(err)
            ));
        }
    }
    dm_verity::close_loops(&mut s.candidate_device);
    s.candidate.close();
}

/// `remove` until it is not -EBUSY, 100 times at most and 10 ms apart:
/// a just-rejected mapping stays busy while udev probes it.
fn retry_busy(remove: impl FnMut() -> c_int) -> c_int {
    retry_busy_with(remove, std::thread::sleep)
}

/// As [`retry_busy`], with `pause` for each wait between two attempts.
pub(crate) fn retry_busy_with(
    mut remove: impl FnMut() -> c_int,
    mut pause: impl FnMut(std::time::Duration),
) -> c_int {
    let mut ret = 0;
    for attempt in 0..100 {
        ret = remove();
        if ret != -EBUSY {
            return ret;
        }
        if attempt < 99 {
            pause(std::time::Duration::from_millis(10));
        }
    }
    ret
}

fn remove_candidate(device: &mut DmVerity) -> c_int {
    retry_busy(|| dm_verity::remove(device, false))
}

/// The candidate's BPF trust set, valid; for a live update, also all
/// held by the kernel, which enrols a set only at boot.
fn candidate_keys(fd: c_int, enrolled: bool) -> c_int {
    // SAFETY: an all-zero set is an empty one.
    let mut set: Box<TrustedSet> = Box::new(unsafe { core::mem::zeroed() });
    let mut ret = image_keys::validate_set(RUNTIME_CERT_PATH, fd, &mut set);
    if ret == 0 && enrolled {
        ret = image_keys::check_set(&set);
    }
    if ret == -ENOKEY {
        error("image: BPF signer was not enrolled at boot; reboot with the new trusted key set required".into());
    }
    ret
}

fn mount_candidate(s: &mut State) -> c_int {
    let current =
        fs::metadata(path(CONFIG_IMAGE_DIR)).is_ok_and(|m| m.dev() == s.candidate_device.device);
    let dir = if current {
        CONFIG_IMAGE_DIR
    } else {
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), MNT_DETACH) } != 0 {
            let err = last_errno();
            if err != -EINVAL && err != -ENOENT {
                return err;
            }
        }
        let mut ret = mkdir_owned(CONFIG_CANDIDATE_DIR);
        if ret == 0 {
            ret = dm_verity::mount_at(&s.candidate_device, CONFIG_CANDIDATE_DIR, false);
        }
        if ret != 0 {
            return ret;
        }
        CONFIG_CANDIDATE_DIR
    };
    match config_root_open(dir, s.candidate_device.device, -ESTALE) {
        Ok(fd) => {
            s.candidate_fd = Some(fd);
            0
        }
        Err(err) => err,
    }
}

/// Maps, checks and mounts the config image `target` names as the
/// candidate, a config verification certificate having signed its root,
/// and validates it; outside the initrd, also that the guards watched
/// its mapping being made, and for a live update that the kernel holds
/// its keys. A mapping made for a candidate refused is removed again.
/// The journal is open whenever this runs.
fn prepare_config(s: &mut State, target: &ConfigUpdateTarget, purpose: Prepare) -> c_int {
    let trusted_boot = purpose == Prepare::Boot;

    close_candidate(s, true);
    if !trusted_boot {
        collect_mappings(true);
    }
    let prefix = cstr(&target.prefix);
    let cache = [IMAGE_CACHE_DIR.to_bytes(), b"/"].concat();
    if !prefix.starts_with(&cache) || !path_valid(prefix) {
        return -EPERM;
    }
    let ret = config_image::place(
        ConfigImageOpen::open(
            CStr::from_bytes_until_nul(&target.prefix).unwrap_or_default(),
            None,
        ),
        &mut s.candidate,
    );
    if ret != 0 {
        return ret;
    }
    if target.root_hash != s.candidate.image.root_hash {
        return -EKEYREJECTED;
    }
    let ret = verify_config_root(s, &s.candidate);
    if ret != 0 {
        return ret;
    }
    let name = mapping_name(&target.root_hash);
    let mut created = false;
    // SAFETY: a C string, the candidate image and its mapping to fill.
    let mut ret = dm_verity::place(
        dm_verity::inspect(&name, &s.candidate.image),
        &mut s.candidate_device,
    );
    if ret == -ENXIO || ret == -ENODEV || ret == -ENOENT {
        ret = dm_verity::place(
            dm_verity::create(&s.candidate, &name),
            &mut s.candidate_device,
        );
        created = ret == 0;
    }
    if ret == 0 {
        ret = dm_verity::verify(&s.candidate_device, &s.candidate);
    }
    if ret == 0 && !trusted_boot {
        ret = device_observed(
            s.candidate_device.device,
            Some(&s.candidate.image.root_hash),
            DEVICE_CONFIG,
        );
    }
    if ret == 0 {
        ret = mount_candidate(s);
        if ret == 0 {
            let fd = s.candidate_raw();
            ret = mount_flags(fd, false);
            if ret == 0 {
                ret = crate::util::image_config::validate(fd);
            }
            if ret == 0 && !trusted_boot {
                ret = candidate_keys(fd, purpose == Prepare::Update);
            }
        }
    }
    if ret != 0 && created {
        close_candidate(s, true);
        let cleanup = remove_candidate(&mut s.candidate_device);
        if cleanup != 0 && cleanup != -ENXIO && cleanup != -ENODEV {
            warn(format!(
                "image: cannot remove rejected mapping {}: {}",
                String::from_utf8_lossy(cstr(&s.candidate_device.name)),
                text(cleanup)
            ));
        }
    }
    ret
}

/// Revokes what the candidate revokes and mounts it as the config, the
/// one the image config reads from here.
fn activate_config(s: &mut State, boot: bool) -> c_int {
    let ret = image_keys::apply(s.candidate_raw(), boot);
    if ret != 0 {
        return ret;
    }
    let ret = mkdir_owned(CONFIG_IMAGE_DIR);
    if ret != 0 {
        return ret;
    }
    let dev = match fs::metadata(path(CONFIG_IMAGE_DIR)) {
        Ok(m) => m.dev(),
        Err(e) => return io_err(&e),
    };
    if dev != s.candidate_device.device {
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_IMAGE_DIR.as_ptr(), MNT_DETACH) } != 0 {
            let err = last_errno();
            if err != -EINVAL {
                return err;
            }
        }
        let ret = dm_verity::mount_at(&s.candidate_device, CONFIG_IMAGE_DIR, false);
        if ret != 0 {
            return ret;
        }
    }
    let dir = match config_root_open(CONFIG_IMAGE_DIR, s.candidate_device.device, -ESTALE) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let ret = mount_flags(dir.as_raw_fd(), false);
    if ret != 0 {
        return ret;
    }
    image_config::set(&s.bootstrap_config, dir.as_raw_fd())
}

unsafe extern "C" fn prepare_update(_: *mut c_void, target: *const ConfigUpdateTarget) -> c_int {
    // SAFETY: the journal's target.
    let target = unsafe { &*target };
    with_state(|s| prepare_config(s, target, Prepare::Update))
}

unsafe extern "C" fn activate_update(_: *mut c_void, _: *const ConfigUpdateTarget) -> c_int {
    with_state(|s| activate_config(s, false))
}

unsafe extern "C" fn activate_boot(_: *mut c_void, _: *const ConfigUpdateTarget) -> c_int {
    with_state(|s| activate_config(s, true))
}

static UPDATE_OPS: ConfigUpdateOps = ConfigUpdateOps {
    boot_identity: Some(boot_identity),
    pcr_read: Some(pcr_read),
    pcr_extend: Some(pcr_extend),
    prepare: Some(prepare_update),
    activate: Some(activate_update),
    seal: Some(seal_fd),
    checkpoint: None,
    lock_wait_ms: 30 * 1000,
};

/// Boot and live updates record key revocations differently.
static BOOT_OPS: ConfigUpdateOps = ConfigUpdateOps {
    boot_identity: Some(boot_identity),
    pcr_read: Some(pcr_read),
    pcr_extend: Some(pcr_extend),
    prepare: Some(prepare_update),
    activate: Some(activate_boot),
    seal: Some(seal_fd),
    checkpoint: None,
    lock_wait_ms: 0,
};

fn open_update() -> c_int {
    if journal_open() {
        return 0;
    }
    let mut ret = mkdir_owned(CONFIG_UPDATE_DIR);
    if ret == 0 {
        // SAFETY: room for the TPM.
        ret = with_state(|s| unsafe { tpm_open(&mut s.tpm) });
    }
    if ret == 0 {
        // SAFETY: a C string, the operations, no context, and the journal.
        ret = with_journal(|j| unsafe {
            config_update_open(CONFIG_UPDATE_DIR.as_ptr(), &UPDATE_OPS, ptr::null_mut(), j)
        });
    }
    ret
}

/// The config the boot activates: the one staged for it, the journal's
/// selection, or the bootstrap's config without one, as the image there
/// is now.
fn boot_target(target: &mut ConfigUpdateTarget) -> c_int {
    let mut previous = zero_record();
    // SAFETY: the open journal and room for its record.
    let ret = with_journal(|j| unsafe { config_update_read(j, &mut previous) });
    let selected = ret == 0;
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    if selected {
        let (mut reset, mut restart) = (0u32, 0u32);
        let mut staged = zero_target();
        let tpm = with_state(|s| s.tpm);
        // SAFETY: the TPM open_update() opened and rooms for its counts.
        let mut ret = unsafe { tpm_boot_identity(tpm, &mut reset, &mut restart) };
        if ret == 0 {
            // SAFETY: the open journal, the record read and room for the
            // staged target.
            ret =
                with_journal(|j| unsafe { config_update_staged(j, &previous, reset, &mut staged) });
        }
        if ret < 0 {
            return ret;
        }
        if ret > 0 {
            *target = staged;
            return 0;
        }
    }
    let prefix = if selected {
        cstr(&previous.target.prefix).to_vec()
    } else {
        with_state(|s| cstr(&s.bootstrap.config).to_vec())
    };
    let prefix_c = CString::new(prefix.clone()).unwrap_or_default();
    let mut opened = ConfigImageOpen::closed();
    let ret = config_image::place(ConfigImageOpen::open(&prefix_c, None), &mut opened);
    if ret != 0 {
        return ret;
    }
    let ret = if selected && previous.target.root_hash != opened.image.root_hash {
        -EKEYREJECTED
    } else {
        copy_str(&mut target.prefix, &prefix);
        target.root_hash = opened.image.root_hash;
        0
    };
    opened.close();
    ret
}

fn boot_keys_error(step: &str, ret: c_int) -> c_int {
    error(format!("initrd boot keys: {step}: {}", text(ret)));
    ret
}

/// The config verification certificates into the dm-verity keyring,
/// sealed after them: the kernel trusts every key in it for config
/// roots, so whether init sealed it now or earlier this boot, it must
/// hold exactly the runtime image's set.
fn enroll_config_keys(s: &State) -> c_int {
    let ring = keyring::dm_verity_serial();
    if ring < 0 {
        return boot_keys_error("lookup dm-verity keyring", ring);
    }
    let mut certs = Vec::with_capacity(s.certificates.len());
    let mut added = false;
    for c in &s.certificates {
        certs.push(&c.der[..]);
        let key = keyring::dm_verity_add_cert(&c.der);
        if key < 0 && key != -EPERM && key != -EACCES {
            return boot_keys_error("add config verification certificate", key);
        }
        added |= key >= 0;
    }
    if added {
        let ret = keyring::dm_verity_seal();
        if ret == -EEXIST {
            return boot_keys_error(
                "seal dm-verity keyring restricted by another task (tampered)",
                -EKEYREJECTED,
            );
        }
        if ret != 0 {
            return boot_keys_error("seal dm-verity keyring", ret);
        }
    }
    if !added && keyring::holds_exactly(ring, &[]) == 1 {
        return boot_keys_error(
            "dm-verity keyring sealed empty at boot; boot with dm_verity.keyring_unsealed=1",
            -ENOKEY,
        );
    }
    let ret = keyring::holds_exactly(ring, &certs);
    if ret != 1 {
        return boot_keys_error(
            "check dm-verity verification keys",
            if ret < 0 { ret } else { -EKEYREJECTED },
        );
    }
    0
}

/// Whether the shirudo commands hold the image state: the runtime
/// image's root, once the bootstrap is loaded.
pub(crate) fn runtime_root() -> Option<[u8; 32]> {
    with_state(|s| s.loaded.then_some(s.bootstrap.runtime_root))
}

/// The config activation journal of this command, which attestation
/// reports on; null without one.
pub(crate) fn update_context() -> *mut ConfigUpdate {
    if journal_open() {
        JOURNAL.with(RefCell::as_ptr)
    } else {
        ptr::null_mut()
    }
}

fn reject_overrides() -> c_int {
    const NAMES: [&str; 9] = [
        "SHIRUDO_KEYS_DIR",
        "SHIRUDO_TPM_TCTI",
        "SHIRUDO_TPM_OWNER_AUTH",
        "SHIRUDO_EVENTLOG_PATH",
        "SHIRUDO_EVENTLOG_PENDING_PATH",
        "SHIRUDO_INITRD_RELEASE",
        "SHIRUDO_SYSROOT",
        "TSS2_LOGFILE",
        "SSLKEYLOGFILE",
    ];
    match NAMES.iter().find(|n| std::env::var_os(n).is_some()) {
        Some(name) => {
            error(format!("bootstrap override {name} is forbidden"));
            -EPERM
        }
        None => 0,
    }
}

/// Loads the authenticated bootstrap: on an enforcing boot from the
/// runtime image the identity names, before it from the initrd's own
/// config. 1 once loaded, or -errno.
pub(crate) fn bootstrap_load() -> c_int {
    if with_state(|s| s.loaded) {
        return 1;
    }
    let mode = identity::enforcement_active();
    if mode < 0 {
        return mode;
    }
    let mut identity = Identity::zeroed();
    let id = identity::read(&mut identity);
    if mode != 0 && id != 0 {
        return id;
    }
    if id == 0 && mode == 0 {
        return -EPROTO;
    }
    with_state(|s| {
        let ret = if id == 0 {
            s.bootstrap.runtime_root = identity.runtime_root;
            s.bootstrap.have_root = true;
            load_runtime_config(s, false)
        } else {
            let mut ret = image_bootstrap::read(CONF_PATH, &mut s.bootstrap, true);
            if ret == 0 && (s.bootstrap.runtime[0] == 0 || !s.bootstrap.have_root) {
                ret = -EINVAL;
            }
            if ret == 0 {
                ret = config::load_path(&mut s.bootstrap_config, CONF_PATH);
            }
            ret
        };
        if ret != 0 {
            return ret;
        }
        let ret = reject_overrides();
        if ret != 0 {
            return ret;
        }
        let ret = image_config::set(&s.bootstrap_config, -1);
        if ret != 0 {
            return ret;
        }
        s.loaded = true;
        1
    })
}

/// Mounts the authenticated runtime image, or takes the one mounted.
pub(crate) fn runtime_mount() -> c_int {
    with_state(|s| mount_runtime(s, false))
}

/// The initrd's boot trust set: the runtime mounted, its config
/// certificate sealed into the dm-verity keyring, the boot config
/// prepared and its key set validated, with the runtime's signer added
/// for the guard loaders until activation. The mounts stay until
/// [`boot_keys_close`].
pub(crate) fn boot_keys(set: &mut TrustedSet) -> c_int {
    with_state(|s| s.boot_keys_open = true);
    let ret = with_state(|s| mount_runtime(s, true));
    if ret != 0 {
        return boot_keys_error("mount runtime", ret);
    }
    let ret = with_state(|s| enroll_config_keys(s));
    if ret != 0 {
        return boot_keys_error("enrol config certificate", ret);
    }
    let ret = open_update();
    if ret != 0 {
        return boot_keys_error("open config update state", ret);
    }
    let mut target = zero_target();
    let ret = boot_target(&mut target);
    if ret != 0 {
        return boot_keys_error("select boot config", ret);
    }
    let ret = with_state(|s| {
        s.boot_target = target;
        prepare_config(s, &target, Prepare::Boot)
    });
    if ret != 0 {
        return boot_keys_error("prepare boot config", ret);
    }
    let ret = image_keys::validate_set(RUNTIME_CERT_PATH, with_state(|s| s.candidate_raw()), set);
    if ret != 0 {
        return boot_keys_error("validate BPF trust set", ret);
    }
    let primary = match TrustedCert::primary_at(RUNTIME_CERT_PATH) {
        Ok(c) => c,
        Err(err) => return boot_keys_error("digest primary certificate", err),
    };
    if !members(set).iter().any(|c| c.sha256() == primary.sha256()) {
        if set.len() == KEYS_MAX {
            return boot_keys_error("add runtime certificate to trusted set", -E2BIG);
        }
        set.push(primary);
    }
    with_state(|s| s.boot_target_valid = true);
    0
}

/// Releases what [`boot_keys`] mounted and mapped: 0 or the first error.
pub(crate) fn boot_keys_close() -> c_int {
    with_state(|s| {
        if !s.boot_keys_open {
            return 0;
        }
        image_config::clear();
        s.candidate_fd = None;
        s.certificates.clear();
        let mut ret = 0;
        // SAFETY: a C string.
        if unsafe { umount2(CONFIG_CANDIDATE_DIR.as_ptr(), 0) } != 0 {
            let err = last_errno();
            if err != -EINVAL && err != -ENOENT {
                ret = err;
            }
        }
        for (device, image) in [
            (&mut s.candidate_device, Some(&mut s.candidate)),
            (&mut s.boot_runtime, None),
        ] {
            if image.is_none() {
                // SAFETY: a C string.
                if unsafe { umount2(RUNTIME_DIR.as_ptr(), 0) } != 0 {
                    let err = last_errno();
                    if err != -EINVAL && err != -ENOENT && ret == 0 {
                        ret = err;
                    }
                }
            }
            if device.name[0] != 0 {
                let err = dm_verity::remove(device, false);
                if ret == 0 && err != 0 && err != -ENXIO && err != -ENODEV {
                    ret = err;
                }
            }
            if let Some(image) = image {
                image.close();
            }
        }
        s.boot_keys_open = false;
        ret
    })
}

/// Activates the boot config through the journal: -EINPROGRESS while
/// an activation is pending, which blocks further changes.
pub(crate) fn boot() -> c_int {
    let ret = open_update();
    if ret != 0 {
        return ret;
    }
    let (valid, saved, pcr) = with_state(|s| (s.boot_target_valid, s.boot_target, s.bootstrap.pcr));
    let target = if valid {
        saved
    } else {
        let mut target = zero_target();
        let ret = boot_target(&mut target);
        if ret != 0 {
            return ret;
        }
        target
    };
    let ret = with_journal(|j| {
        j.set_ops(&BOOT_OPS);
        // SAFETY: the open journal and the boot target.
        let ret = unsafe { config_update_boot(j, &target, pcr) };
        j.set_ops(&UPDATE_OPS);
        ret
    });
    if ret == -EINPROGRESS {
        error("image: activation is pending; further changes are blocked".into());
    }
    ret
}

/// Whether the config the journal selected is the one mounted, through
/// a mapping the guards watched being made, and so the config the image
/// config reads: 0, -EUCLEAN or -errno.
fn config_mount_check(s: &State, record: &ConfigUpdateRecord) -> c_int {
    let mut opened = ConfigImageOpen::closed();
    let mut ret = config_image::place(
        ConfigImageOpen::open(
            CStr::from_bytes_until_nul(&record.target.prefix).unwrap_or_default(),
            None,
        ),
        &mut opened,
    );
    if ret != 0 {
        return ret;
    }
    if record.target.root_hash != opened.image.root_hash {
        ret = -EKEYREJECTED;
    }
    let mut device = DmVerity::empty();
    if ret == 0 {
        let name = mapping_name(&record.target.root_hash);
        ret = dm_verity::place(dm_verity::inspect(&name, &opened.image), &mut device);
    }
    opened.close();
    if ret != 0 {
        return ret;
    }
    let ret = (|| {
        match fs::metadata(path(CONFIG_IMAGE_DIR)) {
            Ok(m) if m.dev() == device.device => {}
            _ => return -EUCLEAN,
        }
        let ret = device_observed(device.device, Some(&record.target.root_hash), DEVICE_CONFIG);
        if ret != 0 {
            return ret;
        }
        let dir = match config_root_open(CONFIG_IMAGE_DIR, device.device, -EUCLEAN) {
            Ok(fd) => fd,
            Err(err) => return err,
        };
        let ret = mount_flags(dir.as_raw_fd(), false);
        if ret != 0 {
            return ret;
        }
        image_config::set(&s.bootstrap_config, dir.as_raw_fd())
    })();
    dm_verity::close_loops(&mut device);
    ret
}

/// Completes the boot's activation once the config it selected is the
/// one mounted.
pub(crate) fn boot_complete() -> c_int {
    let mut record = zero_record();
    // SAFETY: the open journal and room for its record.
    let mut ret = with_journal(|j| unsafe { config_update_read(j, &mut record) });
    if ret == 0 {
        ret = with_state(|s| config_mount_check(s, &record));
    }
    if ret == 0 {
        // SAFETY: the open journal.
        ret = with_journal(|j| unsafe { config_update_complete_boot(j) });
    }
    ret
}

/// Whether the journal's selection is complete and the config mounted.
fn current_config() -> c_int {
    let mut record = zero_record();
    let mut ret = open_update();
    if ret == 0 {
        // SAFETY: the open journal and room for its record.
        ret = with_journal(|j| unsafe { config_update_check(j, &mut record) });
    }
    if ret != 0 {
        ret
    } else {
        with_state(|s| config_mount_check(s, &record))
    }
}

/// status is how a fleet sees these states, so it runs in them while
/// every other command refuses: with the pending config's settings when
/// that is the config mounted, and with the runtime image's alone
/// otherwise, since a config the record cannot vouch for names no export
/// destination.
fn status_config(state: c_int) -> c_int {
    with_state(|s| s.config_state = state);
    if state == -EINPROGRESS {
        let mut record = zero_record();
        // SAFETY: the open journal and room for its record.
        if with_journal(|j| unsafe { config_update_read(j, &mut record) }) == 0 {
            with_state(|s| config_mount_check(s, &record));
        }
    }
    0
}

/// Enters the image state `command` needs before it runs with `args`,
/// the command word first: nothing outside an enforcing boot or for the
/// commands that need none; else the runtime's settings, the journal,
/// and for all but `image` the config the journal selected. Options
/// that would point a command away from the runtime's keys, TPM or
/// certificates are refused there.
pub(crate) fn enter(command: &[u8], args: &[&[u8]]) -> c_int {
    let image_exempt = matches!(
        args.get(1),
        Some(&(b"build" | b"verify" | b"--help" | b"-h" | b"--list-cmds"))
    );
    if command == b"image" && image_exempt {
        return 0;
    }
    if matches!(
        command,
        b"init" | b"genkey" | b"build" | b"help" | b"version"
    ) {
        return 0;
    }
    let mode = identity::enforcement_active();
    if mode < 0 {
        return mode;
    }
    let mut identity = Identity::zeroed();
    let ret = identity::read(&mut identity);
    if mode != 0 && ret != 0 {
        return ret;
    }
    if ret != 0 {
        return if ret == -ENOENT || ret == -EPERM || ret == -EACCES {
            0
        } else {
            ret
        };
    }
    if mode == 0 {
        return -EPROTO;
    }
    let ret = bootstrap_load();
    if ret < 0 {
        return ret;
    }
    let ret = with_state(|s| load_runtime_config(s, false));
    if ret != 0 {
        return ret;
    }
    let redirects = |a: &&[u8]| {
        a.starts_with(b"--keys-dir") || a.starts_with(b"--cert") || a.starts_with(b"--tcti")
    };
    if args.iter().skip(1).any(redirects) {
        return -EPERM;
    }
    if command == b"image" {
        return open_update();
    }
    let ret = current_config();
    if command == b"status" && [-EINPROGRESS, -EUCLEAN, -ESTALE, -EKEYREJECTED].contains(&ret) {
        return status_config(ret);
    }
    ret
}

/// The config state status reports: 0 with the selected config active,
/// -EINPROGRESS while an activation is pending, or the integrity error
/// the other commands refuse on; -ENODEV without activation state.
/// `root` is the selected or pending config's, zero when unknown.
pub(crate) fn config_state(root: &mut [u8; 32]) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut record = zero_record();
    // SAFETY: the open journal and room for its record.
    *root = if with_journal(|j| unsafe { config_update_read(j, &mut record) }) == 0 {
        record.target.root_hash
    } else {
        [0; 32]
    };
    with_state(|s| s.config_state)
}

/// Prints the activation state, as JSON with `json`: 0, -EINPROGRESS
/// while an activation is pending, -ENODEV without activation state, or
/// the error the config fails its check with.
pub(crate) fn status(json: bool) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut record = zero_record();
    let mut staged = zero_record();
    // SAFETY: the open journal and room for its record.
    let ret = with_journal(|j| unsafe { config_update_read(j, &mut record) });
    if ret != 0 {
        return ret;
    }
    // SAFETY: as above, for the record staged for the next boot.
    let ret = with_journal(|j| unsafe { config_update_stage_read(j, &mut staged) });
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    let hex = |root: &[u8; 32]| -> String { root.iter().map(|b| format!("{b:02x}")).collect() };
    let next_root = (ret == 0).then(|| hex(&staged.target.root_hash));
    let root = hex(&record.target.root_hash);
    let ret = if record.pending {
        -EINPROGRESS
    } else {
        current_config()
    };
    if !json {
        let pending = if record.pending {
            "yes, until the next reboot"
        } else {
            "no"
        };
        let consistent = if ret != 0 { "no" } else { "yes" };
        let lines = [
            ("Config root hash:", root),
            (
                "Next boot root hash:",
                next_root.unwrap_or_else(|| "none".to_owned()),
            ),
            ("PCR:", record.pcr.to_string()),
            ("Sequence:", (record.sequence as i64).to_string()),
            ("TPM reset count:", record.reset_count.to_string()),
            ("Restart count:", record.restart_count.to_string()),
            ("Pending:", pending.to_owned()),
            ("Consistent:", consistent.to_owned()),
        ];
        for (label, value) in lines {
            print(format!("{label:<22} {value}\n").as_bytes());
        }
        return ret;
    }
    let mut buf = [0u8; 768];
    let mut e = JsonEmit::fixed(&mut buf);
    e.obj_open();
    e.kv_string(b"root_hash", root.as_bytes());
    match &next_root {
        Some(next) => e.kv_string(b"next_boot_root_hash", next.as_bytes()),
        None => e.kv_null(b"next_boot_root_hash"),
    }
    e.kv_int(b"pcr", i64::from(record.pcr));
    e.kv_int(b"sequence", record.sequence as i64);
    e.kv_int(b"reset_count", i64::from(record.reset_count));
    e.kv_int(b"restart_count", i64::from(record.restart_count));
    e.kv_bool(b"pending", record.pending);
    e.kv_bool(b"consistent", ret == 0);
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    print(&[e.output(), b"\n"].concat());
    ret
}

/// Leaves what [`enter`] or the initrd entered: mounts, mappings the
/// guards never watched being made, the journal and the TPM, the
/// bootstrap's secrets wiped.
pub(crate) fn leave() {
    boot_keys_close();
    image_config::clear();
    let open = journal_open();
    with_state(|s| close_candidate(s, open));
    collect_mappings(open);
    if open {
        // SAFETY: the open journal, closed once.
        with_journal(|j| unsafe { config_update_close(j) });
    }
    with_state(|s| {
        // SAFETY: the TPM open_update() opened, or null.
        unsafe { tpm_close(s.tpm) };
        s.tpm = ptr::null_mut();
        s.certificates.clear();
        // SAFETY: the bootstrap config's bytes, wiped.
        unsafe { explicit_bzero((&raw mut s.bootstrap_config).cast(), size_of::<Config>()) };
    });
}

/// Fetches the config image at `prefix` into the cache and begins its
/// activation through the journal: 0, -EINPROGRESS while one is pending,
/// -ENODEV without activation state, or -errno.
pub(crate) fn update(prefix: &CStr) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut target = zero_target();
    let mut ret = current_config();
    if ret == 0 {
        ret = mkdir_owned(IMAGE_CACHE_DIR);
    }
    if ret == 0 {
        ret = fetch_verified(prefix, &mut target, |image| {
            with_state(|s| verify_config_root(s, image))
        });
    }
    if ret == 0 {
        let pcr = with_state(|s| s.bootstrap.pcr);
        // SAFETY: the open journal and the fetched target.
        ret = with_journal(|j| unsafe { config_update_begin(j, &target, pcr) });
    }
    ret
}

/// Fetches the config image at `prefix` into the cache, prepares it as
/// a live update would, and stages it for the next boot: 0, -ENODEV
/// without activation state, or -errno.
pub(crate) fn stage(prefix: &CStr) -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let mut target = zero_target();
    let mut ret = current_config();
    if ret == 0 {
        ret = mkdir_owned(IMAGE_CACHE_DIR);
    }
    if ret == 0 {
        ret = fetch_verified(prefix, &mut target, |image| {
            with_state(|s| verify_config_root(s, image))
        });
    }
    if ret == 0 {
        ret = with_state(|s| prepare_config(s, &target, Prepare::Stage));
    }
    if ret == 0 {
        // SAFETY: the open journal and the prepared target.
        ret = with_journal(|j| unsafe { config_update_stage(j, &target) });
    }
    ret
}

/// Drops the config staged for the next boot: 0, -ENODEV without
/// activation state, or -errno.
pub(crate) fn stage_cancel() -> c_int {
    if !journal_open() {
        return -ENODEV;
    }
    let ret = current_config();
    if ret != 0 {
        return ret;
    }
    // SAFETY: the open journal.
    with_journal(|j| unsafe { config_update_clear_staged(j) })
}
