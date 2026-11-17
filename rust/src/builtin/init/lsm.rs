// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Brings the enforcement up: loads `bpf2`, freezes the anchor it
//! enforces into the identity map, and attaches its guards and the
//! seal's in order, the bpf() gates last. Each link is pinned, so it
//! outlives init; a run that fails unpins every link it pinned and
//! removes the maps it pinned, leaving nothing half attached.
//!
//! bpf2 and the seal are light skeletons built into the binary: their
//! loaders, generated when shirudo was built, make their maps and
//! programs; the seal's takes the maps it shares with bpf2 from bpf2.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::os::fd::{AsRawFd, OwnedFd};

use super::{NV_INDEX, SIG_KEYRING_BPF, cat, error, info, last_err, strerr};
use crate::bpf::lskel::{Lskel, Program};
use crate::errno::{E2BIG, EACCES, EINVAL, EKEYREJECTED, ENOENT, ENOKEY};
use crate::ffi;
use crate::sys::identity::Identity;
use crate::sys::libc::{
    O_CLOEXEC, O_DIRECTORY, O_RDONLY, SYS_PIDFD_OPEN, access, close, open, syscall, unlink,
};
use crate::sys::loader::{EmbeddedBpf, bpf2_blob, seal_blob};
use crate::util::bpf_sys::{
    Attr, BPF_ANY, BPF_OBJ_PIN, bpf_map_freeze, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_obj_pin, link_create,
};
use crate::util::identity;
use crate::util::image_guards::{
    GATE_GUARDS, GATE_HOOK_COUNT, GUARD_BPF, GUARD_BPF_MAP, GUARD_KEY_PERMISSION, GUARD_MAP_COUNT,
    GUARD_MAPS, GUARD_PROG_LOAD, GUARD_REMOVEXATTR, GUARD_ROOTS, GUARD_SETXATTR, GUARD_TASKS,
    GUARD_TPM_COMMAND, GUARD_UNLINK, IMAGE_OBSERVER_GUARDS, IMAGE_SEAL_GUARDS, ImageGuard,
    MOUNT_GUARDS, OBSERVER_GUARDS, SEAL_GUARDS,
};
use crate::util::image_runtime;
use crate::util::io::kernel_dev;
use crate::util::keyring::{self, keyring_bpf_serial, keyring_dm_verity_serial};
use crate::util::lskel::{self as runner, Ctx};
use crate::util::nv_writer::nv_writer_create;
use crate::util::tpm::{Tpm, tpm_close, tpm_ek_name, tpm_open};

const BPFFS_DIR: &CStr = c"/run/shirudo/bpffs";
const RUN_DIR: &CStr = c"/run/shirudo";
const IDENTITY_PIN: &CStr = c"/run/shirudo/bpffs/identity";
const TAMPER_PIN: &CStr = c"/run/shirudo/bpffs/tamper";
const TPM_COMMAND_LINK_PIN: &CStr = c"/run/shirudo/bpffs/bpf2_tpm_command_link";
/// What a failed run removes besides its links: every map it pinned.
const MAP_PINS: [&CStr; 7] = [
    IDENTITY_PIN,
    TAMPER_PIN,
    c"/run/shirudo/bpffs/task_authority",
    c"/run/shirudo/bpffs/task_policy",
    c"/run/shirudo/bpffs/socket_policy",
    c"/run/shirudo/bpffs/devices",
    c"/run/shirudo/bpffs/config_roots",
];
/// `IDENTITY_KEYS_MAX`: the keys the identity map records.
const IDENTITY_KEYS_MAX: usize = 16;
/// `TASK_BOOTSTRAP`: the authority of the task bringing enforcement up.
const TASK_BOOTSTRAP: u8 = 2;
/// BPF_PROG_TYPE_LSM and BPF_LSM_MAC: every program of bpf2 and the seal.
const PROG_TYPE_LSM: u32 = 29;
const LSM_MAC: u32 = 27;

/// `struct task_authority` of `bpf/lib/lsm.h`.
#[repr(C)]
struct TaskAuthority {
    trusted: u8,
    candidate_valid: u8,
    candidate_trusted: u8,
    pad: u8,
    pad2: u32,
}

fn exists(path: *const c_char) -> bool {
    // SAFETY: a C string.
    unsafe { access(path, 0) == 0 }
}

fn text(p: *const c_char) -> &'static [u8] {
    // SAFETY: a static C string of the guard tables or the blob.
    unsafe { ffi::c_str(p) }
}

fn gate(guard: usize) -> &'static ImageGuard {
    &GATE_GUARDS[guard]
}

/// The name of an embedded skeleton.
fn blob_name(blob: *const EmbeddedBpf) -> &'static [u8] {
    // SAFETY: the blob, static, its name a static C string.
    text(unsafe { (*blob).name })
}

/// The embedded skeleton, whole.
fn skeleton(blob: *const EmbeddedBpf) -> Result<Lskel<'static>, c_int> {
    // SAFETY: NULL or the static blob.
    let Some(b) = (unsafe { blob.as_ref() }).filter(|b| !b.data.is_null() && b.size != 0) else {
        return Err(-ENOENT);
    };
    // SAFETY: the blob's `size` static bytes.
    let data = unsafe { ffi::slice(b.data.cast::<u8>(), b.size) };
    Lskel::parse(data).ok_or(-EINVAL)
}

/// An embedded object, loaded: its skeleton, and the context holding
/// the descriptors of the maps and programs its loader made.
struct Loaded {
    skel: Lskel<'static>,
    cx: Ctx,
}

impl Loaded {
    /// Runs the loader of `skel`, the maps it reuses taken from `shared`.
    fn load(
        name: &[u8],
        skel: Lskel<'static>,
        shared: impl Fn(usize) -> Option<c_int>,
    ) -> Result<Self, c_int> {
        match runner::run(&skel, shared) {
            Ok(cx) => Ok(Loaded { skel, cx }),
            Err((step, err)) => {
                error(&cat!(name, ": ", step, ": ", strerr(-err)));
                Err(err)
            }
        }
    }

    fn map(&self, name: *const c_char) -> Option<c_int> {
        self.map_named(text(name))
    }

    fn map_named(&self, name: &[u8]) -> Option<c_int> {
        let i = self.skel.map(name)?;
        Some(self.cx.map_fd(i as u32))
    }

    fn program(&self, name: *const c_char) -> Option<(c_int, Program<'static>)> {
        let (i, p) = self.skel.prog(text(name))?;
        Some((self.cx.prog_fd(i as u32), *p))
    }
}

/// A pinned link: dropped, its descriptor lets go of the link, which
/// its pin keeps.
struct Link {
    _fd: OwnedFd,
    pin: *const c_char,
}

impl Link {
    /// Removes the pin, so that the link goes with its descriptor.
    fn unpin(&self) {
        // SAFETY: a C string.
        unsafe { unlink(self.pin) };
    }
}

/// Attaches the LSM program `prog` and pins its link at `pin`.
fn attach_pin(prog: (c_int, Program<'_>), pin: *const c_char) -> Result<Link, c_int> {
    let (fd, p) = prog;
    if p.prog_type != PROG_TYPE_LSM || p.attach_type != LSM_MAC {
        return Err(-EINVAL);
    }
    let link = link_create(fd, 0, LSM_MAC, |a| a).map_err(|e| -e)?;
    Attr::new()
        .ptr(0, pin)
        .u32(8, link.as_raw_fd() as u32)
        .run(BPF_OBJ_PIN)
        .map_err(|e| -e)?;
    Ok(Link { _fd: link, pin })
}

/// Attaches the `guards` of `obj` in order, their links into `links`.
fn attach_group(obj: &Loaded, guards: &[ImageGuard], links: &mut Vec<Link>) -> c_int {
    for g in guards {
        let Some(p) = obj.program(g.prog) else {
            error(&cat!("program ", text(g.prog), " missing"));
            return -ENOENT;
        };
        match attach_pin(p, g.pin) {
            Ok(l) => links.push(l),
            Err(ret) => {
                error(&cat!("attach ", text(g.prog), ": ", strerr(-ret)));
                return ret;
            }
        }
    }
    0
}

/// The descriptors of bpf2's maps the seal's loader takes, the policy
/// maps the two share: the seal must reuse exactly those.
fn shared_policy_maps(bpf2: &Loaded, seal: &Lskel<'_>) -> Result<Vec<(usize, c_int)>, c_int> {
    let mut shared = Vec::new();
    for m in &GUARD_MAPS {
        let name = text(m.name);
        let (Some(i), Some(fd)) = (seal.map(name), bpf2.map_named(name)) else {
            return Err(-ENOENT);
        };
        if !seal.reuses(i) {
            return Err(-EINVAL);
        }
        shared.push((i, fd));
    }
    let reused = (0..seal.maps.len()).filter(|&i| seal.reuses(i)).count();
    if reused != shared.len() {
        return Err(-EINVAL);
    }
    Ok(shared)
}

/// The asymmetric keys of `ring`, at most IDENTITY_KEYS_MAX, and
/// whether it held more.
fn asymmetric_keys(ring: i32) -> Result<(Vec<i32>, bool), c_int> {
    let (mut keys, mut overflow) = (Vec::new(), false);
    let ret = keyring::list(ring, |serial, ty, _| {
        if ty.to_bytes() != b"asymmetric" {
            return;
        }
        if keys.len() >= IDENTITY_KEYS_MAX {
            overflow = true;
        } else {
            keys.push(serial);
        }
    });

    if ret != 0 {
        Err(ret)
    } else {
        Ok((keys, overflow))
    }
}

/// Boot keys left the sealed keyring holding the config certificate
/// alone.
fn dm_verity_anchor(id: &mut Identity) -> c_int {
    let ring = keyring_dm_verity_serial();

    if ring <= 0 {
        let err = if ring != 0 { ring } else { -ENOKEY };
        error(&cat!(
            "resolve the dm-verity keyring serial: ",
            strerr(-err)
        ));
        return err;
    }
    let keys = match asymmetric_keys(ring) {
        Ok((keys, _)) => keys,
        Err(err) => {
            error(&cat!(
                "list the dm-verity keyring ",
                ring,
                ": ",
                strerr(-err)
            ));
            return err;
        }
    };
    if keys.len() != 1 {
        error(&cat!(
            "dm-verity keyring ",
            ring,
            " holds ",
            keys.len(),
            " keys, not the config certificate alone"
        ));
        return -EKEYREJECTED;
    }
    id.dm_verity_ring = ring;
    id.dm_verity_key = keys[0];
    0
}

/// Initial TPM contact is trusted in the authenticated initrd. Later
/// connections salt their sessions with the key whose name is frozen
/// here.
fn record_ek_name(id: &mut Identity) -> c_int {
    let mut tpm: *mut Tpm = ptr::null_mut();

    // SAFETY: room for the TPM.
    let ret = unsafe { tpm_open(&mut tpm) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the TPM opened above and room for the name; then closed.
    unsafe {
        tpm_ek_name(tpm, id.ek_name.as_mut_ptr());
        tpm_close(tpm);
    }
    0
}

/// Seeds the bootstrap task's authority, freezes the shared state but
/// the expected config roots, which change with each mapping, and pins
/// it.
fn freeze_task_maps(obj: &Loaded) -> c_int {
    let maps = &GUARD_MAPS;
    let authority = TaskAuthority {
        trusted: TASK_BOOTSTRAP,
        candidate_valid: 0,
        candidate_trusted: 0,
        pad: 0,
        pad2: 0,
    };
    // SAFETY: pidfd_open() of this process.
    let pidfd =
        unsafe { syscall(SYS_PIDFD_OPEN, std::process::id() as c_int, 0 as c_int) } as c_int;
    if pidfd < 0 {
        return last_err();
    }
    let mut ret = 0;
    for (i, m) in maps
        .iter()
        .enumerate()
        .take(GUARD_MAP_COUNT)
        .skip(GUARD_TASKS)
    {
        let Some(fd) = obj.map(m.name) else {
            ret = -ENOENT;
            break;
        };
        if i == GUARD_TASKS {
            let (key, value) = ((&raw const pidfd).cast(), (&raw const authority).cast());
            // SAFETY: the map's fd, the pidfd key and the authority value.
            if unsafe { bpf_map_update_elem(fd, key, value, BPF_ANY) } != 0 {
                ret = last_err();
                break;
            }
        }
        // Expected roots change for each mapping.
        let frozen = i == GUARD_ROOTS || bpf_map_freeze(fd) == 0;
        // SAFETY: the map's fd and a C string.
        if !frozen || unsafe { bpf_obj_pin(fd, m.pin) } != 0 {
            ret = last_err();
            break;
        }
    }
    // SAFETY: the pidfd opened above.
    unsafe { close(pidfd) };
    ret
}

/// The recorder in the mount guards sees the bootstrap task open the
/// bpffs root; the record is read back, since a guard with none to keep
/// would let an unmount above the bpffs through.
fn record_bpffs_mount(obj: &Loaded) -> c_int {
    let (zero, mut mount) = (0u32, 0u64);
    // SAFETY: a C string.
    let fd = unsafe { open(BPFFS_DIR.as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };

    if fd < 0 {
        return last_err();
    }
    // SAFETY: the descriptor opened above.
    unsafe { close(fd) };
    let Some(m) = obj.map(c"shirudo_mnt_rec".as_ptr()) else {
        return -ENOENT;
    };
    // SAFETY: the map's fd, its key and room for its value.
    if unsafe { bpf_map_lookup_elem(m, (&raw const zero).cast(), (&raw mut mount).cast()) } != 0 {
        return last_err();
    }
    if mount == 0 {
        return -ENOENT;
    }
    if bpf_map_freeze(m) != 0 {
        last_err()
    } else {
        0
    }
}

/// The objects and links of one run, in the order a failed run undoes
/// them.
struct Attached {
    seal_obj: Option<Loaded>,
    image_seal: Vec<Link>,
    image_observer: Vec<Link>,
    observer: Vec<Link>,
    seal: Vec<Link>,
    mount: Vec<Link>,
    gates: [Option<Link>; GATE_HOOK_COUNT],
}

/// The gates in the order a run that ends lets go of them.
const GATE_RELEASE: [usize; GATE_HOOK_COUNT] = [
    GUARD_BPF,
    GUARD_BPF_MAP,
    GUARD_PROG_LOAD,
    GUARD_KEY_PERMISSION,
    GUARD_TPM_COMMAND,
    GUARD_REMOVEXATTR,
    GUARD_SETXATTR,
    GUARD_UNLINK,
];

impl Attached {
    fn gate(&mut self, guard: usize, p: Option<(c_int, Program<'_>)>, hook: &str) -> c_int {
        match p
            .ok_or(-ENOENT)
            .and_then(|p| attach_pin(p, gate(guard).pin))
        {
            Ok(l) => {
                self.gates[guard] = Some(l);
                0
            }
            Err(ret) => {
                error(&cat!("attach lsm/", hook, ": ", strerr(-ret)));
                ret
            }
        }
    }

    /// Writable state and runtime processes always get the full seal.
    fn attach_seal(&mut self, bpf2: &Loaded) -> c_int {
        // SAFETY: the embedded seal skeleton, static.
        let blob = unsafe { seal_blob() };
        let skel = match skeleton(blob) {
            Ok(s) => s,
            Err(err) => {
                error(&cat!("embedded seal skeleton: ", strerr(-err)));
                return err;
            }
        };
        let shared = match shared_policy_maps(bpf2, &skel) {
            Ok(s) => s,
            Err(err) => {
                error(&cat!("seal: shared policy maps: ", strerr(-err)));
                return err;
            }
        };
        let fd = |i| shared.iter().find(|&&(j, _)| j == i).map(|&(_, fd)| fd);
        let obj = match Loaded::load(b"seal", skel, fd) {
            Ok(obj) => obj,
            Err(err) => return err,
        };
        let err = match obj.map(c"seal_scratch_map".as_ptr()) {
            None => -ENOENT,
            Some(scratch) if bpf_map_freeze(scratch) != 0 => last_err(),
            Some(_) => 0,
        };
        if err != 0 {
            error(&cat!("seal: freeze seal_scratch_map: ", strerr(-err)));
            return err;
        }
        let (seal, image_seal) = (&SEAL_GUARDS, &IMAGE_SEAL_GUARDS);
        let mut err = attach_group(&obj, seal, &mut self.seal);
        if err == 0 {
            err = attach_group(&obj, image_seal, &mut self.image_seal);
        }
        if err == 0 {
            self.seal_obj = Some(obj);
        }
        err
    }

    fn run(&mut self, obj: &Loaded, name: &[u8]) -> c_int {
        let mut id = Identity::zeroed();

        match std::fs::metadata(super::path(BPFFS_DIR.to_bytes())) {
            Ok(m) => id.sb_dev = kernel_dev(std::os::unix::fs::MetadataExt::dev(&m)),
            Err(e) => {
                let err = -e.raw_os_error().unwrap_or(crate::errno::EIO);
                error(&cat!("stat ", BPFFS_DIR, ": ", strerr(-err)));
                return err;
            }
        }
        match std::fs::metadata(super::path(RUN_DIR.to_bytes())) {
            Ok(m) => id.run_dev = kernel_dev(std::os::unix::fs::MetadataExt::dev(&m)),
            Err(e) => return -e.raw_os_error().unwrap_or(crate::errno::EIO),
        }
        let Some(root) = image_runtime::runtime_root() else {
            return -crate::errno::EINVAL;
        };
        id.runtime_root = root;

        // The trust anchor lsm/bpf_prog_load enforces: only a load the
        // kernel verified against exactly this sealed keyring, of exactly
        // this kind, is admitted from userspace. The keyring is enrolled
        // and sealed by now, so this resolves the serial the kernel
        // records for a load that names it as keyring_id.
        let keyring = keyring_bpf_serial();
        id.keyring_type = SIG_KEYRING_BPF;
        if keyring <= 0 {
            let err = if keyring != 0 { keyring } else { -ENOKEY };
            error(&cat!("resolve the bpf keyring serial: ", strerr(-err)));
            return err;
        }
        id.keyring_serial = keyring;

        // The keys that keyring holds, for lsm/key_permission: with the
        // keyring itself, what no task but shirudo may write, unlink,
        // revoke or invalidate for the rest of the boot.
        let (keys, overflow) = match asymmetric_keys(keyring) {
            Ok(k) => k,
            Err(err) => {
                error(&cat!(
                    "list the anchor keyring ",
                    keyring,
                    ": ",
                    strerr(-err)
                ));
                return err;
            }
        };
        if overflow || keys.is_empty() {
            let what = if overflow { "too many" } else { "no" };
            error(&cat!(
                "anchor keyring ",
                keyring,
                " holds ",
                what,
                " asymmetric keys"
            ));
            return if overflow { -E2BIG } else { -ENOKEY };
        }
        id.n_keys = keys.len() as u32;
        id.nv_index = NV_INDEX;
        id.key_serials[..keys.len()].copy_from_slice(&keys);
        let err = dm_verity_anchor(&mut id);
        if err != 0 {
            return err;
        }
        // SAFETY: room for the seed and the public modulus.
        let err = unsafe {
            nv_writer_create(
                id.nv_writer_seed.as_mut_ptr(),
                id.nv_writer_public.as_mut_ptr(),
            )
        };
        if err != 0 {
            error(&cat!("init: create TPM RSA-3072 NV writer: ", strerr(-err)));
            return err;
        }
        let err = record_ek_name(&mut id);
        if err != 0 {
            error(&cat!(
                "init: record the endorsement key name: ",
                strerr(-err),
                " (tpm_error)"
            ));
            return err;
        }

        let Some(fd) = obj.map(c"shirudo_bpffs_sb".as_ptr()) else {
            error(b"shirudo_bpffs_sb map not in embedded bpf2");
            return -ENOENT;
        };
        let zero = 0u32;
        // SAFETY: the map's fd, its key and the identity.
        if unsafe {
            bpf_map_update_elem(
                fd,
                (&raw const zero).cast(),
                (&raw const id).cast(),
                BPF_ANY,
            )
        } != 0
        {
            let err = last_err();
            error(&cat!("populate sb-identity map: ", strerr(-err)));
            return err;
        }
        if bpf_map_freeze(fd) != 0 {
            let err = last_err();
            error(&cat!("freeze sb-identity map: ", strerr(-err)));
            return err;
        }
        let err = freeze_task_maps(obj);
        if err != 0 {
            return err;
        }
        // Pinned so that every later command reads the anchor init froze
        // from the kernel rather than from a file: the serial a load
        // names and status reports is the one lsm/bpf_prog_load enforces.
        // SAFETY: the map's fd and a C string.
        if unsafe { bpf_obj_pin(fd, IDENTITY_PIN.as_ptr()) } != 0 {
            let err = last_err();
            error(&cat!(
                "pin identity map at ",
                IDENTITY_PIN,
                ": ",
                strerr(-err)
            ));
            return err;
        }

        // The executable-identity guard precedes every BPF admission gate.
        let (observer, image_observer, mount) =
            (&OBSERVER_GUARDS, &IMAGE_OBSERVER_GUARDS, &MOUNT_GUARDS);
        let mut err = attach_group(obj, observer, &mut self.observer);
        if err == 0 {
            err = attach_group(obj, image_observer, &mut self.image_observer);
        }
        if err != 0 {
            return err;
        }
        let mut progs = Vec::new();
        for g in [
            GUARD_UNLINK,
            GUARD_SETXATTR,
            GUARD_REMOVEXATTR,
            GUARD_PROG_LOAD,
            GUARD_BPF_MAP,
            GUARD_KEY_PERMISSION,
            GUARD_TPM_COMMAND,
            GUARD_BPF,
        ] {
            let Some(p) = obj.program(gate(g).prog) else {
                error(b"expected programs missing in bpf2 object");
                return -ENOENT;
            };
            progs.push((g, p));
        }
        let prog = |guard: usize| progs.iter().find(|(g, _)| *g == guard).map(|&(_, p)| p);

        // The prctl identity guard is already active. The remaining hooks
        // go on as the bpffs guards, the seal's filesystem and
        // exec-identity hooks, then the bpf() gates (map fd access,
        // bpf_prog_load admission, then lsm/bpf) LAST. Pinning a link
        // creates a bpffs inode, gated by neither guard set; the seal's
        // unsigned load and the identity-map freeze precede the gates.
        for (guard, hook) in [
            (GUARD_UNLINK, "inode_unlink"),
            (GUARD_SETXATTR, "inode_setxattr"),
            (GUARD_REMOVEXATTR, "inode_removexattr"),
            (GUARD_KEY_PERMISSION, "key_permission"),
            (GUARD_TPM_COMMAND, "tpm_command"),
        ] {
            let err = self.gate(guard, prog(guard), hook);
            if err != 0 {
                return err;
            }
        }
        // With the other bpffs guards, so the mount is immutable before
        // enforcement goes live.
        let err = attach_group(obj, mount, &mut self.mount);
        if err != 0 {
            return err;
        }
        let err = record_bpffs_mount(obj);
        if err != 0 {
            error(&cat!("record the bpffs mount: ", strerr(-err)));
            return err;
        }
        let err = self.attach_seal(obj);
        if err != 0 {
            return err;
        }
        for (guard, hook) in [
            (GUARD_BPF_MAP, "bpf_map"),
            (GUARD_PROG_LOAD, "bpf_prog_load"),
            (GUARD_BPF, "bpf"),
        ] {
            let err = self.gate(guard, prog(guard), hook);
            if err != 0 {
                return err;
            }
        }
        info(&cat!(
            name,
            " and seal attached: lsm/bpf gate live, writable state sealed"
        ));
        0
    }

    /// Lets go of the seal and the links; after a failed run (`err`)
    /// unpins each link and removes the maps it pinned first.
    fn release(self, err: c_int) {
        let Attached {
            seal_obj,
            image_seal,
            image_observer,
            observer,
            seal,
            mount,
            mut gates,
        } = self;
        for group in [image_seal, image_observer, observer, seal, mount] {
            for l in group {
                if err != 0 {
                    l.unpin();
                }
            }
        }
        if err != 0 {
            for l in GATE_RELEASE.iter().filter_map(|&g| gates[g].as_ref()) {
                l.unpin();
            }
            for pin in MAP_PINS {
                // SAFETY: a C string.
                unsafe { unlink(pin.as_ptr()) };
            }
        }
        drop(seal_obj);
        for g in GATE_RELEASE {
            drop(gates[g].take());
        }
    }
}

/// Brings the enforcement up, or finds it up.
pub(super) fn attach() -> c_int {
    let bpf_gate = gate(GUARD_BPF).pin;

    if exists(bpf_gate) {
        let mut id = Identity::zeroed();
        let err = identity::read(&mut id);
        if err != 0
            || id.nv_writer_public[0] & 0x80 == 0
            || id.nv_index != NV_INDEX
            || !exists(TPM_COMMAND_LINK_PIN.as_ptr())
        {
            error(b"init: TPM NV index guard missing or changed; reboot with the updated initrd");
            return if err != 0 { err } else { -EACCES };
        }
        info(&cat!("bpf2 already attached (", text(bpf_gate), " exists)"));
        return 0;
    }
    // A pin without the links behind it is what a failed attempt leaves.
    for pin in [IDENTITY_PIN, TAMPER_PIN] {
        // SAFETY: a C string.
        if unsafe { unlink(pin.as_ptr()) } != 0 {
            let err = last_err();
            if err != -ENOENT {
                error(&cat!("unlink stale ", pin, ": ", strerr(-err)));
                return err;
            }
        }
    }
    // SAFETY: the embedded bpf2 skeleton, static.
    let blob = unsafe { bpf2_blob() };
    let skel = match skeleton(blob) {
        Ok(s) => s,
        Err(err) => {
            error(&cat!("embedded bpf2 skeleton: ", strerr(-err)));
            return err;
        }
    };
    let name = blob_name(blob);
    let obj = match Loaded::load(name, skel, |_| None) {
        Ok(obj) => obj,
        Err(err) => return err,
    };
    let mut a = Attached {
        seal_obj: None,
        image_seal: Vec::new(),
        image_observer: Vec::new(),
        observer: Vec::new(),
        seal: Vec::new(),
        mount: Vec::new(),
        gates: [const { None }; GATE_HOOK_COUNT],
    };
    let err = a.run(&obj, name);
    a.release(err);
    drop(obj);
    err
}

const _: () = assert!(size_of::<TaskAuthority>() == 8);
