// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Brings the enforcement up: loads `bpf2`, freezes the anchor it
//! enforces into the identity map, and attaches its guards and the
//! seal's in order, the bpf() gates last. Each link is pinned, so it
//! outlives init; a run that fails unpins every link it pinned and
//! removes the maps it pinned, leaving nothing half attached.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::{NV_INDEX, SIG_KEYRING_BPF, cat, error, info, last_err, strerr};
use crate::errno::{E2BIG, EACCES, EKEYREJECTED, ENOENT, ENOKEY};
use crate::ffi;
use crate::sys::bpf::{
    BPF_ANY, bpf_map_freeze, bpf_map_lookup_elem, bpf_map_update_elem, bpf_obj_pin,
};
use crate::sys::btf::libbpf_get_error;
use crate::sys::identity::Identity;
use crate::sys::image_guards::{
    GATE_HOOK_COUNT, GUARD_BPF, GUARD_BPF_MAP, GUARD_KEY_PERMISSION, GUARD_MAP_COUNT,
    GUARD_PROG_LOAD, GUARD_REMOVEXATTR, GUARD_ROOTS, GUARD_SETXATTR, GUARD_TASKS,
    GUARD_TPM_COMMAND, GUARD_UNLINK, ImageGuard, shirudo_gate_guards, shirudo_guard_maps,
    shirudo_image_observer_guards, shirudo_image_seal_guards, shirudo_mount_guards,
    shirudo_observer_guards, shirudo_seal_guards,
};
use crate::sys::libbpf::{
    BpfLink, BpfMap, BpfObject, BpfProgram, bpf_link__destroy, bpf_link__pin, bpf_link__unpin,
    bpf_map__fd, bpf_map__reuse_fd, bpf_object__close, bpf_object__find_map_by_name,
    bpf_object__find_program_by_name, bpf_object__load, bpf_object__open_mem, bpf_program__attach,
};
use crate::sys::libc::{
    O_CLOEXEC, O_DIRECTORY, O_RDONLY, SYS_PIDFD_OPEN, access, close, open, syscall, unlink,
};
use crate::sys::loader::{EmbeddedBpf, bpf2_blob, seal_blob};
use crate::util::identity;
use crate::util::image_runtime;
use crate::util::io::kernel_dev;
use crate::util::keyring::{self, keyring_bpf_serial, keyring_dm_verity_serial};
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
    // SAFETY: the gate table, constant data; guard is below its count.
    unsafe { &shirudo_gate_guards[guard] }
}

fn program(obj: *mut BpfObject, name: *const c_char) -> *mut BpfProgram {
    // SAFETY: the object and a C string.
    unsafe { bpf_object__find_program_by_name(obj, name) }
}

fn map(obj: *mut BpfObject, name: *const c_char) -> *mut BpfMap {
    // SAFETY: the object and a C string.
    unsafe { bpf_object__find_map_by_name(obj, name) }
}

fn map_fd(m: *mut BpfMap) -> c_int {
    // SAFETY: a map of a loaded object.
    unsafe { bpf_map__fd(m) }
}

/// The embedded object, opened.
fn open_blob(blob: *const EmbeddedBpf) -> Result<*mut BpfObject, c_int> {
    // SAFETY: the blob, static, checked by the caller.
    let obj = unsafe { bpf_object__open_mem((*blob).data, (*blob).size, ptr::null()) };
    // SAFETY: what libbpf returned.
    match unsafe { libbpf_get_error(obj.cast_const().cast()) } {
        0 => Ok(obj),
        err => Err(err as c_int),
    }
}

fn blob_ok(blob: *const EmbeddedBpf) -> bool {
    // SAFETY: NULL or the static blob.
    unsafe { blob.as_ref() }.is_some_and(|b| !b.data.is_null() && b.size != 0)
}

/// Attaches `p` and pins its link at `pin`, into `out`.
fn attach_pin(p: *mut BpfProgram, pin: *const c_char, out: &mut *mut BpfLink) -> c_int {
    *out = ptr::null_mut();
    // SAFETY: a program of a loaded object.
    let l = unsafe { bpf_program__attach(p) };
    // SAFETY: what libbpf returned.
    let err = unsafe { libbpf_get_error(l.cast_const().cast()) } as c_int;
    if err != 0 {
        return err;
    }
    // SAFETY: the link attached above and a C string.
    if unsafe { bpf_link__pin(l, pin) } != 0 {
        let err = last_err();
        // SAFETY: the link, detached as it goes.
        unsafe { bpf_link__destroy(l) };
        return err;
    }
    *out = l;
    0
}

/// Attaches the `guards` of `obj` in order, their links into `links`.
fn attach_group(
    obj: *mut BpfObject,
    guards: &[ImageGuard],
    links: &mut Vec<*mut BpfLink>,
) -> c_int {
    for g in guards {
        let p = program(obj, g.prog);
        if p.is_null() {
            error(&cat!("program ", text(g.prog), " missing"));
            return -ENOENT;
        }
        let mut l = ptr::null_mut();
        let ret = attach_pin(p, g.pin, &mut l);
        links.push(l);
        if ret != 0 {
            error(&cat!("attach ", text(g.prog), ": ", strerr(-ret)));
            return ret;
        }
    }
    0
}

/// The admission and seal objects share bootstrap state and task marks.
fn share_policy_maps(source: *mut BpfObject, destination: *mut BpfObject) -> c_int {
    // SAFETY: the map table, constant data.
    let maps = unsafe { &shirudo_guard_maps };

    for m in maps {
        let (from, to) = (map(source, m.name), map(destination, m.name));
        if from.is_null() || to.is_null() {
            return -ENOENT;
        }
        // SAFETY: a map of the unloaded destination and a map's fd.
        let ret = unsafe { bpf_map__reuse_fd(to, map_fd(from)) };
        if ret != 0 {
            return ret;
        }
    }
    0
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
fn freeze_task_maps(obj: *mut BpfObject) -> c_int {
    // SAFETY: the map table, constant data.
    let maps = unsafe { &shirudo_guard_maps };
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
        let found = map(obj, m.name);
        if found.is_null() {
            ret = -ENOENT;
            break;
        }
        let fd = map_fd(found);
        if i == GUARD_TASKS {
            let (key, value) = ((&raw const pidfd).cast(), (&raw const authority).cast());
            // SAFETY: the map's fd, the pidfd key and the authority value.
            if unsafe { bpf_map_update_elem(fd, key, value, BPF_ANY) } != 0 {
                ret = last_err();
                break;
            }
        }
        // Expected roots change for each mapping.
        // SAFETY: the map's fd.
        let frozen = i == GUARD_ROOTS || unsafe { bpf_map_freeze(fd) } == 0;
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
fn record_bpffs_mount(obj: *mut BpfObject) -> c_int {
    let (zero, mut mount) = (0u32, 0u64);
    // SAFETY: a C string.
    let fd = unsafe { open(BPFFS_DIR.as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };

    if fd < 0 {
        return last_err();
    }
    // SAFETY: the descriptor opened above.
    unsafe { close(fd) };
    let m = map(obj, c"shirudo_mnt_rec".as_ptr());
    if m.is_null() {
        return -ENOENT;
    }
    // SAFETY: the map's fd, its key and room for its value.
    if unsafe { bpf_map_lookup_elem(map_fd(m), (&raw const zero).cast(), (&raw mut mount).cast()) }
        != 0
    {
        return last_err();
    }
    if mount == 0 {
        return -ENOENT;
    }
    // SAFETY: the map's fd.
    if unsafe { bpf_map_freeze(map_fd(m)) } != 0 {
        last_err()
    } else {
        0
    }
}

/// The objects and links of one run, in the order a failed run undoes
/// them.
struct Attached {
    obj: *mut BpfObject,
    seal_obj: *mut BpfObject,
    image_seal: Vec<*mut BpfLink>,
    image_observer: Vec<*mut BpfLink>,
    observer: Vec<*mut BpfLink>,
    seal: Vec<*mut BpfLink>,
    mount: Vec<*mut BpfLink>,
    gates: [*mut BpfLink; GATE_HOOK_COUNT],
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
    fn gate(&mut self, guard: usize, p: *mut BpfProgram, hook: &str) -> c_int {
        let ret = attach_pin(p, gate(guard).pin, &mut self.gates[guard]);

        if ret != 0 {
            error(&cat!("attach lsm/", hook, ": ", strerr(-ret)));
        }
        ret
    }

    /// Writable state and runtime processes always get the full seal.
    fn attach_seal(&mut self) -> c_int {
        // SAFETY: the embedded seal object, static.
        let blob = unsafe { seal_blob() };

        if !blob_ok(blob) {
            error(b"embedded seal blob missing");
            return -ENOENT;
        }
        let obj = match open_blob(blob) {
            Ok(obj) => obj,
            Err(err) => {
                error(&cat!("seal: bpf_object__open_mem: ", err));
                return err;
            }
        };
        let mut err = share_policy_maps(self.obj, obj);
        if err == 0 {
            // SAFETY: the object opened above.
            err = unsafe { bpf_object__load(obj) };
        }
        if err == 0 {
            let scratch = map(obj, c"seal_scratch_map".as_ptr());
            err = if scratch.is_null() {
                -ENOENT
            } else {
                // SAFETY: the map's fd.
                unsafe { bpf_map_freeze(map_fd(scratch)) }
            };
        }
        if err != 0 {
            error(&cat!("seal: bpf_object__load: ", err));
            // SAFETY: the object opened above.
            unsafe { bpf_object__close(obj) };
            return err;
        }
        // SAFETY: the guard tables, constant data.
        let (seal, image_seal) = unsafe { (&shirudo_seal_guards, &shirudo_image_seal_guards) };
        err = attach_group(obj, seal, &mut self.seal);
        if err == 0 {
            err = attach_group(obj, image_seal, &mut self.image_seal);
        }
        if err != 0 {
            // SAFETY: the object opened above.
            unsafe { bpf_object__close(obj) };
            return err;
        }
        self.seal_obj = obj;
        0
    }

    fn run(&mut self, blob: *const EmbeddedBpf) -> c_int {
        let obj = self.obj;
        let mut id = Identity::zeroed();

        // SAFETY: the object opened from the blob.
        let err = unsafe { bpf_object__load(obj) };
        if err != 0 {
            error(&cat!("bpf_object__load: ", err));
            return err;
        }
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

        let sb = map(obj, c"shirudo_bpffs_sb".as_ptr());
        if sb.is_null() {
            error(b"shirudo_bpffs_sb map not in embedded bpf2");
            return -ENOENT;
        }
        let fd = map_fd(sb);
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
        // SAFETY: the map's fd.
        if unsafe { bpf_map_freeze(fd) } != 0 {
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
        // SAFETY: the guard tables, constant data.
        let (observer, image_observer, mount) = unsafe {
            (
                &shirudo_observer_guards,
                &shirudo_image_observer_guards,
                &shirudo_mount_guards,
            )
        };
        let mut err = attach_group(obj, observer, &mut self.observer);
        if err == 0 {
            err = attach_group(obj, image_observer, &mut self.image_observer);
        }
        if err != 0 {
            return err;
        }
        let progs = [
            GUARD_UNLINK,
            GUARD_SETXATTR,
            GUARD_REMOVEXATTR,
            GUARD_PROG_LOAD,
            GUARD_BPF_MAP,
            GUARD_KEY_PERMISSION,
            GUARD_TPM_COMMAND,
            GUARD_BPF,
        ]
        .map(|g| (g, program(obj, gate(g).prog)));
        if progs.iter().any(|(_, p)| p.is_null()) {
            error(b"expected programs missing in bpf2 object");
            return -ENOENT;
        }
        let prog = |guard: usize| {
            progs
                .iter()
                .find(|(g, _)| *g == guard)
                .map_or(ptr::null_mut(), |(_, p)| *p)
        };

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
        let err = self.attach_seal();
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
        // SAFETY: the blob's name, a static C string.
        let name = unsafe { ffi::c_str((*blob).name) };
        info(&cat!(
            name,
            " and seal attached: lsm/bpf gate live, writable state sealed"
        ));
        0
    }

    /// Lets go of the objects and links; after a failed run (`err`)
    /// unpins each link and removes the maps it pinned first.
    fn release(self, err: c_int) {
        for group in [
            &self.image_seal,
            &self.image_observer,
            &self.observer,
            &self.seal,
            &self.mount,
        ] {
            for &l in group {
                // SAFETY: a link this run attached, or NULL.
                unsafe {
                    if err != 0 && !l.is_null() {
                        bpf_link__unpin(l);
                    }
                    bpf_link__destroy(l);
                }
            }
        }
        if err != 0 {
            for &l in GATE_RELEASE.iter().map(|&g| &self.gates[g]) {
                if !l.is_null() {
                    // SAFETY: a link this run attached.
                    unsafe { bpf_link__unpin(l) };
                }
            }
            for pin in MAP_PINS {
                // SAFETY: a C string.
                unsafe { unlink(pin.as_ptr()) };
            }
        }
        // SAFETY: the objects this run opened, or NULL, and its links.
        unsafe {
            bpf_object__close(self.seal_obj);
            for g in GATE_RELEASE {
                bpf_link__destroy(self.gates[g]);
            }
            bpf_object__close(self.obj);
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
    // SAFETY: the embedded bpf2 object, static.
    let blob = unsafe { bpf2_blob() };
    if !blob_ok(blob) {
        error(b"embedded bpf2 blob missing");
        return -ENOENT;
    }
    let obj = match open_blob(blob) {
        Ok(obj) => obj,
        Err(err) => {
            error(&cat!("bpf_object__open_mem: ", err));
            return err;
        }
    };
    let mut a = Attached {
        obj,
        seal_obj: ptr::null_mut(),
        image_seal: Vec::new(),
        image_observer: Vec::new(),
        observer: Vec::new(),
        seal: Vec::new(),
        mount: Vec::new(),
        gates: [ptr::null_mut(); GATE_HOOK_COUNT],
    };
    let err = a.run(blob);
    a.release(err);
    err
}

const _: () = assert!(size_of::<TaskAuthority>() == 8);
