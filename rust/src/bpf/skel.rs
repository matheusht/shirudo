// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C light skeleton of an object, byte for byte the header bpftool's
//! `gen skeleton -L` writes: the struct a C program fills to run the
//! loader through skel_internal.h's bpf_load_and_run(), with the loader's
//! instructions and blob, the initial values of the object's global data
//! and, signed, the loader's signature and the hash its maps are bound
//! to.

use core::ffi::c_int;
use std::fmt::Write as _;

use super::btf::{self, Btf};
use super::btf_dump::Dump;
use super::object::{GenOpts, Map, Object};
use super::{F_MMAPABLE, F_RDONLY_PROG, MAP_ARENA, PROG_LSM, PROG_RAW_TRACEPOINT, PROG_TRACING};
use crate::errno::EINVAL;

/// The most bytes bpftool takes of an object's name.
const MAX_OBJ_NAME_LEN: usize = 64;
/// The room bpftool gives a signature.
const MAX_SIG_SIZE: usize = 16384;
/// BPF_TRACE_ITER, which a tracing program attaches through a link.
const TRACE_ITER: u32 = 28;

fn sanitize(name: &mut [u8]) {
    for c in name {
        if !c.is_ascii_alphanumeric() && *c != b'_' {
            *c = b'_';
        }
    }
}

fn sanitized(name: &[u8]) -> Vec<u8> {
    let mut n = name.to_vec();
    sanitize(&mut n);
    n
}

/// get_obj_name(): the object's file name without its directory and a
/// `.o`, made an identifier.
pub(crate) fn obj_name(file: &[u8]) -> Vec<u8> {
    let trimmed = match file.iter().rposition(|&c| c != b'/') {
        Some(end) => &file[..=end],
        None if file.is_empty() => b".",
        None => b"/",
    };
    let base = trimmed.rsplit(|&c| c == b'/').next().unwrap_or(trimmed);
    let mut name = base[..base.len().min(MAX_OBJ_NAME_LEN - 1)].to_vec();
    if name.ends_with(b".o") {
        name.truncate(name.len() - 2);
    }
    sanitize(&mut name);
    name
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// get_map_ident(): the name of the map's member of the skeleton: a map
/// of .maps its own, a global data map that of its section.
fn map_ident(m: &Map) -> Option<Vec<u8>> {
    if !m.is_internal() {
        return Some(m.name.clone());
    }
    [&b".data"[..], b".rodata", b".bss", b".kconfig"]
        .iter()
        .find_map(|sfx| find(&m.name, sfx))
        .map(|p| sanitized(&m.name[p + 1..]))
}

/// is_skel_data(): the member of a global data map user space reaches
/// through the skeleton, which is one it can map. Once the object is
/// `loaded`, libbpf has mapped an arena too, so bpftool takes it for one
/// named `arena`, with no initial value.
fn skel_data(m: &Map, loaded: bool) -> Option<Vec<u8>> {
    if loaded && m.map_type() == MAP_ARENA {
        return Some(b"arena".to_vec());
    }
    if !m.is_internal() || m.map_flags() & F_MMAPABLE == 0 {
        return None;
    }
    map_ident(m)
}

/// get_datasec_ident()
fn datasec_ident(sec_name: &[u8]) -> Option<Vec<u8>> {
    if sec_name == b".addr_space.1" {
        return Some(b"arena".to_vec());
    }
    [&b".data"[..], b".rodata", b".bss", b".percpu", b".kconfig"]
        .iter()
        .any(|pfx| sec_name.starts_with(pfx))
        .then(|| sanitized(&sec_name[1..]))
}

/// find_type_for_map(): the DATASEC of a global data map.
fn datasec_for(btf: &Btf, ident: &[u8]) -> Option<u32> {
    (1..btf.type_cnt()).find(|&id| {
        btf.kind(id) == btf::KIND_DATASEC && datasec_ident(btf.name(id)).as_deref() == Some(ident)
    })
}

fn text(s: &[u8]) -> Result<&str, c_int> {
    core::str::from_utf8(s).map_err(|_| {
        crate::log::warn(b"skeleton: a name is not UTF-8");
        -EINVAL
    })
}

/// print_hex(): `data` as the body of a C string, in lines of at most 78
/// columns.
fn print_hex(out: &mut String, data: &[u8]) {
    let mut len = 0;
    for &c in data {
        let w = if c != 0 { 4 } else { 2 };
        len += w;
        if len > 78 {
            out.push_str("\\\n");
            len = w;
        }
        if c == 0 {
            out.push_str("\\0");
        } else {
            let _ = write!(out, "\\x{c:02x}");
        }
    }
}

/// What signs the loader: a detached signature over its instructions and
/// blob, of at most the bytes given.
pub(crate) type Signer<'a> = dyn Fn(&[u8], &[u8], usize) -> Result<Vec<u8>, c_int> + 'a;

/// The skeleton's generator: the object, its name, and the members of its
/// maps and programs.
struct Gen<'a> {
    obj: Object,
    name: &'a str,
    out: String,
}

impl Gen<'_> {
    /// The maps with a member, each with its member's name, in the
    /// object's order.
    fn maps(&self) -> Vec<(usize, Vec<u8>)> {
        self.obj
            .maps
            .iter()
            .enumerate()
            .filter_map(|(i, m)| map_ident(m).map(|id| (i, id)))
            .collect()
    }

    /// The maps of global data user space reaches, before the loader is
    /// generated or after.
    fn data_maps(&self, loaded: bool) -> Vec<(usize, Vec<u8>)> {
        self.obj
            .maps
            .iter()
            .enumerate()
            .filter_map(|(i, m)| skel_data(m, loaded).map(|id| (i, id)))
            .collect()
    }

    fn prog_names(&self) -> Result<Vec<String>, c_int> {
        self.obj
            .programs()
            .map(|p| text(&p.name).map(str::to_owned))
            .collect()
    }

    /// codegen_datasec_def(): the struct of a global data section's
    /// variables, padded to their offsets.
    fn datasec_def(
        out: &mut String,
        name: &str,
        btf: &Btf,
        dump: &mut Dump<'_>,
        sec: u32,
    ) -> Result<(), c_int> {
        let sec_name = btf.name(sec);
        let Some(sec_ident) = datasec_ident(sec_name) else {
            return Ok(());
        };
        let strip_mods = sec_name != b".kconfig";
        let sec_ident = text(&sec_ident)?.to_owned();
        let _ = writeln!(out, "\tstruct {}__{sec_ident} {{", name);
        let (mut off, mut pad_cnt) = (0u32, 0);
        for i in 0..btf.vlen(sec) {
            let (var, need_off, size) = btf.secinfo(sec, i);
            if btf.var_linkage(var) == btf::VAR_STATIC {
                continue;
            }
            if off > need_off {
                crate::log::warn(
                    format!("Something is wrong for {}'s variable #{i}: need offset {need_off}, already at {off}.", text(sec_name)?)
                        .as_bytes(),
                );
                return Err(-EINVAL);
            }
            let Ok(align) = btf.align_of(btf.size_or_type(var)) else {
                crate::log::warn(b"Failed to determine alignment of a variable");
                return Err(-EINVAL);
            };
            // bpftool lays the section out for a 32-bit host.
            let align = align.min(4);
            if off.div_ceil(align) * align != need_off {
                let _ = writeln!(out, "\t\tchar __pad{pad_cnt}[{}];", need_off - off);
                pad_cnt += 1;
            }
            let mut ident = btf.name(var).to_vec();
            ident.truncate(255);
            sanitize(&mut ident);
            let mut decl = Vec::new();
            dump.emit_type_decl(&mut decl, btf.size_or_type(var), &ident, strip_mods)?;
            let _ = writeln!(out, "\t\t{};", text(&decl)?);
            off = need_off + size;
        }
        let _ = writeln!(out, "\t}} *{sec_ident};");
        Ok(())
    }

    /// codegen_datasecs(): the struct of each global data map user space
    /// reaches, empty for one without a DATASEC.
    fn datasecs(&mut self) -> Result<(), c_int> {
        let btf = self.obj.btf();
        let mut dump = Dump::new(btf);
        for (_, ident) in self.data_maps(false) {
            match datasec_for(btf, &ident) {
                Some(sec) => Self::datasec_def(&mut self.out, self.name, btf, &mut dump, sec)?,
                None => {
                    let ident = text(&ident)?;
                    let _ = write!(
                        self.out,
                        "\tstruct {}__{ident} {{\n\t}} *{ident};\n",
                        self.name
                    );
                }
            }
        }
        Ok(())
    }

    /// codegen_attach_detach()
    fn attach_detach(&mut self) -> Result<(), c_int> {
        let n = self.name;
        for p in self.obj.programs() {
            let pn = text(&p.name)?;
            let _ = write!(
                self.out,
                "\nstatic inline int\n{n}__{pn}__attach(struct {n} *skel)\n{{\n\tint prog_fd = skel->progs.{pn}.prog_fd;\n"
            );
            match p.prog_type {
                PROG_RAW_TRACEPOINT => {
                    let tp = p
                        .sec_name
                        .iter()
                        .position(|&c| c == b'/')
                        .map(|i| &p.sec_name[i + 1..]);
                    let Some(tp) = tp else {
                        crate::log::warn(b"skeleton: a raw tracepoint program names no tracepoint");
                        return Err(-EINVAL);
                    };
                    let _ = writeln!(
                        self.out,
                        "\tint fd = skel_raw_tracepoint_open(\"{}\", prog_fd);",
                        text(tp)?
                    );
                }
                PROG_TRACING | PROG_LSM if p.attach == TRACE_ITER => {
                    self.out
                        .push_str("\tint fd = skel_link_create(prog_fd, 0, BPF_TRACE_ITER);\n");
                }
                PROG_TRACING | PROG_LSM => self
                    .out
                    .push_str("\tint fd = skel_raw_tracepoint_open(NULL, prog_fd);\n"),
                _ => self
                    .out
                    .push_str("\tint fd = ((void)prog_fd, 0); /* auto-attach not supported */\n"),
            }
            let _ = write!(
                self.out,
                "\n\tif (fd > 0)\n\t\tskel->links.{pn}_fd = fd;\n\treturn fd;\n}}\n"
            );
        }
        let _ = write!(
            self.out,
            "\nstatic inline int\n{n}__attach(struct {n} *skel)\n{{\n\tint ret = 0;\n\n"
        );
        let progs = self.prog_names()?;
        for pn in &progs {
            let _ = writeln!(self.out, "\tret = ret < 0 ? ret : {n}__{pn}__attach(skel);");
        }
        let _ = write!(
            self.out,
            "\treturn ret < 0 ? ret : 0;\n}}\n\nstatic inline void\n{n}__detach(struct {n} *skel)\n{{\n"
        );
        for pn in &progs {
            let _ = writeln!(self.out, "\tskel_closenz(skel->links.{pn}_fd);");
        }
        self.out.push_str("}\n");
        Ok(())
    }

    /// codegen_destroy()
    fn destroy(&mut self) -> Result<(), c_int> {
        let n = self.name;
        let _ = write!(
            self.out,
            "static void\n{n}__destroy(struct {n} *skel)\n{{\n\tif (!skel)\n\t\treturn;\n\t{n}__detach(skel);\n"
        );
        for pn in self.prog_names()? {
            let _ = writeln!(self.out, "\tskel_closenz(skel->progs.{pn}.prog_fd);");
        }
        for (i, ident) in self.maps() {
            let m = &self.obj.maps[i];
            // bpftool goes on with the member is_skel_data() names.
            let data = skel_data(m, true);
            let ident = text(data.as_deref().unwrap_or(&ident))?.to_owned();
            if data.is_some() {
                let _ = writeln!(
                    self.out,
                    "\tskel_free_map_data(skel->{ident}, skel->maps.{ident}.initial_value, {}, {});",
                    m.value_size(),
                    m.max_entries()
                );
            }
            let _ = writeln!(self.out, "\tskel_closenz(skel->maps.{ident}.map_fd);");
        }
        self.out.push_str("\tskel_free(skel);\n}\n");
        Ok(())
    }

    /// codegen_asserts(): the size of each variable a global data struct
    /// declares, checked when the header compiles.
    fn asserts(&mut self) -> Result<(), c_int> {
        let n = self.name;
        let _ = write!(
            self.out,
            "__attribute__((unused)) static void\n{n}__assert(struct {n} *s __attribute__((unused)))\n{{\n#ifdef __cplusplus\n#define _Static_assert static_assert\n#endif\n"
        );
        let btf = self.obj.btf();
        for (_, ident) in self.data_maps(true) {
            let Some(sec) = datasec_for(btf, &ident) else {
                continue;
            };
            let ident = text(&ident)?;
            for i in 0..btf.vlen(sec) {
                let var = btf.secinfo(sec, i).0;
                if btf.var_linkage(var) == btf::VAR_STATIC {
                    continue;
                }
                let Ok(size) = btf.resolve_size(btf.size_or_type(var)) else {
                    continue;
                };
                let mut v = btf.name(var).to_vec();
                v.truncate(255);
                sanitize(&mut v);
                let v = text(&v)?;
                let _ = writeln!(
                    self.out,
                    "\t_Static_assert(sizeof(s->{ident}->{v}) == {size}, \"unexpected size of '{v}'\");"
                );
            }
        }
        self.out
            .push_str("#ifdef __cplusplus\n#undef _Static_assert\n#endif\n}\n");
        Ok(())
    }

    /// gen_trace(): the loader generated, then the functions that open,
    /// load, attach and destroy the skeleton around it.
    fn trace(&mut self, guard: &str, sign: Option<&Signer<'_>>) -> Result<(), c_int> {
        let n = self.name;
        let opts = GenOpts {
            gen_hash: sign.is_some(),
            reuse_map_mask: 0,
        };
        let (insns, data) = self.obj.gen_loader(&opts)?;
        self.out.push_str("};\n");
        self.attach_detach()?;
        self.destroy()?;
        let _ = write!(
            self.out,
            "static inline struct {n} *\n{n}__open(void)\n{{\n\tstruct {n} *skel;\n\n\tskel = (struct {n} *)skel_alloc(sizeof(*skel));\n\tif (!skel)\n\t\tgoto cleanup;\n\tskel->ctx.sz = (char *)&skel->links - (char *)skel;\n"
        );
        for (i, ident) in self.data_maps(true) {
            let m = &self.obj.maps[i];
            let ident = text(&ident)?.to_owned();
            self.out.push_str(
                "\t{\n\t\tstatic const char data[] __attribute__((__aligned__(8))) = \"\\\n",
            );
            let (value_size, max_entries) = (m.value_size(), m.max_entries());
            // An arena has no initial value without arena globals.
            let initial = if m.map_type() == MAP_ARENA {
                Vec::new()
            } else {
                m.initial.clone()
            };
            print_hex(
                &mut self.out,
                &initial[..initial.len().min(value_size as usize)],
            );
            let _ = write!(
                self.out,
                "\";\n\n\t\tskel->{ident} = (__typeof__(skel->{ident}))skel_prep_map_data((void *)data, {value_size}, {max_entries},\n\t\t\t\t\t\tsizeof(data) - 1);\n\t\tif (!skel->{ident})\n\t\t\tgoto cleanup;\n\t\tskel->maps.{ident}.initial_value = (__u64) (long) skel->{ident};\n\t}}\n"
            );
        }
        let _ = write!(
            self.out,
            "\treturn skel;\ncleanup:\n\t{n}__destroy(skel);\n\treturn NULL;\n}}\n\nstatic inline int\n{n}__load(struct {n} *skel)\n{{\n\tstruct bpf_load_and_run_opts opts = {{}};\n\tint err;\n\tstatic const char opts_data[] __attribute__((__aligned__(8))) = \"\\\n"
        );
        print_hex(&mut self.out, &data);
        self.out.push_str(
            "\";\n\tstatic const char opts_insn[] __attribute__((__aligned__(8))) = \"\\\n",
        );
        print_hex(&mut self.out, &insns);
        self.out.push_str("\";\n");
        if let Some(s) = sign {
            let sig = s(&insns, &data, MAX_SIG_SIZE)?;
            let mut prog_sha = [0u8; 32];
            // SAFETY: the instructions, and room for a digest.
            if unsafe {
                crate::util::crypto_openssl::sha256_buffer(
                    insns.as_ptr().cast(),
                    insns.len(),
                    prog_sha.as_mut_ptr(),
                )
            } != 0
            {
                return Err(-EINVAL);
            }
            self.out.push_str(
                "\tstatic const char opts_sig[] __attribute__((__aligned__(8))) = \"\\\n",
            );
            print_hex(&mut self.out, &sig);
            self.out.push_str("\";\n");
            self.out.push_str(
                "\tstatic const char opts_excl_hash[] __attribute__((__aligned__(8))) = \"\\\n",
            );
            print_hex(&mut self.out, &prog_sha);
            self.out.push_str("\";\n");
            self.out.push_str(
                "\topts.signature = (void *)opts_sig;\n\topts.signature_sz = sizeof(opts_sig) - 1;\n\topts.excl_prog_hash = (void *)opts_excl_hash;\n\topts.excl_prog_hash_sz = sizeof(opts_excl_hash) - 1;\n\topts.keyring_id = skel->keyring_id;\n",
            );
        }
        self.out.push_str(
            "\topts.ctx = (struct bpf_loader_ctx *)skel;\n\topts.data_sz = sizeof(opts_data) - 1;\n\topts.data = (void *)opts_data;\n\topts.insns_sz = sizeof(opts_insn) - 1;\n\topts.insns = (void *)opts_insn;\n\n\terr = bpf_load_and_run(&opts);\n\tif (err < 0)\n\t\treturn err;\n",
        );
        for (i, ident) in self.data_maps(true) {
            let m = &self.obj.maps[i];
            let ident = text(&ident)?.to_owned();
            let prot = if m.map_flags() & F_RDONLY_PROG != 0 {
                "PROT_READ"
            } else {
                "PROT_READ | PROT_WRITE"
            };
            let _ = write!(
                self.out,
                "\tskel->{ident} = (__typeof__(skel->{ident}))skel_finalize_map_data(&skel->maps.{ident}.initial_value,\n\t\t\t\t\t{}, {}, {prot}, skel->maps.{ident}.map_fd);\n\tif (!skel->{ident})\n\t\treturn -ENOMEM;\n",
                m.value_size(),
                m.max_entries()
            );
        }
        let _ = write!(
            self.out,
            "\treturn 0;\n}}\n\nstatic inline struct {n} *\n{n}__open_and_load(void)\n{{\n\tstruct {n} *skel;\n\n\tskel = {n}__open();\n\tif (!skel)\n\t\treturn NULL;\n\tif ({n}__load(skel)) {{\n\t\t{n}__destroy(skel);\n\t\treturn NULL;\n\t}}\n\treturn skel;\n}}\n\n"
        );
        self.asserts()?;
        let _ = write!(self.out, "\n#endif /* {guard} */\n");
        Ok(())
    }
}

/// do_skeleton() with `-L`: the light skeleton of the object `data` read
/// from `file`, named `name` or after the file, signed with `sign`.
pub(crate) fn skeleton(
    data: &[u8],
    file: &[u8],
    name: Option<&[u8]>,
    sign: Option<&Signer<'_>>,
) -> Result<String, c_int> {
    let obj_name = match name {
        Some(n) => n[..n.len().min(MAX_OBJ_NAME_LEN - 1)].to_vec(),
        None => obj_name(file),
    };
    let obj = Object::open(data, &obj_name)?;
    let name = text(&obj_name)?;
    let guard = format!("__{name}_SKEL_H__").to_ascii_uppercase();
    let mut g = Gen {
        obj,
        name,
        out: String::new(),
    };
    for m in &g.obj.maps {
        if map_ident(m).is_none() {
            crate::log::warn(
                format!("ignoring unrecognized internal map '{}'...", text(&m.name)?).as_bytes(),
            );
        }
    }
    let _ = write!(
        g.out,
        "/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */\n/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */\n#ifndef {guard}\n#define {guard}\n\n#include <bpf/skel_internal.h>\n\nstruct {name} {{\n\tstruct bpf_loader_ctx ctx;\n"
    );
    let maps = g.maps();
    if !maps.is_empty() {
        g.out.push_str("\tstruct {\n");
        for (_, ident) in &maps {
            let _ = writeln!(g.out, "\t\tstruct bpf_map_desc {};", text(ident)?);
        }
        g.out.push_str("\t} maps;\n");
    }
    let progs = g.prog_names()?;
    if !progs.is_empty() {
        g.out.push_str("\tstruct {\n");
        for pn in &progs {
            let _ = writeln!(g.out, "\t\tstruct bpf_prog_desc {pn};");
        }
        g.out.push_str("\t} progs;\n\tstruct {\n");
        for pn in &progs {
            let _ = writeln!(g.out, "\t\tint {pn}_fd;");
        }
        g.out.push_str("\t} links;\n");
    }
    if sign.is_some() {
        g.out.push_str("\t__s32 keyring_id;\n");
    }
    g.datasecs()?;
    g.trace(&guard, sign)?;
    Ok(g.out)
}
