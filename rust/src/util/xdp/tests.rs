// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{
    EACCES, EBUSY, EEXIST, EINVAL, EMEDIUMTYPE, ENODEV, ENOMEM, ENOPROTOOPT, ENOSPC, EOPNOTSUPP,
    EPERM, ERANGE, EREMOTE, EXDEV,
};
use crate::util::upatch::{XDP_ALL, XDP_NETWORK, XDP_UNKNOWN, XDP_VIRTUAL, XDP_VM};

const NLA_F_NESTED: u16 = 0x8000;
const NETDEV_XDP_ACT_REDIRECT: u64 = 2;

fn set(field: &mut [u8], value: &str) {
    field.fill(0);
    field[..value.len()].copy_from_slice(value.as_bytes());
}

/// `n` veth devices of ifindex 10 on.
fn veths(n: u32) -> Vec<XdpDevice> {
    (0..n)
        .map(|i| {
            let mut d = XdpDevice::empty();
            set(&mut d.kind, "veth");
            d.ifindex = 10 + i;
            d
        })
        .collect()
}

#[test]
fn classes_are_exclusive() {
    let mut dev = XdpDevice::empty();

    assert_eq!(dev.class(), XDP_UNKNOWN);
    set(&mut dev.kind, "veth");
    assert_eq!(dev.class(), XDP_VIRTUAL);
    set(&mut dev.parent_bus, "pci");
    assert_eq!(dev.class(), XDP_NETWORK);
    dev.devlink_port = true;
    dev.port_flavour = FLAVOUR_PCI_VF;
    assert_eq!(dev.class(), XDP_VIRTUAL);
    dev.port_flavour = FLAVOUR_PHYSICAL;
    assert_eq!(dev.class(), XDP_NETWORK);
    dev.port_flavour = u16::MAX;
    assert_eq!(dev.class(), XDP_UNKNOWN);
    set(&mut dev.driver, "virtio_net");
    assert_eq!(dev.class(), XDP_VM);
    dev.flags = IFF_LOOPBACK;
    assert_eq!(dev.class(), 0);
    assert!(!selected(&[dev], 0, XDP_ALL));
}

#[test]
fn netdevsim_is_virtual_whatever_its_port_says() {
    let mut dev = XdpDevice::empty();

    set(&mut dev.driver, "netdevsim");
    set(&mut dev.parent_bus, "netdevsim");
    assert_eq!(dev.class(), XDP_VIRTUAL);
    dev.devlink_port = true;
    dev.port_flavour = FLAVOUR_PHYSICAL;
    assert_eq!(dev.class(), XDP_VIRTUAL);
}

#[test]
fn xen_netback_is_virtual_though_named_vif() {
    let mut dev = XdpDevice::empty();

    set(&mut dev.driver, "vif");
    set(&mut dev.parent_bus, "xen");
    assert_eq!(dev.class(), XDP_VM);
    set(&mut dev.parent_bus, "xen-backend");
    assert_eq!(dev.class(), XDP_VIRTUAL);
}

#[test]
fn veth_peers_are_namespace_aware() {
    let mut devs = veths(4);

    devs[0].peer_ifindex = 11;
    devs[1].peer_ifindex = 10;
    assert!(selected(&devs, 0, XDP_VIRTUAL));
    assert!(!selected(&devs, 1, XDP_ALL));
    assert!(!selected(&devs, 0, XDP_UNKNOWN));
    devs[2].peer_ifindex = 13;
    devs[3].peer_ifindex = 12;
    devs[2].peer_other_netns = true;
    devs[3].peer_other_netns = true;
    assert!(selected(&devs, 2, XDP_VIRTUAL));
    assert!(selected(&devs, 3, XDP_VIRTUAL));
    devs[0].peer_other_netns = true;
    devs[1].peer_other_netns = true;
    assert!(selected(&devs, 0, XDP_VIRTUAL));
    assert!(selected(&devs, 1, XDP_VIRTUAL));
}

#[test]
fn veth_without_a_peer_is_not_selected() {
    let mut devs = veths(2);

    devs[0].peer_ifindex = 99;
    devs[1].peer_ifindex = 11;
    assert!(!selected(&devs, 0, XDP_ALL));
    assert!(!selected(&devs, 1, XDP_ALL));
}

#[test]
fn unresolved_devices_sit_out() {
    let mut devs = veths(3);

    devs[0].peer_ifindex = 11;
    devs[1].peer_ifindex = 10;
    devs[2].peer_ifindex = 7;
    devs[2].peer_other_netns = true;
    devs[1].unresolved = true;
    assert!(!selected(&devs, 0, XDP_ALL));
    assert!(!selected(&devs, 1, XDP_ALL));
    assert!(selected(&devs, 2, XDP_ALL));
    devs[2].unresolved = true;
    assert!(!selected(&devs, 2, XDP_ALL));
}

#[test]
fn reconcile_never_touches_another_program() {
    assert_eq!(reconcile_action(false, 0, 7), Reconcile::None);
    assert_eq!(reconcile_action(false, 7, 7), Reconcile::None);
    assert_eq!(reconcile_action(false, 9, 7), Reconcile::None);
    assert_eq!(reconcile_action(true, 0, 7), Reconcile::Attach);
    assert_eq!(reconcile_action(true, 7, 7), Reconcile::Covered);
    assert_eq!(reconcile_action(true, 9, 7), Reconcile::Occupied);
}

/// Whether the kernel's network devices could be read: unavailable where
/// it refuses discovery, which skips the case.
fn discovered() -> Option<Vec<XdpDevice>> {
    match devices_read() {
        Err(err) if [-EPERM, -EACCES, -::libc::EAFNOSUPPORT].contains(&err) => {
            eprintln!("skipped: kernel network discovery unavailable");
            None
        }
        r => Some(r.unwrap()),
    }
}

#[test]
fn attach_fails_on_a_refusal_of_a_device_still_there() {
    // No device has this index, so the kernel answers ENODEV.
    let mut gone = XdpDevice::empty();
    gone.ifindex = 0x7fff_fff0;
    // Index 0 names no device, so the lookup itself fails with EINVAL.
    let unaskable = XdpDevice::empty();

    for err in [-EXDEV, -ENODEV, -EINVAL] {
        assert!(attach_skippable(err, &gone), "{err}");
    }
    assert!(!attach_skippable(-EINVAL, &unaskable));
    for err in [ERR_LINK_SCOPE, -EACCES, -EPERM, 0] {
        assert!(!attach_skippable(err, &gone), "{err}");
    }
    let Some(devices) = discovered() else {
        return;
    };
    assert!(!devices.is_empty());
    for err in [
        -EINVAL,
        -ENOSPC,
        -ERANGE,
        -EEXIST,
        -EBUSY,
        -EMEDIUMTYPE,
        -ENOPROTOOPT,
        -EREMOTE,
        ERR_NO_MULTIBUF,
        ERR_DRIVER_SETTINGS,
        ERR_LINK_SCOPE,
        ERR_OCCUPIED,
    ] {
        assert!(!attach_skippable(err, &devices[0]), "{err}");
    }
}

/// Gone or not, a device that answers busy runs another program.
#[test]
fn attach_stops_on_an_occupied_device() {
    let dev = XdpDevice::empty();
    let mut gone = XdpDevice::empty();
    gone.ifindex = 0x7fff_fff0;

    assert!(!attach_skippable(ERR_OCCUPIED, &dev));
    assert!(!attach_skippable(ERR_OCCUPIED, &gone));
    assert!(!attach_skippable(-EEXIST, &dev));
    assert!(!attach_skippable(-EBUSY, &dev));
    assert!(attach_skippable(-EXDEV, &dev));
    assert!(attach_skippable(-ENODEV, &dev));
    assert!(!attach_skippable(0, &dev));
}

/// strerror() of `errno`.
fn strerror_of(errno: c_int) -> &'static CStr {
    // SAFETY: the C library's text for an errno, static for its life.
    unsafe { CStr::from_ptr(crate::sys::libc::strerror(errno)) }
}

#[test]
fn multibuf_is_required_of_native_xdp_alone() {
    let (basic, sg) = (NETDEV_XDP_ACT_BASIC, NETDEV_XDP_ACT_RX_SG);

    assert!(multibuf_refused(basic));
    assert!(multibuf_refused(basic | NETDEV_XDP_ACT_REDIRECT));
    assert!(!multibuf_refused(basic | sg));
    assert!(!multibuf_refused(0));
    assert!(!multibuf_refused(sg));
    assert_eq!(
        attach_strerror(ERR_NO_MULTIBUF),
        c"the device does not report multi-buffer XDP support"
    );
    assert_eq!(attach_strerror(-EINVAL), strerror_of(EINVAL));
}

#[test]
fn uncovered_devices_say_why() {
    let (basic, sg) = (NETDEV_XDP_ACT_BASIC, NETDEV_XDP_ACT_RX_SG);

    assert_eq!(
        uncovered_reason(9, 0, basic | sg),
        c"another XDP program attached"
    );
    assert_eq!(uncovered_reason(0, -EOPNOTSUPP, 0), c"not attached");
    assert_eq!(uncovered_reason(0, 0, 0), c"no native XDP");
    assert_eq!(uncovered_reason(0, 0, basic), c"no multi-buffer XDP");
    assert_eq!(uncovered_reason(0, 0, basic | sg), c"not attached");
}

#[test]
fn only_a_device_without_xdp_lacks_it() {
    assert!(attach_unsupported(-EOPNOTSUPP, 0));
    assert!(!attach_unsupported(-EOPNOTSUPP, NETDEV_XDP_ACT_BASIC));
    assert!(!attach_unsupported(-EINVAL, 0));
    assert!(!attach_unsupported(0, 0));
    assert_eq!(
        attach_strerror(ERR_DRIVER_SETTINGS),
        c"the driver refuses XDP in its current settings"
    );
    assert_eq!(
        attach_strerror(ERR_LINK_SCOPE),
        c"the link is not on the device it was made for"
    );
}

#[test]
fn a_driver_refusal_is_told_from_other_errors() {
    for err in [-EOPNOTSUPP, -EINVAL, -ENOSPC, -ERANGE] {
        assert!(driver_refused(err), "{err}");
    }
    for err in [-EBUSY, -ENOMEM, -EPERM, 0] {
        assert!(!driver_refused(err), "{err}");
    }
}

#[test]
fn attach_errors_never_alias_an_errno() {
    assert_eq!(attach_errno(ERR_NO_MULTIBUF), -EMEDIUMTYPE);
    assert_eq!(attach_errno(ERR_DRIVER_SETTINGS), -ENOPROTOOPT);
    assert_eq!(attach_errno(ERR_OCCUPIED), -EBUSY);
    assert_eq!(attach_errno(ERR_LINK_SCOPE), -EREMOTE);
    assert_eq!(attach_errno(-EBUSY), -EBUSY);
    const { assert!(ERR_NO_NATIVE > 0) };
    assert_eq!(
        attach_strerror(ERR_OCCUPIED),
        c"the device runs another XDP program"
    );
    assert_eq!(attach_strerror(-EBUSY), strerror_of(EBUSY));
}

/// `buf` with a netlink attribute of `ty` and `value` appended, padded
/// to four bytes.
fn add_attr(buf: &mut Vec<u8>, ty: u16, value: &[u8]) {
    let len = (NLA_HDRLEN + value.len()) as u16;

    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// An RTM_NEWLINK message of interface `ifindex` with no attribute yet.
fn link_message(ifindex: i32) -> Vec<u8> {
    let mut buf = vec![0u8; IFINFOMSG_LEN];
    buf[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    buf
}

#[test]
fn link_messages_are_checked() {
    let mut buf = link_message(12);
    let mut nested = Vec::new();

    add_attr(&mut buf, IFLA_IFNAME, b"veth0\0");
    add_attr(&mut buf, IFLA_LINK, &13u32.to_ne_bytes());
    add_attr(&mut buf, IFLA_LINK_NETNSID, &4i32.to_ne_bytes());
    add_attr(&mut nested, IFLA_INFO_KIND, b"veth\0");
    add_attr(&mut buf, IFLA_LINKINFO | NLA_F_NESTED, &nested);
    let dev = device_parse(&buf).unwrap();
    assert_eq!(
        (text(&dev.name), text(&dev.kind)),
        (&b"veth0"[..], &b"veth"[..])
    );
    assert_eq!((dev.ifindex, dev.peer_ifindex), (12, 13));
    assert!(dev.peer_other_netns);
    assert_eq!(dev.attached(), 0);
    // Cut short anywhere before the name's end.
    for n in 0..IFINFOMSG_LEN + NLA_HDRLEN + "veth0\0".len() {
        assert_eq!(device_parse(&buf[..n]).err(), Some(-EINVAL), "{n}");
    }
    assert_eq!(device_parse(&buf[..buf.len() - 1]).err(), Some(-EINVAL));
    add_attr(&mut buf, IFLA_IFNAME, b"other\0");
    assert_eq!(device_parse(&buf).err(), Some(-EINVAL));
    let mut unterminated = link_message(12);
    add_attr(&mut unterminated, IFLA_IFNAME, b"no-nul");
    assert_eq!(device_parse(&unterminated).err(), Some(-EINVAL));
}

#[test]
fn every_xdp_mode_is_read_from_the_dump() {
    let mut base = link_message(3);
    add_attr(&mut base, IFLA_IFNAME, b"eth0\0");
    let with_xdp = |attrs: &[(u16, &[u8])]| {
        let mut nested = Vec::new();
        for (ty, value) in attrs {
            add_attr(&mut nested, *ty, value);
        }
        let mut buf = base.clone();
        add_attr(&mut buf, IFLA_XDP | NLA_F_NESTED, &nested);
        device_parse(&buf)
    };
    let (drv, skb, hw) = (21u32, 22u32, 23u32);

    let dev = with_xdp(&[(IFLA_XDP_SKB_PROG_ID, &skb.to_ne_bytes())]).unwrap();
    assert_eq!((dev.xdp_drv_id, dev.attached()), (0, skb));
    assert_eq!(
        reconcile_action(true, dev.attached(), 7),
        Reconcile::Occupied
    );
    let dev = with_xdp(&[
        (IFLA_XDP_HW_PROG_ID, &hw.to_ne_bytes()),
        (IFLA_XDP_DRV_PROG_ID, &drv.to_ne_bytes()),
    ])
    .unwrap();
    assert_eq!((dev.attached(), dev.xdp_other_id), (drv, hw));
    assert_eq!(
        with_xdp(&[(IFLA_XDP_DRV_PROG_ID, &drv.to_ne_bytes()[..2])]).err(),
        Some(-EINVAL)
    );
}

#[test]
fn device_features_are_checked() {
    let value = NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_RX_SG;
    let mut buf = vec![0u8; GENL_HDRLEN];

    add_attr(&mut buf, NETDEV_A_DEV_IFINDEX, &7u32.to_ne_bytes());
    assert_eq!(features_parse(&buf), Err(-EINVAL));
    assert_eq!(features_parse(&buf[..GENL_HDRLEN - 1]), Err(-EINVAL));
    add_attr(&mut buf, NETDEV_A_DEV_XDP_FEATURES, &value.to_ne_bytes());
    assert_eq!(features_parse(&buf), Ok(value));
    let mut small = vec![0u8; GENL_HDRLEN];
    add_attr(&mut small, NETDEV_A_DEV_XDP_FEATURES, &1u32.to_ne_bytes());
    assert_eq!(features_parse(&small), Err(-EINVAL));
}

#[test]
fn the_network_namespace_is_known() {
    // CI runs riscv64 under QEMU user emulation, which lacks the option.
    if cfg!(target_arch = "riscv64") {
        eprintln!("skipped: SO_NETNS_COOKIE unavailable under emulation");
        return;
    }
    let ret = netns_initial();
    assert!(ret == 0 || ret == -EXDEV, "{ret}");
}

#[test]
fn kernel_discovery_revalidates_devices() {
    let Some(devices) = discovered() else {
        return;
    };

    assert!(!devices.is_empty());
    for (i, dev) in devices.iter().enumerate() {
        assert_eq!(device_verify(dev), 0);
        if i > 0 {
            assert!(devices[i - 1].ifindex < dev.ifindex);
        }
    }
}
