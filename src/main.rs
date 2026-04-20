// M1+M2 spike: discover Xiaomi RNDIS interface, try to claim it.
// M3:         RNDIS session handshake (INITIALIZE / SET filter / QUERY MAC).
// Usage:  ./target/release/tethering scan
//         ./target/release/tethering claim
//         ./target/release/tethering init

mod rndis;

use anyhow::{anyhow, bail, Context, Result};
use rusb::{Device, DeviceHandle, UsbContext};
use std::time::Duration;

const RNDIS_CONTROL_CLASS: u8 = 0xE0;
const RNDIS_CONTROL_SUBCLASS: u8 = 0x01;
const RNDIS_CONTROL_PROTOCOL: u8 = 0x03;
const RNDIS_DATA_CLASS: u8 = 0x0A;

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "scan".into());
    match cmd.as_str() {
        "scan" => cmd_scan(),
        "claim" => cmd_claim(),
        "init" => cmd_init(),
        "dump" => cmd_dump(),
        other => Err(anyhow!(
            "unknown command: {} (use: scan | claim | init | dump)",
            other
        )),
    }
}

fn cmd_scan() -> Result<()> {
    let ctx = rusb::Context::new().context("libusb init")?;
    let devices = ctx.devices()?;
    let mut found_any = false;

    for device in devices.iter() {
        let desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let handle = device.open().ok();

        let (vendor, product) = pretty_vendor_product(handle.as_ref(), &desc);
        let is_interesting = looks_like_phone(&vendor, &product) || has_rndis_interface(&device);

        if !is_interesting {
            continue;
        }
        found_any = true;

        println!(
            "─── {:04x}:{:04x}  {}  |  {}",
            desc.vendor_id(),
            desc.product_id(),
            vendor.trim(),
            product.trim()
        );
        print_configurations(&device)?;
        println!();
    }

    if !found_any {
        println!("(no tethering-candidate USB devices found)");
    }
    Ok(())
}

fn cmd_claim() -> Result<()> {
    let ctx = rusb::Context::new()?;
    let devices = ctx.devices()?;

    for device in devices.iter() {
        let desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if !has_rndis_interface(&device) {
            continue;
        }

        println!(
            "target: {:04x}:{:04x}",
            desc.vendor_id(),
            desc.product_id()
        );

        let mut handle = device.open().context("open device (try sudo)")?;
        handle.set_auto_detach_kernel_driver(true).ok();

        let (ctrl_if, data_if, ep_in, ep_out) = find_rndis_endpoints(&device)?;
        println!(
            "  control IF #{}, data IF #{}, bulk IN 0x{:02x}, bulk OUT 0x{:02x}",
            ctrl_if, data_if, ep_in, ep_out
        );

        attempt_claim(&mut handle, ctrl_if, "control")?;
        attempt_claim(&mut handle, data_if, "data")?;
        probe_control_read(&handle);

        println!("✅ claim succeeded — userspace path is viable");
        return Ok(());
    }

    Err(anyhow!(
        "no RNDIS interface detected — is USB tethering toggled ON on the phone?"
    ))
}

fn cmd_init() -> Result<()> {
    let ctx = rusb::Context::new()?;
    for device in ctx.devices()?.iter() {
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if !has_rndis_interface(&device) {
            continue;
        }
        println!(
            "target: {:04x}:{:04x}",
            desc.vendor_id(),
            desc.product_id()
        );

        let handle = device.open().context("open device")?;
        handle.set_auto_detach_kernel_driver(true).ok();

        let (ctrl_if, data_if, _ep_in, _ep_out) = find_rndis_endpoints(&device)?;
        handle.claim_interface(ctrl_if).context("claim control IF")?;
        handle.claim_interface(data_if).context("claim data IF")?;
        println!("  ✔ claimed control IF #{} and data IF #{}", ctrl_if, data_if);

        let mut session = rndis::Session::open(&handle, ctrl_if)?;
        println!(
            "  ✔ INITIALIZE ok — max_transfer_size = {} B",
            session.max_transfer_size
        );

        session.set_oid(
            rndis::OID_GEN_CURRENT_PACKET_FILTER,
            &rndis::FILTER_NORMAL.to_le_bytes(),
        )?;
        println!(
            "  ✔ SET OID_GEN_CURRENT_PACKET_FILTER = 0x{:08x}",
            rndis::FILTER_NORMAL
        );

        let mac = session.query_oid(rndis::OID_802_3_PERMANENT_ADDRESS)?;
        if mac.len() != 6 {
            bail!("expected 6-byte MAC, got {} bytes: {:02x?}", mac.len(), mac);
        }
        println!("  ✔ QUERY OID_802_3_PERMANENT_ADDRESS → {}", rndis::format_mac(&mac));
        println!("✅ RNDIS session ready");
        return Ok(());
    }
    Err(anyhow!("no RNDIS device found"))
}

fn cmd_dump() -> Result<()> {
    let ctx = rusb::Context::new()?;
    for device in ctx.devices()?.iter() {
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if !has_rndis_interface(&device) {
            continue;
        }
        println!(
            "target: {:04x}:{:04x}",
            desc.vendor_id(),
            desc.product_id()
        );

        let handle = device.open().context("open device")?;
        handle.set_auto_detach_kernel_driver(true).ok();

        let (ctrl_if, data_if, ep_in, ep_out) = find_rndis_endpoints(&device)?;

        // Diagnostic: is macOS already holding on to these interfaces?
        for (label, iface) in [("control", ctrl_if), ("data", data_if)] {
            match handle.kernel_driver_active(iface) {
                Ok(true) => println!("  ⚠  kernel driver attached to {} IF #{}", label, iface),
                Ok(false) => println!("  kernel driver NOT attached to {} IF #{}", label, iface),
                Err(e) => println!("  kernel driver check failed on IF #{}: {}", iface, e),
            }
        }

        handle.claim_interface(ctrl_if)?;
        handle.claim_interface(data_if)?;

        // Clear halt on the bulk endpoints — some phones leave them stalled
        // if a previous session aborted mid-transfer.
        handle.clear_halt(ep_in).ok();
        handle.clear_halt(ep_out).ok();

        let mut session = rndis::Session::open(&handle, ctrl_if)?;

        // Replicate the exact query+set sequence that Linux rndis_bind() does,
        // in the same order. Empirically, HyperOS/MIUI RNDIS is picky enough
        // that skipping any of these may leave the data plane gated.
        //
        //   1. QUERY OID_GEN_PHYSICAL_MEDIUM   — must be 802.3 (value 0)
        //   2. QUERY OID_802_3_PERMANENT_ADDRESS
        //   3. QUERY OID_GEN_MAXIMUM_FRAME_SIZE
        //   4. QUERY OID_GEN_MEDIA_CONNECT_STATUS / LINK_SPEED (diagnostics)
        //   5. SET   OID_GEN_CURRENT_PACKET_FILTER = 0x0F  (LAST — opens data)

        let medium = session
            .query_oid(rndis::OID_GEN_PHYSICAL_MEDIUM)
            .unwrap_or_else(|_| 0u32.to_le_bytes().to_vec()); // old RNDIS may omit
        let medium_val = u32::from_le_bytes(medium.as_slice().try_into().unwrap_or([0; 4]));
        println!("  physical medium = 0x{:08x} (0 = 802.3)", medium_val);

        let phone_mac_vec = session.query_oid(rndis::OID_802_3_PERMANENT_ADDRESS)?;
        let phone_mac: [u8; 6] = phone_mac_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("bad MAC length"))?;
        println!("  phone MAC = {}", rndis::format_mac(&phone_mac));

        if let Ok(mtu) = session.query_oid(rndis::OID_GEN_MAXIMUM_FRAME_SIZE) {
            if mtu.len() == 4 {
                println!(
                    "  max frame size = {} B",
                    u32::from_le_bytes(mtu.as_slice().try_into().unwrap())
                );
            }
        }

        let link = session.query_oid(rndis::OID_GEN_MEDIA_CONNECT_STATUS)?;
        let link_val = u32::from_le_bytes(link.as_slice().try_into().unwrap_or([0; 4]));
        let link_str = if link_val == 0 { "CONNECTED" } else { "DISCONNECTED" };
        println!("  link status: {} (raw=0x{:08x})", link_str, link_val);

        let speed = session.query_oid(rndis::OID_GEN_LINK_SPEED).unwrap_or_default();
        if speed.len() == 4 {
            let bps = u32::from_le_bytes(speed.as_slice().try_into().unwrap()) as u64 * 100;
            println!("  link speed: {} bps", bps);
        }

        // SET goes LAST — this is what flips the device into RNDIS_DATA_INITIALIZED.
        session.set_oid(
            rndis::OID_GEN_CURRENT_PACKET_FILTER,
            &rndis::FILTER_NORMAL.to_le_bytes(),
        )?;
        println!("  ✔ packet filter = 0x{:08x} (data plane open)", rndis::FILTER_NORMAL);

        // Some non-Linux RNDIS gadgets stall the bulk endpoints when they see
        // SET_ETHERNET_PACKET_FILTER. SET_CMPLT returns success but the endpoint
        // is left halted and later bulk transfers silently drop. Issue a
        // CLEAR_FEATURE(ENDPOINT_HALT) on both bulk endpoints to recover.
        // Free if it's not needed; critical if it is.
        handle.clear_halt(ep_in).ok();
        handle.clear_halt(ep_out).ok();

        println!("  listening on bulk IN 0x{:02x} for 5s …", ep_in);

        // Our host-side MAC sits under the locally-administered OUI (02:xx:..)
        // so we don't collide with any real NIC. ARP probe is a quick reachability
        // check; DHCPDISCOVER is the authoritative "is this actually tethering?"
        // test since any working Android tether MUST reply with DHCPOFFER.
        let our_mac: [u8; 6] = [0x02, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let arp = build_arp_request(&our_mac, &[0, 0, 0, 0], &[192, 168, 42, 129]);
        rndis::write_bulk_frame(&handle, ep_out, &arp)?;
        println!("  → sent ARP who-has 192.168.42.129  ({} B)", arp.len());

        let xid: u32 = 0xCAFE_BABE;
        let disc = build_dhcp_discover(&our_mac, xid);
        rndis::write_bulk_frame(&handle, ep_out, &disc)?;
        println!("  → sent DHCPDISCOVER xid=0x{:08x}  ({} B)", xid, disc.len());

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut count = 0;
        while std::time::Instant::now() < deadline {
            let frames = rndis::read_bulk_frames(&handle, ep_in, Duration::from_millis(500))?;
            for f in frames {
                count += 1;
                print_ethernet(count, &f);
            }
        }
        println!("  {} frame(s) received", count);
        return Ok(());
    }
    Err(anyhow!("no RNDIS device found"))
}

/// Craft a 42-byte ethernet+ARP request frame. Ethertype 0x0806, opcode 1.
fn build_arp_request(sender_mac: &[u8; 6], sender_ip: &[u8; 4], target_ip: &[u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    // Ethernet header (14 B)
    f.extend_from_slice(&[0xFF; 6]); // dst: broadcast
    f.extend_from_slice(sender_mac); // src
    f.extend_from_slice(&[0x08, 0x06]); // ethertype = ARP
    // ARP payload (28 B)
    f.extend_from_slice(&[0x00, 0x01]); // htype = ethernet
    f.extend_from_slice(&[0x08, 0x00]); // ptype = IPv4
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&[0x00, 0x01]); // opcode = request
    f.extend_from_slice(sender_mac);
    f.extend_from_slice(sender_ip);
    f.extend_from_slice(&[0x00; 6]); // target mac unknown
    f.extend_from_slice(target_ip);
    f
}

/// Craft a 342-byte ethernet+IPv4+UDP+DHCPDISCOVER broadcast frame.
///
/// This is the canonical "wake up, DHCP server" message. Any working Android
/// USB tether runs a DHCP server that MUST reply to this. Using it as our
/// probe avoids guessing the phone's chosen subnet.
fn build_dhcp_discover(sender_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    // DHCP payload (300 B minimum per RFC 951/2131 BOOTP framing).
    let mut dhcp = Vec::with_capacity(300);
    dhcp.push(1);                    // op: BOOTREQUEST
    dhcp.push(1);                    // htype: Ethernet
    dhcp.push(6);                    // hlen
    dhcp.push(0);                    // hops
    dhcp.extend_from_slice(&xid.to_be_bytes()); // xid
    dhcp.extend_from_slice(&[0, 0]); // secs
    dhcp.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
    dhcp.extend_from_slice(&[0; 4]); // ciaddr
    dhcp.extend_from_slice(&[0; 4]); // yiaddr
    dhcp.extend_from_slice(&[0; 4]); // siaddr
    dhcp.extend_from_slice(&[0; 4]); // giaddr
    dhcp.extend_from_slice(sender_mac);
    dhcp.extend_from_slice(&[0; 10]); // chaddr padding (16 - 6)
    dhcp.extend_from_slice(&[0; 64]); // sname
    dhcp.extend_from_slice(&[0; 128]); // file
    dhcp.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    // Options
    dhcp.extend_from_slice(&[53, 1, 1]); // DHCP Message Type = DISCOVER
    dhcp.extend_from_slice(&[55, 4, 1, 3, 6, 15]); // Parameter Request List
    dhcp.push(255); // end
    while dhcp.len() < 300 {
        dhcp.push(0);
    }

    // UDP header (8 B): sport=68, dport=67, len=308, checksum=0 (optional for IPv4)
    let udp_len: u16 = 8 + dhcp.len() as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum
    udp.extend_from_slice(&dhcp);

    // IPv4 header (20 B)
    let ip_total: u16 = 20 + udp.len() as u16;
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version=4, IHL=5
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&ip_total.to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // identification
    ip.extend_from_slice(&[0, 0]); // flags/fragment
    ip.push(64); // TTL
    ip.push(17); // protocol = UDP
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&[0, 0, 0, 0]); // src 0.0.0.0
    ip.extend_from_slice(&[255, 255, 255, 255]); // dst broadcast
    let cksum = ipv4_checksum(&ip);
    ip[10] = (cksum >> 8) as u8;
    ip[11] = cksum as u8;

    // Ethernet (14 B)
    let mut eth = Vec::with_capacity(14 + ip.len() + udp.len());
    eth.extend_from_slice(&[0xFF; 6]);
    eth.extend_from_slice(sender_mac);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth.extend_from_slice(&udp);
    eth
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in hdr.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn print_ethernet(idx: usize, frame: &[u8]) {
    if frame.len() < 14 {
        println!("  [{idx:>3}] runt frame, {} B", frame.len());
        return;
    }
    let dst = &frame[0..6];
    let src = &frame[6..12];
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let kind = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP ",
        0x86DD => "IPv6",
        0x8100 => "VLAN",
        _ => "?   ",
    };
    println!(
        "  [{:>3}] {}  {} → {}  type=0x{:04x} {}  len={}",
        idx,
        kind,
        rndis::format_mac(src),
        rndis::format_mac(dst),
        ethertype,
        ethertype_hint(ethertype, frame),
        frame.len()
    );
}

fn ethertype_hint(etype: u16, frame: &[u8]) -> String {
    match etype {
        0x0806 if frame.len() >= 42 => {
            let opcode = u16::from_be_bytes([frame[20], frame[21]]);
            let sip = &frame[28..32];
            let tip = &frame[38..42];
            let verb = match opcode {
                1 => "request",
                2 => "reply  ",
                _ => "?      ",
            };
            format!(
                "[{} {}.{}.{}.{} → {}.{}.{}.{}]",
                verb, sip[0], sip[1], sip[2], sip[3], tip[0], tip[1], tip[2], tip[3]
            )
        }
        0x0800 if frame.len() >= 34 => {
            let sip = &frame[26..30];
            let dip = &frame[30..34];
            let proto = frame[23];
            let p = match proto {
                1 => "icmp",
                6 => "tcp ",
                17 => "udp ",
                _ => "?   ",
            };
            format!(
                "[{} {}.{}.{}.{} → {}.{}.{}.{}]",
                p, sip[0], sip[1], sip[2], sip[3], dip[0], dip[1], dip[2], dip[3]
            )
        }
        _ => String::new(),
    }
}

fn pretty_vendor_product<T: UsbContext>(
    handle: Option<&DeviceHandle<T>>,
    desc: &rusb::DeviceDescriptor,
) -> (String, String) {
    let lang = handle
        .and_then(|h| h.read_languages(Duration::from_millis(200)).ok())
        .and_then(|l| l.first().copied());
    let vendor = lang
        .and_then(|l| {
            handle.and_then(|h| {
                h.read_manufacturer_string(l, desc, Duration::from_millis(200))
                    .ok()
            })
        })
        .unwrap_or_else(|| format!("vendor 0x{:04x}", desc.vendor_id()));
    let product = lang
        .and_then(|l| {
            handle.and_then(|h| {
                h.read_product_string(l, desc, Duration::from_millis(200))
                    .ok()
            })
        })
        .unwrap_or_else(|| format!("product 0x{:04x}", desc.product_id()));
    (vendor, product)
}

fn looks_like_phone(vendor: &str, product: &str) -> bool {
    let v = vendor.to_lowercase();
    let p = product.to_lowercase();
    ["xiaomi", "redmi", "samsung", "google", "pixel", "oneplus", "lg", "oppo", "realme"]
        .iter()
        .any(|kw| v.contains(kw) || p.contains(kw))
}

fn has_rndis_interface<T: UsbContext>(device: &Device<T>) -> bool {
    let Ok(desc) = device.device_descriptor() else {
        return false;
    };
    for i in 0..desc.num_configurations() {
        let Ok(cfg) = device.config_descriptor(i) else {
            continue;
        };
        for iface in cfg.interfaces() {
            for alt in iface.descriptors() {
                if alt.class_code() == RNDIS_CONTROL_CLASS
                    && alt.sub_class_code() == RNDIS_CONTROL_SUBCLASS
                    && alt.protocol_code() == RNDIS_CONTROL_PROTOCOL
                {
                    return true;
                }
            }
        }
    }
    false
}

fn print_configurations<T: UsbContext>(device: &Device<T>) -> Result<()> {
    let desc = device.device_descriptor()?;
    for i in 0..desc.num_configurations() {
        let cfg = device.config_descriptor(i)?;
        println!("  cfg {} ({} interfaces):", cfg.number(), cfg.num_interfaces());
        for iface in cfg.interfaces() {
            for alt in iface.descriptors() {
                let tag = classify(&alt);
                println!(
                    "    IF {:>2}.{:<2}  class={:#04x} sub={:#04x} proto={:#04x}  {}",
                    alt.interface_number(),
                    alt.setting_number(),
                    alt.class_code(),
                    alt.sub_class_code(),
                    alt.protocol_code(),
                    tag
                );
                for ep in alt.endpoint_descriptors() {
                    let dir = if ep.address() & 0x80 != 0 { "IN " } else { "OUT" };
                    let kind = match ep.transfer_type() {
                        rusb::TransferType::Control => "ctrl",
                        rusb::TransferType::Isochronous => "iso ",
                        rusb::TransferType::Bulk => "bulk",
                        rusb::TransferType::Interrupt => "intr",
                    };
                    println!(
                        "               ep 0x{:02x}  {} {}  max {}B",
                        ep.address(),
                        dir,
                        kind,
                        ep.max_packet_size()
                    );
                }
            }
        }
    }
    Ok(())
}

fn classify(alt: &rusb::InterfaceDescriptor) -> &'static str {
    match (alt.class_code(), alt.sub_class_code(), alt.protocol_code()) {
        (0xE0, 0x01, 0x03) => "⬅ RNDIS control",
        (0x0A, _, _) => "⬅ CDC data (likely RNDIS data)",
        (0xFF, 0x42, 0x01) => "ADB",
        (0x06, _, _) => "PTP/MTP",
        (0x01, _, _) => "Audio",
        _ => "",
    }
}

fn find_rndis_endpoints<T: UsbContext>(
    device: &Device<T>,
) -> Result<(u8, u8, u8, u8)> {
    let desc = device.device_descriptor()?;
    for i in 0..desc.num_configurations() {
        let cfg = device.config_descriptor(i)?;
        let mut ctrl_if = None;
        let mut data_if = None;
        let mut ep_in = None;
        let mut ep_out = None;

        for iface in cfg.interfaces() {
            for alt in iface.descriptors() {
                if alt.class_code() == RNDIS_CONTROL_CLASS
                    && alt.sub_class_code() == RNDIS_CONTROL_SUBCLASS
                    && alt.protocol_code() == RNDIS_CONTROL_PROTOCOL
                {
                    ctrl_if = Some(alt.interface_number());
                }
                if alt.class_code() == RNDIS_DATA_CLASS {
                    data_if = Some(alt.interface_number());
                    for ep in alt.endpoint_descriptors() {
                        if ep.transfer_type() == rusb::TransferType::Bulk {
                            if ep.address() & 0x80 != 0 {
                                ep_in = Some(ep.address());
                            } else {
                                ep_out = Some(ep.address());
                            }
                        }
                    }
                }
            }
        }
        if let (Some(c), Some(d), Some(i), Some(o)) = (ctrl_if, data_if, ep_in, ep_out) {
            return Ok((c, d, i, o));
        }
    }
    Err(anyhow!("RNDIS endpoints not found"))
}

fn attempt_claim<T: UsbContext>(
    handle: &mut DeviceHandle<T>,
    iface: u8,
    label: &str,
) -> Result<()> {
    match handle.claim_interface(iface) {
        Ok(_) => {
            println!("  ✔ claimed {} interface #{}", label, iface);
            Ok(())
        }
        Err(rusb::Error::Busy) => Err(anyhow!(
            "{} interface busy — macOS kernel driver owns it (expected worst case)",
            label
        )),
        Err(rusb::Error::Access) => Err(anyhow!(
            "{} interface access denied — try sudo, or entitlement required",
            label
        )),
        Err(e) => Err(anyhow!("{} claim failed: {}", label, e)),
    }
}

fn probe_control_read<T: UsbContext>(handle: &DeviceHandle<T>) {
    let mut buf = [0u8; 64];
    match handle.read_control(
        0xA1,
        0x01, // GET_ENCAPSULATED_RESPONSE
        0x0000,
        0x0000,
        &mut buf,
        Duration::from_millis(200),
    ) {
        Ok(n) => println!("  ↩ control IN returned {} bytes", n),
        Err(e) => println!("  ↩ control IN test: {} (non-fatal)", e),
    }
}
