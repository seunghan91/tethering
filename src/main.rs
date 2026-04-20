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
        other => Err(anyhow!("unknown command: {} (use: scan | claim | init)", other)),
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
