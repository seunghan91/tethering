//! Minimal RNDIS control plane over USB.
//!
//! Enough to complete the session handshake (INITIALIZE), enable promiscuous-ish
//! packet reception (SET OID_GEN_CURRENT_PACKET_FILTER), and read the phone's
//! ethernet MAC (QUERY OID_802_3_PERMANENT_ADDRESS). Data plane (PACKET_MSG on
//! the bulk endpoints) is a later milestone.
//!
//! Wire format reference: MS-RNDIS §2.2.x, and Linux drivers/net/usb/rndis_host.c
//! for quirks. All integers little-endian.

use anyhow::{anyhow, bail, Context, Result};
use rusb::{DeviceHandle, UsbContext};
use std::time::Duration;

// ── Message type codes ──────────────────────────────────────────────
const MSG_PACKET: u32 = 0x0000_0001;
const MSG_INITIALIZE: u32 = 0x0000_0002;
const MSG_INITIALIZE_CMPLT: u32 = 0x8000_0002;
const MSG_QUERY: u32 = 0x0000_0004;
const MSG_QUERY_CMPLT: u32 = 0x8000_0004;
const MSG_SET: u32 = 0x0000_0005;
const MSG_SET_CMPLT: u32 = 0x8000_0005;

const STATUS_SUCCESS: u32 = 0x0000_0000;

// ── OIDs we speak ───────────────────────────────────────────────────
pub const OID_GEN_SUPPORTED_LIST: u32 = 0x0001_0101;
pub const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x0001_0106;
pub const OID_GEN_LINK_SPEED: u32 = 0x0001_0107; // in 100 bps units
pub const OID_GEN_MAXIMUM_TOTAL_SIZE: u32 = 0x0001_010B;
pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
pub const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114; // 0=connected, 1=disconnected
pub const OID_GEN_PHYSICAL_MEDIUM: u32 = 0x0001_0202;
pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;

// ── Packet filter bit flags (OID_GEN_CURRENT_PACKET_FILTER) ─────────
pub const FILTER_DIRECTED: u32 = 0x0000_0001;
pub const FILTER_MULTICAST: u32 = 0x0000_0002;
pub const FILTER_ALL_MULTICAST: u32 = 0x0000_0004;
pub const FILTER_BROADCAST: u32 = 0x0000_0008;
pub const FILTER_NORMAL: u32 =
    FILTER_DIRECTED | FILTER_MULTICAST | FILTER_ALL_MULTICAST | FILTER_BROADCAST;

// ── CDC class control transfer request codes ────────────────────────
const REQ_SEND_ENCAPSULATED_COMMAND: u8 = 0x00; // bmRequestType = 0x21 (OUT|Class|Interface)
const REQ_GET_ENCAPSULATED_RESPONSE: u8 = 0x01; // bmRequestType = 0xA1 (IN|Class|Interface)

// Max expected response size. MS spec caps structured responses well under 1K.
const MAX_RESPONSE: usize = 1024;

pub struct Session<'a, T: UsbContext> {
    handle: &'a DeviceHandle<T>,
    iface: u8,
    next_rid: u32,
    /// Negotiated during INITIALIZE. Upper bound on any single bulk transfer we
    /// may send to the device (RNDIS + ethernet frame + padding).
    pub max_transfer_size: u32,
}

impl<'a, T: UsbContext> Session<'a, T> {
    /// Runs INITIALIZE handshake. On success, the session is ready for set/query.
    pub fn open(handle: &'a DeviceHandle<T>, control_iface: u8) -> Result<Self> {
        let mut s = Self {
            handle,
            iface: control_iface,
            next_rid: 1,
            max_transfer_size: 0,
        };
        s.initialize().context("RNDIS INITIALIZE handshake")?;
        Ok(s)
    }

    fn rid(&mut self) -> u32 {
        let r = self.next_rid;
        self.next_rid = self.next_rid.wrapping_add(1).max(1);
        r
    }

    fn initialize(&mut self) -> Result<()> {
        let rid = self.rid();
        // REMOTE_NDIS_INITIALIZE_MSG — 24 bytes
        let mut msg = Vec::with_capacity(24);
        msg.extend_from_slice(&MSG_INITIALIZE.to_le_bytes()); //  0: MessageType
        msg.extend_from_slice(&24u32.to_le_bytes()); //  4: MessageLength
        msg.extend_from_slice(&rid.to_le_bytes()); //  8: RequestID
        msg.extend_from_slice(&1u32.to_le_bytes()); // 12: MajorVersion
        msg.extend_from_slice(&0u32.to_le_bytes()); // 16: MinorVersion
        msg.extend_from_slice(&0x4000u32.to_le_bytes()); // 20: MaxTransferSize hint (16 KB)

        self.send(&msg)?;
        let resp = self.recv()?;

        if resp.len() < 40 {
            bail!("INITIALIZE_CMPLT truncated: {} B, dump={}", resp.len(), hex(&resp));
        }
        let msg_type = u32_at(&resp, 0);
        if msg_type != MSG_INITIALIZE_CMPLT {
            bail!(
                "unexpected response type 0x{:08x} (expected INITIALIZE_CMPLT). dump={}",
                msg_type,
                hex(&resp)
            );
        }
        let resp_rid = u32_at(&resp, 8);
        if resp_rid != rid {
            bail!("RequestID mismatch: sent {}, got {}", rid, resp_rid);
        }
        let status = u32_at(&resp, 12);
        if status != STATUS_SUCCESS {
            bail!("INITIALIZE failed, status = 0x{:08x}", status);
        }
        // MaxTransferSize is at offset 36 in the complete message.
        //   0  msg_type        16 major     32 max_pkts_per_xfer
        //   4  msg_len         20 minor     36 max_transfer_size
        //   8  request_id      24 dev_flags 40 packet_align_factor
        //  12  status          28 medium
        self.max_transfer_size = u32_at(&resp, 36);
        Ok(())
    }

    /// REMOTE_NDIS_SET_MSG with an OID and its in-memory value.
    pub fn set_oid(&mut self, oid: u32, value: &[u8]) -> Result<()> {
        let rid = self.rid();
        let hdr_len: u32 = 28;
        let total = hdr_len + value.len() as u32;
        let mut msg = Vec::with_capacity(total as usize);
        msg.extend_from_slice(&MSG_SET.to_le_bytes()); //  0
        msg.extend_from_slice(&total.to_le_bytes()); //  4
        msg.extend_from_slice(&rid.to_le_bytes()); //  8
        msg.extend_from_slice(&oid.to_le_bytes()); // 12
        msg.extend_from_slice(&(value.len() as u32).to_le_bytes()); // 16 InformationBufferLength
        msg.extend_from_slice(&20u32.to_le_bytes()); // 20 InformationBufferOffset (from RequestID)
        msg.extend_from_slice(&0u32.to_le_bytes()); // 24 DeviceVcHandle (reserved, 0)
        msg.extend_from_slice(value); // 28+

        self.send(&msg)?;
        let resp = self.recv()?;
        if resp.len() < 16 {
            bail!("SET_CMPLT truncated: {} B, dump={}", resp.len(), hex(&resp));
        }
        let msg_type = u32_at(&resp, 0);
        if msg_type != MSG_SET_CMPLT {
            bail!("expected SET_CMPLT, got 0x{:08x}. dump={}", msg_type, hex(&resp));
        }
        let status = u32_at(&resp, 12);
        if status != STATUS_SUCCESS {
            bail!("SET oid 0x{:08x} failed, status = 0x{:08x}", oid, status);
        }
        Ok(())
    }

    /// REMOTE_NDIS_QUERY_MSG. Returns the InformationBuffer bytes verbatim.
    pub fn query_oid(&mut self, oid: u32) -> Result<Vec<u8>> {
        let rid = self.rid();
        let mut msg = Vec::with_capacity(28);
        msg.extend_from_slice(&MSG_QUERY.to_le_bytes()); //  0
        msg.extend_from_slice(&28u32.to_le_bytes()); //  4
        msg.extend_from_slice(&rid.to_le_bytes()); //  8
        msg.extend_from_slice(&oid.to_le_bytes()); // 12
        msg.extend_from_slice(&0u32.to_le_bytes()); // 16 InformationBufferLength (0 for query)
        msg.extend_from_slice(&0u32.to_le_bytes()); // 20 InformationBufferOffset
        msg.extend_from_slice(&0u32.to_le_bytes()); // 24 DeviceVcHandle

        self.send(&msg)?;
        let resp = self.recv()?;
        if resp.len() < 24 {
            bail!("QUERY_CMPLT truncated: {} B, dump={}", resp.len(), hex(&resp));
        }
        let msg_type = u32_at(&resp, 0);
        if msg_type != MSG_QUERY_CMPLT {
            bail!("expected QUERY_CMPLT, got 0x{:08x}. dump={}", msg_type, hex(&resp));
        }
        let status = u32_at(&resp, 12);
        if status != STATUS_SUCCESS {
            bail!("QUERY oid 0x{:08x} failed, status = 0x{:08x}", oid, status);
        }
        let info_len = u32_at(&resp, 16) as usize;
        let info_off = u32_at(&resp, 20) as usize;
        // InformationBufferOffset is measured from the start of the RequestID
        // field (byte 8), per MS-RNDIS §2.2.11.
        let start = 8 + info_off;
        let end = start
            .checked_add(info_len)
            .ok_or_else(|| anyhow!("QUERY offset overflow"))?;
        if end > resp.len() {
            bail!(
                "QUERY info buffer out of range: start={}, len={}, total={}",
                start,
                info_len,
                resp.len()
            );
        }
        Ok(resp[start..end].to_vec())
    }

    fn send(&self, payload: &[u8]) -> Result<()> {
        let n = self
            .handle
            .write_control(
                0x21, // OUT | Class | Interface
                REQ_SEND_ENCAPSULATED_COMMAND,
                0,
                self.iface as u16,
                payload,
                Duration::from_millis(1000),
            )
            .context("SEND_ENCAPSULATED_COMMAND")?;
        if n != payload.len() {
            bail!("short control write: {}/{}", n, payload.len());
        }
        Ok(())
    }

    /// Poll for a response. RNDIS is asynchronous — after SEND_ENCAPSULATED,
    /// the device posts a RESPONSE_AVAILABLE notification on the interrupt
    /// endpoint. We skip the interrupt path for simplicity and just poll
    /// GET_ENCAPSULATED_RESPONSE every 20ms until bytes arrive or we give up.
    fn recv(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_RESPONSE];
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);

        while std::time::Instant::now() < deadline {
            let res = self.handle.read_control(
                0xA1, // IN | Class | Interface
                REQ_GET_ENCAPSULATED_RESPONSE,
                0,
                self.iface as u16,
                &mut buf,
                Duration::from_millis(200),
            );
            match res {
                Ok(n) if n > 0 => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(_) | Err(rusb::Error::Pipe) | Err(rusb::Error::Timeout) => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(e) => return Err(e).context("GET_ENCAPSULATED_RESPONSE"),
            }
        }
        Err(anyhow!("RNDIS response timeout after 1.5s"))
    }
}

// ── helpers ─────────────────────────────────────────────────────────

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

// ─────────────────────────────────────────────────────────────────────
// Data plane — REMOTE_NDIS_PACKET_MSG on the bulk endpoints.
//
// Wire format (little-endian):
//   offset  field
//        0  MessageType         0x00000001
//        4  MessageLength       total including ethernet payload
//        8  DataOffset          from start of this field to ethernet frame
//       12  DataLength          ethernet frame byte count
//       16  OOBDataOffset       unused (0)
//       20  OOBDataLength       0
//       24  NumOOBDataElements  0
//       28  PerPacketInfoOffset 0
//       32  PerPacketInfoLength 0
//       36  DeviceVcHandle      0
//       40  Reserved            0
//       44  <ethernet frame>
//
// A single bulk transfer can carry multiple PACKET_MSGs back-to-back. Each
// chunk is self-describing via MessageLength, so we walk until we run out
// of bytes.

pub const PACKET_HEADER_LEN: usize = 44;

/// Wrap a raw ethernet frame in a PACKET_MSG. Returns bytes ready for bulk OUT.
///
/// MS-RNDIS §2.2.1 requires each message to be a multiple of 4 bytes.
/// MessageLength in the header stays the unpadded value (matches Linux
/// rndis_host behavior); trailing zero padding is just filler.
pub fn encode_packet(frame: &[u8]) -> Vec<u8> {
    let total = PACKET_HEADER_LEN + frame.len();
    let padded = (total + 3) & !3;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(&MSG_PACKET.to_le_bytes()); //  0
    out.extend_from_slice(&(total as u32).to_le_bytes()); //  4 MessageLength (unpadded)
    out.extend_from_slice(&(PACKET_HEADER_LEN as u32 - 8).to_le_bytes()); //  8 DataOffset = 36
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // 12 DataLength
    out.extend_from_slice(&[0u8; PACKET_HEADER_LEN - 16]); // 16..44 all zero
    out.extend_from_slice(frame);
    out.resize(padded, 0);
    out
}

/// Parse one or more PACKET_MSGs out of a bulk IN buffer. Non-PACKET messages
/// (e.g. INDICATE_STATUS) are skipped with a log line, never fatal.
pub fn decode_packets(buf: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos + 8 <= buf.len() {
        let msg_type = u32_at(buf, pos);
        let msg_len = u32_at(buf, pos + 4) as usize;
        if msg_len < 8 || pos + msg_len > buf.len() {
            bail!(
                "malformed RNDIS chunk at {}: type=0x{:08x} len={} (buf={})",
                pos,
                msg_type,
                msg_len,
                buf.len()
            );
        }
        let chunk = &buf[pos..pos + msg_len];
        if msg_type == MSG_PACKET {
            if chunk.len() < PACKET_HEADER_LEN {
                bail!("PACKET_MSG truncated: {} B", chunk.len());
            }
            let data_off = u32_at(chunk, 8) as usize;
            let data_len = u32_at(chunk, 12) as usize;
            let start = 8 + data_off;
            let end = start
                .checked_add(data_len)
                .ok_or_else(|| anyhow!("PACKET_MSG length overflow"))?;
            if end > chunk.len() {
                bail!(
                    "PACKET_MSG data out of range: start={}, len={}, chunk={}",
                    start,
                    data_len,
                    chunk.len()
                );
            }
            frames.push(chunk[start..end].to_vec());
        } else {
            // Non-PACKET control on the data pipe is unusual but harmless to
            // ignore. Log to stderr in case it hints at a firmware quirk.
            eprintln!(
                "    ↯ skipped non-PACKET chunk on data pipe: type=0x{:08x} len={}",
                msg_type, msg_len
            );
        }
        pos += msg_len;
    }
    Ok(frames)
}

pub fn read_bulk_frames<T: UsbContext>(
    handle: &DeviceHandle<T>,
    ep_in: u8,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>> {
    let mut buf = vec![0u8; 16 * 1024];
    match handle.read_bulk(ep_in, &mut buf, timeout) {
        Ok(n) if n > 0 => {
            buf.truncate(n);
            decode_packets(&buf)
        }
        Ok(_) => Ok(Vec::new()),
        Err(rusb::Error::Timeout) => Ok(Vec::new()),
        Err(e) => Err(anyhow!("bulk IN read failed: {}", e)),
    }
}

// ── Interrupt endpoint notification drain ───────────────────────────
//
// MS-RNDIS §2.1.2.1: the device posts an 8-byte RESPONSE_AVAILABLE
// notification on the interrupt IN endpoint whenever it has a control
// response ready. Format:
//   bytes 0..4  : 0x00000001  (RESPONSE_AVAILABLE)
//   bytes 4..8  : 0x00000000  (reserved)
//
// The spec warns that a device may buffer-exhaust and stop responding on
// bulk IN if the host ignores these notifications for too long. That
// matches our Redmi 14C symptom. Drain any pending notifications once,
// then consume the paired encapsulated response via the control pipe.
// Returns the number of notifications actually drained.

const NOTIFY_RESPONSE_AVAILABLE: u32 = 0x0000_0001;

pub fn drain_interrupt_notifications<T: UsbContext>(
    handle: &DeviceHandle<T>,
    ctrl_iface: u8,
    intr_ep: u8,
) -> Result<usize> {
    let mut buf = [0u8; 8];
    let mut drained = 0;
    loop {
        match handle.read_interrupt(intr_ep, &mut buf, Duration::from_millis(100)) {
            Ok(n) if n >= 4 => {
                let ty = u32_at(&buf[..n], 0);
                if ty == NOTIFY_RESPONSE_AVAILABLE {
                    // Consume the paired response from control pipe.
                    let mut rsp = [0u8; 1024];
                    let got = handle.read_control(
                        0xA1,
                        REQ_GET_ENCAPSULATED_RESPONSE,
                        0,
                        ctrl_iface as u16,
                        &mut rsp,
                        Duration::from_millis(200),
                    );
                    match got {
                        Ok(n) if n >= 4 => {
                            let msg_type = u32_at(&rsp[..n], 0);
                            let label = match msg_type {
                                0x8000_0002 => "INITIALIZE_CMPLT",
                                0x8000_0004 => "QUERY_CMPLT",
                                0x8000_0005 => "SET_CMPLT",
                                0x0000_0007 => "INDICATE_STATUS",
                                _ => "?",
                            };
                            if drained < 3 {
                                println!(
                                    "    ⇠ drained [{}] {} B  type=0x{:08x}  {}",
                                    drained + 1,
                                    n,
                                    msg_type,
                                    label
                                );
                            }
                        }
                        Ok(n) => {
                            if drained < 3 {
                                println!("    ⇠ drained [{}] {} B (short)", drained + 1, n);
                            }
                        }
                        Err(e) => {
                            if drained < 3 {
                                println!("    ⇠ drained [{}] notif but no response ({})", drained + 1, e);
                            }
                        }
                    }
                    drained += 1;
                } else {
                    eprintln!("    ⇠ unknown interrupt notification type=0x{:08x}", ty);
                    drained += 1;
                }
            }
            Ok(_) => break,
            Err(rusb::Error::Timeout) => break,
            Err(e) => return Err(anyhow!("interrupt read failed: {}", e)),
        }
    }
    Ok(drained)
}

pub fn write_bulk_frame<T: UsbContext>(
    handle: &DeviceHandle<T>,
    ep_out: u8,
    frame: &[u8],
) -> Result<()> {
    let msg = encode_packet(frame);
    let n = handle
        .write_bulk(ep_out, &msg, Duration::from_millis(1000))
        .context("bulk OUT write")?;
    if n != msg.len() {
        bail!("short bulk write: {}/{}", n, msg.len());
    }
    Ok(())
}

pub fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex(buf: &[u8]) -> String {
    buf.iter()
        .take(64)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
