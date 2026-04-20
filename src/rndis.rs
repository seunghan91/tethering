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
const MSG_INITIALIZE: u32 = 0x0000_0002;
const MSG_INITIALIZE_CMPLT: u32 = 0x8000_0002;
const MSG_QUERY: u32 = 0x0000_0004;
const MSG_QUERY_CMPLT: u32 = 0x8000_0004;
const MSG_SET: u32 = 0x0000_0005;
const MSG_SET_CMPLT: u32 = 0x8000_0005;

const STATUS_SUCCESS: u32 = 0x0000_0000;

// ── OIDs we speak ───────────────────────────────────────────────────
pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
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
