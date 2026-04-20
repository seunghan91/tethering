# M4 Data-Plane Silence — Investigation Log

## Symptom

After a fully successful RNDIS session handshake, the phone receives our
bulk OUT frames (no USB errors) but never emits any bulk IN frames in
response. Both `tcpdump`-style listening and active probes (ARP,
DHCPDISCOVER) come back empty.

```
  link status: CONNECTED (raw=0x00000000)
  link speed: 425984000 bps
  session up. phone MAC = 2a:01:af:63:c3:52
  listening on bulk IN 0x81 for 5s …
  → sent ARP who-has 192.168.42.129  (42 B)
  → sent DHCPDISCOVER xid=0xcafebabe  (342 B)
  0 frame(s) received
```

## What is verified

1. USB interface claim succeeds without sudo or entitlement.
2. RNDIS INITIALIZE negotiates `max_transfer_size = 15800 B`.
3. RNDIS SET `OID_GEN_CURRENT_PACKET_FILTER = 0x0F` returns success.
4. RNDIS QUERY `OID_GEN_MEDIA_CONNECT_STATUS` returns 0 (connected).
5. RNDIS QUERY `OID_GEN_LINK_SPEED` returns 4.26 Gbps/10 = 425 Mbps.
6. RNDIS QUERY `OID_802_3_PERMANENT_ADDRESS` returns 2a:01:af:63:c3:52.
7. `kernel_driver_active()` returns false on both IF 0 and IF 1 — macOS
   is NOT holding the interfaces hostage.
8. Bulk OUT writes report full byte count written, no errors.
9. PACKET_MSG framing matches Linux `drivers/net/usb/rndis_host.c`
   `rndis_tx_fixup()` byte-for-byte (44-byte header, DataOffset=36,
   MessageLength=unpadded, 4-byte pad only).

## Eliminated hypotheses

- ❌ Framing misalignment (tried 4-byte padding, no effect)
- ❌ Wrong endpoints (confirmed via descriptor walk)
- ❌ Wrong subnet in ARP target (DHCPDISCOVER is subnet-independent)
- ❌ macOS kernel driver competition (kernel_driver_active = false)
- ❌ Link-down on phone side (OID reports CONNECTED)
- ❌ Interface claim permission issue (claim succeeded)

## Remaining hypotheses (untested)

1. **Xiaomi firmware expects an INDICATE_STATUS ACK or some other control
   message before enabling data flow.** Unlike standard RNDIS, HyperOS
   may require the host to respond to a link-state indication that
   arrives on the interrupt endpoint (0x82).
2. **Phone expects us to query additional OIDs** before declaring the
   session live — e.g. `OID_GEN_MAXIMUM_FRAME_SIZE`,
   `OID_GEN_SUPPORTED_LIST`. Linux queries a handful of these during
   setup. We skipped them as "optional per spec" — maybe not for this
   device.
3. **macOS itself is swallowing the bulk IN frames at a level below
   libusb** despite `kernel_driver_active` returning false. The soft
   interface en25 with APIPA 169.254.x suggests SOME macOS-level RNDIS
   understanding exists on Apple Silicon (Catalina+ gained
   `AppleRNDISHost`?). Even if it's not "attached" as a claimable kernel
   driver, it might be sniffing packets off the bus before userspace.
4. **Phone's data path requires cellular data to have transmitted at
   least one packet on the cellular side before enabling the tether
   relay.** Worth testing by opening a browser on the phone and then
   repeating.
5. **Xiaomi RNDIS is actually broken at the data plane in this firmware
   build** and Linux works around it with some undocumented quirk. Would
   need to diff Linux's cdc_ether vs rndis_host behaviors on this VID:PID.

## Next-step investigation plan

Priority order, most informative first:

1. **Poll interrupt endpoint 0x82 in parallel with bulk IN.** If the
   phone is sending RESPONSE_AVAILABLE or INDICATE_STATUS_MSG
   notifications we're ignoring, that's a big clue.
2. **Query the full OID set Linux queries at startup.** Match rndis_host's
   `rndis_bind()` sequence exactly.
3. **Capture actual USB traffic with Wireshark + usbmon or macOS's
   built-in `wireshark + USBCAP`.** See whether the bulk IN pipe is truly
   silent on the wire or whether bytes are arriving and we're just not
   consuming them.
4. **Try the phone with a Linux VM (UTM)** where we know RNDIS works —
   if Linux gets DHCPOFFER while hardware/cable/firmware are identical,
   the bug is in our host-side code, not the phone.
5. **Cross-device comparison.** Borrow a Samsung/Pixel and run the same
   binary. If that one streams bulk IN immediately, the bug is
   Xiaomi-specific and we need a quirk.

## What's solid

Despite the silence, the RNDIS framing module (`src/rndis.rs`) implements
the full control plane correctly, and the encode/decode routines are
spec-compliant. Once we identify the missing handshake step or quirk,
the existing code will light up with no structural changes needed.
