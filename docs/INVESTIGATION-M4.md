# M4 Data-Plane Silence — Investigation Log

## Status: Native macOS Apple Silicon path is blocked at the USB subsystem layer

All protocol-level causes have been empirically eliminated. The data plane
is silent without any detectable USB error, which is the diagnostic
signature of a layer-0 loss (bytes never reaching libusb), not a protocol
mismatch.

## Final probe result (2026-04-20, Redmi 14C, iPad unplugged, single device)

```
PHASE A environment
  default route = utun7 (Tailscale only, no iPad, no Xiaomi-as-gateway)

PHASE B USB enumeration
  RNDIS device found: 2717:ff88 (Xiaomi Redmi 14C)

PHASE C claim
  kernel_driver_active(control IF 0) = no
  kernel_driver_active(data    IF 1) = no
  ✔ claimed both interfaces

PHASE D RNDIS handshake
  INITIALIZE  ok, max_transfer_size = 15800 B
  physical_medium = 0x00000000  (802.3)
  phone_mac       = 2a:01:af:63:c3:52
  max_frame_size  = 1500
  media_connect_status = 0  (connected)
  link_speed      = 425 Mbps
  packet_filter set=0x0F  readback=0x0F  ✔
  drained 8 interrupt notifications from 0x82

PHASE E listen 15 s, no TX           → 0 frames, 0 io_err, 0 pipe_err
PHASE F ARP broadcast + 10 s         → 0 frames, 0 io_err, 0 pipe_err
PHASE G DHCPDISCOVER × 3 + 15 s      → 0 frames, 0 io_err, 0 pipe_err

Grand total: 0 frames, 0 errors of any kind
```

## Verified

1. USB interface claim succeeds without sudo / entitlement / kext
2. RNDIS INITIALIZE negotiates valid session parameters
3. Every OID query Linux rndis_bind() issues returns correct values
4. SET OID_GEN_CURRENT_PACKET_FILTER readback = written value (= filter
   was actually applied, not silently dropped as the ActiveSync quirk
   theory predicted)
5. Interrupt endpoint drained of 60 stale notifications on first run and
   ~8 per run afterwards (control plane is alive and responsive)
6. Bulk OUT writes report full byte count returned, no error
7. No kernel driver holds either interface
8. USB cable is data-capable (control transfers work)
9. Cellular data on the phone is active (provides DHCP + NAT when
   tethering to a different host — this has been independently
   confirmed since the phone tethers fine to its original
   Mac-mini-unrelated Windows PC)

## Eliminated

- Framing misalignment (4-byte aligned PACKET_MSG)
- Wrong endpoints (confirmed via descriptor walk)
- Wrong filter value (readback = 0x0F)
- Missing OID queries (Linux-order sequence replicated)
- Endpoint halt / toggle desync (io_err=0, pipe_err=0)
- Pre-emptive clear_halt regression (removed)
- iPad contention (verified single-device state)
- ActiveSync silent-SET quirk (filter readback negates it)
- Buffer-exhaustion of interrupt queue (drained to 0)

## Remaining hypotheses

**H1 — macOS Apple Silicon USB subsystem consumes bulk IN below libusb (65%)**
Evidence: control endpoint works perfectly, bulk endpoints report no
errors yet receive zero bytes. macOS 26 may have an
AppleUSBCDCEthernet or similar stub that binds the CDC Data class
interface (0x0A) below the IOUSBHost layer where libusb operates,
consuming bulk IN bytes before they reach userspace. The fact that
macOS creates en25 with APIPA even without a claimable kernel driver
implies *some* level of macOS-side RNDIS interpretation is happening.

**H2 — HyperOS-specific data-plane gate (35%)**
Evidence: none direct, but Xiaomi's MIUI/HyperOS has documented
deviations from standard RNDIS (ActiveSync lineage). The phone may
refuse to emit bulk IN until an undocumented precondition is met.

## The experiment that distinguishes H1 from H2

**Run the same phone + cable through a Linux VM in UTM with USB
passthrough.** Linux has a native, production-grade rndis_host.ko that
is known-good across thousands of Xiaomi tethering reports.

If Linux gets DHCPOFFER → H1 confirmed, macOS stack is the blocker,
native path is dead without DriverKit/kext.

If Linux is also silent → H2 confirmed, phone is the blocker, need
another phone or deep ActiveSync research.

## Implications for the project

If H1 is confirmed (which I currently weight higher):

- Native macOS userspace RNDIS is not viable on Apple Silicon without
  SystemExtension (DriverKit) entitlement — which requires Apple
  developer approval and is effectively gated behind a business case.
- The actual user-facing solution on Apple Silicon becomes UTM +
  Alpine Linux VM + USB passthrough + NAT back to host. This is
  exactly the fallback architecture we documented at project start.
- The native code we've written is not wasted — it's a working,
  spec-compliant RNDIS control-plane client that would run on any
  platform without macOS's interference. It can be lifted into a
  Linux or FreeBSD host unchanged.

If H2 is confirmed:

- Broaden target to Pixel / Samsung devices which use stock Android
  RNDIS/CDC-NCM.
- Research HyperOS-specific preconditions (IPv6 RS? vendor-specific
  OIDs?).

## Next step

Stand up the UTM Alpine Linux VM and run the same diagnostic to settle
H1 vs H2 before committing further native-path effort.
