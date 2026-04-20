# tethering — Userspace RNDIS USB Tethering for Apple Silicon macOS

**극악의 환경(Wi-Fi 차단, Apple Silicon, kext 봉쇄) 전용 경량 USB 테더링 데몬**

## Why

- Xiaomi HyperOS 등 RNDIS only 안드로이드 + macOS Apple Silicon 조합은 현재 상용/오픈소스 해법 없음
- HoRNDIS는 kext 기반이라 macOS Ventura+에서 사실상 사장
- 해법: **완전 userspace** (libusb + utun + 사용자모드 DHCP)

## Target

- macOS 15+ / Apple Silicon (arm64)
- RNDIS 기반 안드로이드 폰 (Xiaomi, 구 삼성 등)
- 단일 디바이스 테더링 (멀티 디바이스 비목표)
- 경량: 바이너리 < 2MB, 메모리 < 20MB, root 1회

## Non-Goals

- GUI (CLI + launchd plist만)
- CDC-ECM/NCM 지원 (그쪽은 macOS 네이티브로 됨)
- Windows/Linux 지원 (Linux는 이미 RNDIS 커널 지원)
- 고성능 튜닝 (셀룰러 속도 상한 < 100Mbps라 userspace로 충분)

## Stack

- **언어**: Rust (메모리 안전 + libusb/tun 크레이트 성숙)
- **USB**: `rusb` (libusb 1.0 바인딩)
- **가상 NIC**: `tun` crate → macOS `utun` 디바이스
- **DHCP 클라이언트**: 자체 구현 (단순) 또는 `dhcproto` 파싱 + 직접 소켓
- **빌드**: `cargo build --release`

## Milestones

- [x] **M1 — Discovery**: Xiaomi USB 디바이스 enumerate, RNDIS interface descriptor 파싱
- [x] **M2 — Claim**: USB interface claim, endpoint 열기 (control/bulk in/bulk out)
- [x] **M3 — RNDIS init**: INITIALIZE / SET_FILTER / QUERY_MAC 핸드셰이크
- [🛑] **M4 — Packet I/O**: PACKET_MSG 프레이밍 완성. 데이터 플레인 **완전 무음** — 0 프레임 / 0 에러. macOS USB 서브시스템이 하위에서 bulk IN을 삼키는 것으로 추정(H1) vs HyperOS 펌웨어 게이트(H2). UTM Linux VM 대조 실험으로 결정 필요 — [investigation log](docs/INVESTIGATION-M4.md)
- [ ] **M5 — utun bridge**: utun 생성, 양방향 패킷 포워딩
- [ ] **M6 — DHCP**: DHCPDISCOVER/REQUEST, IP/gateway/DNS 획득
- [ ] **M7 — System config**: `route add`, `/etc/resolv.conf` 갱신, 종료 시 복원
- [ ] **M8 — Packaging**: launchd plist, `sudo tethering up/down` CLI

## Verified on real hardware

Xiaomi Redmi 14C (VID:PID `2717:ff88`) against macOS 26.4.1 / Apple Silicon:

```
$ ./target/release/tethering init
target: 2717:ff88
  ✔ claimed control IF #0 and data IF #1
  ✔ INITIALIZE ok — max_transfer_size = 15800 B
  ✔ SET OID_GEN_CURRENT_PACKET_FILTER = 0x0000000f
  ✔ QUERY OID_802_3_PERMANENT_ADDRESS → 2a:01:af:63:c3:52
✅ RNDIS session ready
```

No sudo. No entitlement. No kext. Pure userspace.

## References

- Linux kernel: `drivers/net/usb/rndis_host.c`, `cdc_ether.c`
- Microsoft RNDIS spec: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/remote-ndis--rndis-2
- HoRNDIS source (kext reference): https://github.com/jwise/HoRNDIS
- macOS utun: `/usr/include/net/if_utun.h`
- rusb: https://docs.rs/rusb/latest/rusb/
- tun crate: https://docs.rs/tun/latest/tun/

## Warning

- RNDIS interface claim 시 macOS 기본 드라이버(없지만 디버그용 class driver)에서 **kernel detach** 필요할 수 있음
- root 권한 필수 (utun 생성 + 라우팅 테이블 수정)
- Xiaomi 펌웨어마다 RNDIS OID 응답이 미묘하게 달라서 디바이스별 테스트 필요
