# Milestones

검증 가능한 최소 단위로 쪼갠다. 각 마일스톤 끝나면 **직접 확인 가능한 산출물**이 있어야 함.

## M1 — USB Discovery (반나절)

**목표**: Xiaomi가 꽂혀있으면 식별하고 RNDIS 인터페이스를 찾는다.

**산출물**:
```bash
$ sudo ./tethering scan
Found Xiaomi Redmi 14C (2717:ff88)
  Configuration 1:
    Interface 0: RNDIS Control (class=0xE0, subclass=0x01, protocol=0x03)
    Interface 1: RNDIS Data (class=0x0A, subclass=0x00, protocol=0x00)
      Endpoint 0x81 (bulk IN,  512B)
      Endpoint 0x01 (bulk OUT, 512B)
    Interface 2: ADB (...)
```

**검증**: 출력 확인 + `system_profiler SPUSBDataType` 와 대조.

## M2 — Claim & Detach (반나절)

**목표**: RNDIS 인터페이스를 다른 드라이버에서 뺏어와 독점.

**위험**: macOS는 kernel driver가 이미 claim 중이면 `LIBUSB_ERROR_ACCESS` 반환.
Entitlement 또는 `com.apple.developer.driverkit.transport.usb` 필요할 수 있음.
→ 먼저 `libusb_detach_kernel_driver` 시도, 안 되면 Info.plist / codesign 조정.

**산출물**: 에러 없이 bulk endpoint에 read/write 가능.

## M3 — RNDIS Handshake (1일)

**목표**: 장치와 세션 협상 완료.

**시퀀스**:
1. INITIALIZE_MSG (MessageType=0x00000002)
2. INITIALIZE_CMPLT 수신 → MaxTransferSize 저장
3. SET_MSG(OID_GEN_CURRENT_PACKET_FILTER=0x0F)
4. SET_CMPLT 수신
5. QUERY_MSG(OID_802_3_PERMANENT_ADDRESS)
6. QUERY_CMPLT 수신 → 폰의 MAC 저장

**산출물**: 로그에 폰 MAC 주소 출력. 이 시점에서 폰은 "연결됨" 상태로 인식.

## M4 — Packet I/O (1일)

**목표**: 원시 이더넷 프레임을 양방향으로 주고받는다.

**테스트**: RNDIS PACKET_MSG를 파싱해서 페이로드를 pcap 파일로 덤프.
→ Wireshark에서 DHCPDISCOVER가 폰으로부터 오는지 확인 (폰이 먼저 우리한테 DHCP 브로드캐스트 안 보냄 — 우리가 보내야 함).

## M5 — utun Bridge (반나절)

**목표**: utun 생성 + bulk IN의 payload를 utun에 write, utun read를 bulk OUT으로 write.

**유의**: RNDIS PACKET_MSG payload는 **이더넷 프레임 (L2)**. utun은 **L3 (IP only)**.
→ Ethernet 헤더 14바이트를 벗겨서 utun에, 반대 방향은 씌워서 RNDIS로.
→ ARP도 우리가 처리해야 함: 폰이 우리 MAC 물으면 응답 (feth 또는 자체 ARP 스택).

**대안**: utun 대신 `feth` (fake ethernet)를 쓰면 L2 그대로 통과 → ARP 자동 처리.
하지만 feth는 문서화 미흡. 일단 utun + 미니 ARP 핸들러로 진행.

**산출물**: `ifconfig utun10` 에 `fe80::` link-local 표시. `tcpdump -i utun10` 에 트래픽 흐름.

## M6 — DHCP Client (1일)

**목표**: 폰으로부터 IP/gateway/DNS 획득.

**구현**: DHCPDISCOVER → OFFER → REQUEST → ACK 루프.
`dhcproto` 크레이트 사용 또는 raw bytes 직접 조립.

**산출물**: 로그에 `Acquired 192.168.42.2 via 192.168.42.129, DNS 192.168.42.129`.

## M7 — System Config (반나절)

**목표**: 기본 게이트웨이 전환 + DNS 설정 + 종료 시 원복.

**명령**:
```bash
ifconfig utun10 inet 192.168.42.2 192.168.42.129 netmask 255.255.255.0 up
route change default 192.168.42.129
# 백업: 기존 default gateway 기억
```

**산출물**: `curl ifconfig.me` 결과가 폰 셀룰러 IP로 바뀜.

## M8 — Packaging & UX (반나절)

- `./tethering up` / `./tethering down` / `./tethering status`
- launchd plist로 USB plug 감지 시 자동 기동 (선택)
- 로그: `/tmp/tethering.log`
- Ctrl+C 시 clean teardown (route 복원, utun 제거)

## 전체 예상 공수

혼자 하면 **3~5일 집중 작업**. 단계별로 막히면 RNDIS 스펙 재해석이 가장 시간 많이 먹음.

최악의 리스크: M2 Claim 단계에서 Entitlement 벽에 막히면 codesign 설정까지 필요 → 별도 하루.
