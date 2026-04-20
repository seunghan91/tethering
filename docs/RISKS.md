# Risks & Mitigations

## 🔴 High: USB Interface Claim 거부

**증상**: `libusb_claim_interface` → `LIBUSB_ERROR_ACCESS`

**원인**:
- macOS가 RNDIS 인터페이스에 기본 class driver를 이미 바인딩
- libusb가 `com.apple.developer.driverkit.*` entitlement 없이 detach 불가

**대응 순서**:
1. `libusb_set_auto_detach_kernel_driver(1)` 호출
2. 실패 시: 바이너리를 codesign + Info.plist에 `IOKitPersonalities` 추가
3. 최후: `kextunload` 불가능하므로 SystemExtension(dext)으로 전환 검토

**근거**: Linux에서는 `modprobe -r rndis_host` 한 방인데, macOS는 kernel driver가 설령 있어도 detach API가 제한적.

## 🟡 Med: RNDIS 펌웨어 비표준

**증상**: INITIALIZE_CMPLT 응답이 스펙과 다른 바이트

**원인**: Xiaomi의 RNDIS 구현이 마이크로소프트 스펙 v2를 완전히 따르지 않을 수 있음

**대응**: 모든 메시지 raw hex 덤프 + Linux kernel `rndis_host.c` 와 대조. 필요 시 quirk 플래그 추가.

## 🟡 Med: Ethernet 레이어 처리

**증상**: utun은 L3인데 RNDIS는 L2 → ARP 처리 필요

**대응**:
- 옵션 A: 미니 ARP 스택 (ARP request 오면 우리가 만든 가짜 MAC로 응답)
- 옵션 B: `feth` (fake ethernet) 디바이스 사용 — L2 그대로 통과, 하지만 문서 적고 불안정
- **선택**: 옵션 A. ARP는 50 LOC면 충분.

## 🟡 Med: DHCP Race

**증상**: RNDIS init 직후 DHCP 너무 빨리 보내면 폰이 아직 NAT 준비 안 됨

**대응**: INITIALIZE_CMPLT 받고 500ms 대기 후 DHCPDISCOVER 시작.

## 🟢 Low: 성능

**우려**: userspace는 컨텍스트 스위치가 많음

**현실**: LTE 업/다운 합쳐 50Mbps 내외 → Rust + 512바이트 bulk 버퍼면 CPU < 5%. 전혀 문제 안 됨.

## 🟢 Low: Code signing for distribution

**현실**: 본인 맥에서만 쓰면 `sudo ./tethering`으로 끝. 배포하려면 Developer ID 서명 필요하지만 지금은 비목표.

## 🔴 High: 절대 실패 시나리오

**만약 M2에서 claim이 절대 안 되면**: 이 아키텍처 자체가 막힘. 그 경우 fallback:
- UTM Linux VM + USB passthrough (이미 검토한 방법)
- DriverKit System Extension으로 전환 (개발자 계정 + dext entitlement 승인 필요, 진입장벽 높음)

**판단 기준**: M2를 하루 안에 못 뚫으면 아키텍처 재검토.
