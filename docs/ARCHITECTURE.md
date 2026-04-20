# Architecture

## 데이터 흐름

```
Xiaomi Redmi 14C                  Mac (Apple Silicon)
┌──────────────┐                  ┌─────────────────────────────────────┐
│ Modem        │                  │  Userspace daemon (Rust, root)      │
│   ↕ LTE      │                  │                                     │
│ Android IP   │                  │  ┌──────────┐      ┌─────────────┐  │
│   ↕          │   USB bulk OUT   │  │ libusb   │      │  RNDIS FSM  │  │
│ RNDIS driver │ ────────────────→│  │ claim IF │ ───→ │  init/oid   │  │
│   ↕          │                  │  └──────────┘      └─────────────┘  │
│ USB gadget   │   USB bulk IN    │       ↑                   ↓         │
└──────────────┘ ←────────────────│       │             ┌────────────┐  │
                                  │       │             │ IP packets │  │
                                  │       │             └────────────┘  │
                                  │       │                   ↓         │
                                  │       │             ┌────────────┐  │
                                  │       │             │ utun write │  │
                                  │       │             └────────────┘  │
                                  │       │                   ↓         │
                                  │  ┌──────────────────────────────┐   │
                                  │  │  macOS XNU networking stack  │   │
                                  │  │  (TCP/IP, route, PF)         │   │
                                  │  └──────────────────────────────┘   │
                                  │                   ↓                 │
                                  │            [ Safari, curl, ... ]    │
                                  └─────────────────────────────────────┘
```

## 스레드 모델

3개 비동기 태스크 (tokio):

1. **usb_reader**: `bulk_transfer(IN)` loop → RNDIS 디프레임 → channel send
2. **usb_writer**: channel recv ← utun reader → RNDIS 프레임 → `bulk_transfer(OUT)`
3. **utun_rw**: utun fd read/write 양방향

RNDIS control message (OID query/set)는 드문 이벤트라 별도 태스크 없이 init 시점에만 처리.

## RNDIS 메시지 타입 (최소 구현 셋)

| OID / MSG | 용도 | 구현 필요? |
|-----------|------|-----------|
| `REMOTE_NDIS_INITIALIZE_MSG` | 세션 시작 | ✅ 필수 |
| `REMOTE_NDIS_HALT_MSG` | 세션 종료 | ✅ 필수 |
| `REMOTE_NDIS_QUERY_MSG` (OID_GEN_CURRENT_PACKET_FILTER) | 필터 조회 | ⚠️ 일부 장치 요구 |
| `REMOTE_NDIS_SET_MSG` (OID_GEN_CURRENT_PACKET_FILTER = 0x0F) | 모든 패킷 수신 | ✅ 필수 |
| `REMOTE_NDIS_QUERY_MSG` (OID_802_3_PERMANENT_ADDRESS) | MAC 주소 | ✅ 필수 |
| `REMOTE_NDIS_PACKET_MSG` | 데이터 송수신 | ✅ 필수 |
| `REMOTE_NDIS_INDICATE_STATUS_MSG` | 연결 상태 변경 알림 | ⚠️ 처리만, ACK 불필요 |

## DHCP 단순화

자체 구현 (100 LOC):
1. DHCPDISCOVER 브로드캐스트 (랜덤 XID)
2. DHCPOFFER 수신 → server identifier, yiaddr 추출
3. DHCPREQUEST
4. DHCPACK → IP/mask/gateway/DNS/lease 확정

Xiaomi가 주는 전형적 값: `192.168.42.x/24`, gateway `192.168.42.129`, DNS `192.168.42.129`.

Lease renew는 생략 (프로세스 재시작으로 대체).

## 시스템 설정 변경

기동 시:
```
ifconfig utunN inet <yiaddr> <gateway> netmask 255.255.255.0 up
route add default <gateway> -ifscope utunN
networksetup -setdnsservers "Wi-Fi" <dns>  # 또는 resolver 파일
```

종료 시: 저장해둔 원상태로 복원.

## 오류 대응

| 상황 | 전략 |
|------|------|
| USB 연결 끊김 | 재enumerate, 5초 backoff, 재시도 |
| RNDIS init 실패 | OID 응답 덤프 로그 → 이슈 보고용 |
| DHCP 타임아웃 | 10초 × 3회 시도, 실패 시 exit |
| utun 생성 실패 | root 체크, 실패 시 즉시 exit |

## 파일 구조

```
src/
├── main.rs           # CLI entry, tokio runtime
├── usb.rs            # libusb wrapper, device discovery
├── rndis/
│   ├── mod.rs
│   ├── messages.rs   # 메시지 구조체 + 직렬화
│   ├── fsm.rs        # init/halt 상태머신
│   └── framing.rs    # 패킷 프레이밍
├── utun.rs           # utun 디바이스 생성/read/write
├── dhcp.rs           # 최소 DHCP 클라이언트
├── sysconfig.rs      # route, DNS 설정/복원
└── errors.rs
```
