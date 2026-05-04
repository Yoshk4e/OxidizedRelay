# OxidizedRelay

A high-performance CLI tool for decrypting and parsing ChaCha20-encrypted protobuf game-protocol traffic from PCAP captures.

---

## Table of Contents

- [Overview](#overview)
- [Encryption Scheme](#encryption-scheme)
  - [Wire Frame Layout](#wire-frame-layout)
  - [CSHead Schema](#cshead-schema)
- [Building](#building)
- [Usage](#usage)
  - [Arguments](#arguments)
  - [Options](#options)
- [Examples](#examples)
- [Output Format](#output-format)
- [How Frame Filtering Works](#the-process-of-frame-filtering)
- [Proto Schema Loading](#proto-schema-loading)
- [Supported Link Types](#supported-link-types)
- [Plans](#plans)
- [License](#license)

---

## Overview

OxidizedRelay stitches together TCP connections from the provided .pcap file, decodes the payload of each frame with ChaCha20 encryption (RFC 7539) based on the stream's key, analyzes the binary protocol format and CSHead protocol buffer header, verifies the integrity of the body through CRC validation, and prints out the output in a readable manner, optionally mapping the fields to your own .proto schema file.

---

## Encryption Scheme

| Parameter | Value |
|-----------|-------|
| Cipher | ChaCha20 (RFC 7539) |
| Key length | 32 bytes |
| Nonce length | 12 bytes |
| First block index | 1 (index 0 is reserved, AEAD standard) |
| Keystream generation | Continuous across TCP direction (not new for each frame) |

### Wire Frame Layout

```
┌──────┬─────────────────┬─────────────────────────────┐
│  hl  │  bl  (u16 LE)   │  head[hl]  ||  body[bl]     │
│ (u8) │                 │  ← encrypted together ──►    │
└──────┴─────────────────┴─────────────────────────────┘
```

- `hl`: length of the CSHead protobuf section
- `bl`: length of the message body
- head + body are concatenated and XOR'd with the current keystream position
- `CSHead.checksum` is a CRC-32/IEEE of the decrypted body

### CSHead Schema

```protobuf
syntax = "proto3";

message CSHead {
    int32  msgid              = 1;
    uint64 up_seqid           = 2;
    uint64 down_seqid         = 3;
    uint32 total_pack_count   = 4;
    uint32 current_pack_index = 5;
    bool   is_compress        = 6;
    uint32 checksum           = 7;
}
```

---

## Building

Requirements: Rust 1.75+ (install through [rustup](https://rustup.rs))

```bash
git clone https://github.com/Yoshk4e/OxidizedRelay.git
cd OxidizedRelay
cargo build --release

# Binary at: target/release/OxidizedRelay
```

---

## Usage

```
OxidizedRelay [OPTIONS] <PCAP>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<PCAP>` | Path to the input .pcap file (pcapng must be converted first) |

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--key <HEX64>` | `-k` | Session key as a 64-char hex string (32 bytes). Prompted interactively if omitted. |
| `--iv <HEX24>` | `-i` | Encryption IV/nonce as a 24-char hex string (12 bytes). Prompted interactively if omitted. |
| `--host <IP>` | | Only process TCP streams where one endpoint matches this IP. |
| `--proto <FILE>` | | Path to a .proto file for named field decoding. |
| `--msgid-map <FILE>` | | Path to a file mapping msgid:TypeName pairs (one per line). Required with `--proto`. |
| `--plaintext-frames <N>` | | Number of leading frames per stream to treat as plaintext (default: 1). |
| `--show-invalid` | | Also display frames that fail CSHead parsing or CRC verification. |
| `--raw` | | Dump decrypted hex bytes for every frame. |

---

## Examples

### Interactive key/IV entry

```bash
OxidizedRelay capture.pcap

# → prompts for session key and IV
```

### Inline key/IV with server filter

```bash
OxidizedRelay capture.pcap \
  --key a3f1...64hexchars...9c2d \
  --iv  00000000deadbeefcafebabe \
  --host 192.168.1.100
```

### With proto schema for readable field names

```bash
OxidizedRelay capture.pcap \
  --key a3f1...64hexchars...9c2d \
  --iv  00000000deadbeefcafebabe \
  --host 192.168.1.100 \
  --proto game_messages.proto \
  --msgid-map msgid_map.txt
```

`msgid_map.txt` format, one mapping per line:

```
1001:LoginReq
1002:MoveReq
2001:LoginResp
2002:ChatMsg
```

### Show everything including invalid frames

```bash
OxidizedRelay capture.pcap -k <KEY> -i <IV> --show-invalid --raw
```

### pcapng → pcap conversion

OxidizedRelay only accepts legacy .pcap format. Convert first:

```bash
tshark -F pcap -r input.pcapng -w output.pcap
```

---

## Output Format

> **Note**: This is just an example and doesn't represent the real fields, msgid nor name

```
╔════════════════════════════════════════════════════════════════════════╗
║  TCP Stream  192.168.1.50:54321 → 192.168.1.100:8080  (42 frames)    ║
╚════════════════════════════════════════════════════════════════════════╝

▶ Frame #1   encrypted  │  msgid: 1001  (LoginReq)
──────────────────────────────────────────────────────────────────────

  [CSHead]
    msgid:                    1001
    up_seqid:                 1
    down_seqid:               0
    total_pack_count:         1
    current_pack_index:       0
    is_compress:              false
    checksum:                 0xA1B2C3D4  ✓

  [Body: LoginReq]
    account_id (1):           123456789
    token (2):                "eyJhbGciOiJSUzI1NiJ9..."
    platform (3):             2
```

Frames that fail wire-format validation or CRC are silently skipped unless `--show-invalid` is passed. A summary is printed at the end:

```
══════════════════════════════════════════════════════════════════════
 Summary  total=247  valid=241  crc_fail=3  skipped=3
══════════════════════════════════════════════════════════════════════
```

---

## The Process of Frame Filtering

The frame is filtered out silently (except for the flag `--show-invalid`) if any of the following conditions apply:

1. Decrypted header data cannot be parsed as a proper protobuf message or lacks field 1 (msgid).
2. The CRC-32/IEEE checksum of the decrypted payload does not equal `CSHead.checksum`.

This can be seen as an auto-filtering process, whereby random junk or TLS traffic, or even frames coming from another TCP connection, will not have a valid CSHead structure with a proper checksum, hence they get filtered out.

---

## Proto Schema Loading

> **Note:** Proto schema loading has not been tested thoroughly and may produce unexpected results in certain cases.

If the flags `--proto` and `--msgid-map` are provided together, OxidizedRelay loads the provided .proto file at runtime by utilizing protox (no protoc install needed). Field names are determined via the loaded descriptor and overlaid onto the output body fields that get decoded.

In the absence of a schema, the decoded body field names are output as `field_N`, with the raw byte values. Nested message bodies are decoded recursively, with length-delimited fields heuristically decoded as text → nested proto → bytes.

---

## Supported Link Types

| pcap DataLink | Notes |
|---------------|-------|
| `ETHERNET` | Standard Ethernet II |
| `LINUX_SLL` | Linux cooked capture (any interface) |
| `NULL / LOOP` | BSD loopback (4-byte AF header stripped) |
| `RAW` | Raw IP |

---

## Plans

- **CS/SC filter:** Implement filtering to distinguish and separately handle client-to-server (CS) and server-to-client (SC) traffic, along with an organized and structured representation of each direction's frames.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html) (AGPL-3.0).

You are free to use, modify, and distribute this software, but any modified version that is run over a network must also be made available under the same license.
