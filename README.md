# cs333-network-utils-zeroday

Example code for CS333 Spring 2026 — a simple packet builder and parser in Python. Designed to demonstrate how network packets are structured and how to construct them from scratch, without relying on third-party libraries. This is not a full-featured packet crafting tool — it's meant for educational purposes only, to help students understand the fundamentals of network protocols and packet structure.



## Team Members

- Alice Smith
- Bob Johnson
- Charlie Davis

---

## Quick Start

**Requirements:** Python 3.14+, [uv](https://docs.astral.sh/uv/)

```bash
# Clone and enter the repo
git clone <repo-url>
cd cs333-network-utils-zeroday
```

---

## Usage

```
uv run main.py --help
```

### Commands

| Command  | Description                                               |
| -------- | --------------------------------------------------------- |
| `create` | Build a packet and write it to a `.pkt` file              |
| `read`   | Parse and display all headers from a `.pkt` file          |
| `send`   | Inject a `.pkt` file onto the network (requires root)     |

---

## `create` — Build a Packet

### Using a preset

Presets are ready-made packets that demonstrate common network traffic patterns covered in the course.

```bash
uv run main.py create --preset <name> [--src-ip IP] [--dst-ip IP] [--output FILE]
```

| Preset      | Protocol | Description                                                               |
| ----------- | -------- | ------------------------------------------------------------------------- |
| `syn-scan`  | TCP      | SYN-only packet — the probe nmap sends during a stealth port scan (`-sS`) |
| `http-get`  | TCP      | PSH+ACK with a full HTTP GET request payload                              |
| `dns-query` | UDP      | DNS A-record query for `example.com` in correct wire format               |
| `ping`      | ICMP     | Echo Request (type 8) — equivalent to a standard `ping`                   |

**Examples:**

```bash
# ICMP ping to 8.8.8.8, display hexdump
uv run main.py create --preset ping --dst-ip 8.8.8.8 --hexdump

# TCP SYN scan probe saved to a custom file
uv run main.py create --preset syn-scan --dst-ip 10.0.0.1 --output scan.pkt

# HTTP GET request
uv run main.py create --preset http-get --src-ip 192.168.1.5 --dst-ip 93.184.216.34 --output get.pkt

# DNS query to Google's resolver
uv run main.py create --preset dns-query --dst-ip 8.8.8.8 --output dns.pkt
```

---

### Manual packet construction

Build a packet with full control over every field.

```bash
uv run main.py create --type <tcp|udp|icmp> [options]
```

**Options:**

| Flag         | Default         | Description                            |
| ------------ | --------------- | -------------------------------------- |
| `--type`     | *(required)*    | Protocol: `tcp`, `udp`, or `icmp`      |
| `--src-ip`   | `192.168.1.100` | Source IP address                      |
| `--dst-ip`   | `10.0.0.1`      | Destination IP address                 |
| `--src-port` | `54321`         | Source port (TCP/UDP)                  |
| `--dst-port` | `80`            | Destination port (TCP/UDP)             |
| `--ttl`      | `64`            | IP time-to-live                        |
| `--seq`      | `1000`          | TCP sequence number                    |
| `--ack`      | `0`             | TCP acknowledgment number              |
| `--flags`    | `SYN`           | TCP flags, comma-separated (see below) |
| `--window`   | `65535`         | TCP receive window size                |
| `--payload`  | *(empty)*       | UTF-8 string payload                   |
| `--output`   | `packet.pkt`    | Output file path                       |
| `--hexdump`  | off             | Print hexdump after writing            |
| `--send`     | off             | Send the packet immediately after writing (requires root) |

**TCP flag names** (combine with commas, e.g. `SYN,ACK`):

`FIN` `SYN` `RST` `PSH` `ACK` `URG` `ECE` `CWR` `NS`

**Examples:**

```bash
# TCP SYN — initiate a connection
uv run main.py create --type tcp \
  --src-ip 10.0.0.5 --dst-ip 10.0.0.1 \
  --src-port 49152 --dst-port 22 \
  --flags SYN --seq 100

# TCP SYN+ACK — server's response to a SYN
uv run main.py create --type tcp \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.5 \
  --src-port 22 --dst-port 49152 \
  --flags SYN,ACK --seq 5000 --ack 101

# TCP RST — abrupt connection teardown
uv run main.py create --type tcp \
  --src-ip 10.0.0.1 --dst-ip 10.0.0.5 \
  --flags RST

# UDP with a custom payload
uv run main.py create --type udp \
  --src-ip 10.0.0.5 --dst-ip 10.0.0.1 \
  --dst-port 9999 --payload "hello server"

# ICMP ping
uv run main.py create --type icmp \
  --src-ip 10.0.0.5 --dst-ip 10.0.0.1
```

---

## `send` — Inject a Packet onto the Network

```bash
sudo uv run main.py send <file> [--hexdump]
```

Reads a `.pkt` file, displays its headers, then injects the IP datagram via a raw socket. The 14-byte Ethernet header is stripped before sending — the OS kernel handles Layer 2 routing to the next hop.

**Requires root.** Raw sockets (`AF_INET + SOCK_RAW`) are a privileged operation on both Linux and macOS.

```bash
# Send a saved packet
sudo uv run main.py send ping.pkt

# Show hexdump then send
sudo uv run main.py send scan.pkt --hexdump
```

You can also build and send in one step using `--send` on the `create` command:

```bash
# Build a ping and send it immediately
sudo uv run main.py create --preset ping --dst-ip 8.8.8.8 --send

# Manual TCP SYN — build, write, and send
sudo uv run main.py create --type tcp \
  --src-ip 10.0.0.5 --dst-ip 10.0.0.1 \
  --dst-port 80 --flags SYN --send
```

**How it works:** uses `socket.IPPROTO_RAW` with `IP_HDRINCL=1`, which tells the kernel that the application is supplying the full IP header. The kernel routes the datagram based on the destination address in that header.

**Lab note:** when injecting raw TCP SYN packets, the OS may automatically send a RST in response to the SYN-ACK reply (because no socket is listening). This is expected behaviour and a useful observation — it illustrates how the kernel's TCP stack interacts with raw-socket traffic.

---

## `read` — Inspect a Packet File

```bash
uv run main.py read <file> [--hexdump]
```

Parses the binary `.pkt` file and prints every header field across all layers — Ethernet, IPv4, and the transport header — plus the payload if present.

```bash
# Display all headers
uv run main.py read packet.pkt

# Display headers + full hexdump of the Ethernet frame
uv run main.py read packet.pkt --hexdump
```

**Example output (`read scan.pkt`):**

```
Capture timestamp : 2026-03-31 21:12:09
Packet type       : TCP
Frame length      : 54 bytes

  [Ethernet]
    dst_mac   = ff:ee:dd:cc:bb:aa
    src_mac   = aa:bb:cc:dd:ee:ff
    ethertype = 0x0800 (IPv4)
  [IPv4]
    version   = 4
    ihl       = 20 bytes
    dscp/ecn  = 0x00
    length    = 40
    id        = 0x1234
    flags     = DF  (0b010)
    frag_off  = 0
    ttl       = 64
    protocol  = TCP (6)
    checksum  = 0x5c8f
    src       = 192.168.1.100
    dst       = 10.0.0.1
  [TCP]
    src_port  = 54321
    dst_port  = 80
    seq       = 1000
    ack       = 0
    data_off  = 20 bytes
    flags     = SYN
    window    = 65535
    checksum  = 0x0b6c
    urgent    = 0
```

---

## .pkt File Format

Binary format used to store a captured packet on disk.

| Offset | Size    | Type       | Description                             |
| ------ | ------- | ---------- | --------------------------------------- |
| 0      | 4 bytes | bytes      | Magic: `PKT\x01`                        |
| 4      | 8 bytes | float64 BE | Capture timestamp (Unix seconds)        |
| 12     | 1 byte  | uint8      | Packet type: `0`=TCP, `1`=UDP, `2`=ICMP |
| 13     | 4 bytes | uint32 BE  | Frame length in bytes                   |
| 17     | N bytes | bytes      | Raw Ethernet frame                      |

---

## Network Packet Structure

Each packet is a real Ethernet frame built from the ground up using Python's `struct` module.

### Layer Stack

```
+---------------------------+
|   Ethernet Header  14 B   |  dst MAC, src MAC, EtherType (0x0800)
+---------------------------+
|   IPv4 Header      20 B   |  version, IHL, TTL, protocol, src/dst IP, checksum
+---------------------------+
|   TCP Header       20 B   |  src/dst port, seq, ack, flags, window, checksum
|   UDP Header        8 B   |  — or —
|   ICMP Header       8 B   |
+---------------------------+
|   Payload          N B    |  arbitrary bytes
+---------------------------+
```

### Checksums

All checksums are computed correctly per the relevant RFCs:

- **IPv4** — internet checksum (RFC 1071) over the 20-byte IP header.
- **TCP/UDP** — internet checksum over a pseudo-header (src IP, dst IP, zero, protocol, segment length) concatenated with the full segment. This mirrors what a real network stack does.
- **ICMP** — internet checksum over the ICMP header and its data payload.

### TCP Flags Reference

| Flag  | Bit | Common use                         |
| ----- | --- | ---------------------------------- |
| `FIN` | 0   | Graceful connection teardown       |
| `SYN` | 1   | Connection initiation              |
| `RST` | 2   | Abrupt connection reset            |
| `PSH` | 3   | Push buffered data to application  |
| `ACK` | 4   | Acknowledgment field is valid      |
| `URG` | 5   | Urgent pointer is valid            |
| `ECE` | 6   | ECN-Echo (congestion notification) |
| `CWR` | 7   | Congestion Window Reduced          |
| `NS`  | 8   | ECN nonce sum                      |
