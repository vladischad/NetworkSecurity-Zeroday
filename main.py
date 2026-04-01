#!/usr/bin/env python3
"""
pkt — CS333 Network Packet Builder

Craft, serialize, and inspect binary network packets for network security coursework.
Builds real Ethernet + IPv4 + TCP/UDP/ICMP frames with correct checksums.

File format (.pkt):
  Bytes 0-3   : Magic "PKT\\x01"
  Bytes 4-11  : Capture timestamp (float64 big-endian, Unix seconds)
  Byte  12    : Packet type (0=TCP, 1=UDP, 2=ICMP)
  Bytes 13-16 : Frame length (uint32 big-endian)
  Bytes 17+   : Raw Ethernet frame bytes

Usage:
  uv run main.py create --type tcp --src-ip 10.0.0.1 --dst-ip 10.0.0.2
  uv run main.py create --preset http-get --output get.pkt
  uv run main.py create --preset ping --dst-ip 8.8.8.8 --send
  uv run main.py read packet.pkt
  uv run main.py read packet.pkt --hexdump
  sudo uv run main.py send packet.pkt
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import ClassVar, Literal

# ── Protocol constants ──────────────────────────────────────────────────────────
ETHERTYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PacketKind = Literal["tcp", "udp", "icmp"]
_KIND_TO_BYTE: dict[str, int] = {"tcp": 0, "udp": 1, "icmp": 2}
_BYTE_TO_KIND: dict[int, str] = {v: k for k, v in _KIND_TO_BYTE.items()}

# ── File format ─────────────────────────────────────────────────────────────────
MAGIC = b"PKT\x01"
# Metadata written after magic: timestamp(d=8) + kind(B=1) + frame_len(I=4)
_FILE_META = struct.Struct("!dBI")


# ── Checksum (RFC 1071) ──────────────────────────────────────────────────────────
def inet_checksum(data: bytes) -> int:
    """Internet checksum over arbitrary bytes. Returns the 16-bit one's complement sum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _transport_checksum(src_ip: bytes, dst_ip: bytes, proto: int, segment: bytes) -> int:
    """Compute TCP/UDP checksum using the IPv4 pseudo-header."""
    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, proto, len(segment))
    return inet_checksum(pseudo + segment)


# ── Ethernet header ─────────────────────────────────────────────────────────────
@dataclass
class EthernetHeader:
    dst_mac: bytes  # 6 bytes
    src_mac: bytes  # 6 bytes
    ethertype: int  # 2 bytes

    STRUCT: ClassVar[struct.Struct] = struct.Struct("!6s6sH")
    SIZE: ClassVar[int] = 14

    def pack(self) -> bytes:
        return self.STRUCT.pack(self.dst_mac, self.src_mac, self.ethertype)

    @classmethod
    def unpack(cls, raw: bytes) -> EthernetHeader:
        dst, src, et = cls.STRUCT.unpack(raw[: cls.SIZE])
        return cls(dst_mac=dst, src_mac=src, ethertype=et)

    def __str__(self) -> str:
        dst = ":".join(f"{b:02x}" for b in self.dst_mac)
        src = ":".join(f"{b:02x}" for b in self.src_mac)
        return (
            f"  [Ethernet]\n"
            f"    dst_mac   = {dst}\n"
            f"    src_mac   = {src}\n"
            f"    ethertype = 0x{self.ethertype:04x} (IPv4)"
        )


# ── IPv4 header ─────────────────────────────────────────────────────────────────
@dataclass
class IPv4Header:
    version_ihl: int    # 1 B  — 0x45 means version=4, IHL=5 (20-byte header)
    dscp_ecn: int       # 1 B  — differentiated services / ECN bits
    total_length: int   # 2 B  — entire IP datagram length
    identification: int # 2 B  — fragment identification
    flags_frag: int     # 2 B  — [3-bit flags | 13-bit fragment offset]
    ttl: int            # 1 B  — time to live (hops)
    protocol: int       # 1 B  — next protocol (TCP=6, UDP=17, ICMP=1)
    checksum: int       # 2 B  — header checksum (zeroed during calculation)
    src_ip: bytes       # 4 B
    dst_ip: bytes       # 4 B

    STRUCT: ClassVar[struct.Struct] = struct.Struct("!BBHHHBBH4s4s")
    SIZE: ClassVar[int] = 20

    def pack(self) -> bytes:
        # Zero checksum field, then compute and patch it back in.
        raw = self.STRUCT.pack(
            self.version_ihl, self.dscp_ecn, self.total_length,
            self.identification, self.flags_frag,
            self.ttl, self.protocol, 0,
            self.src_ip, self.dst_ip,
        )
        csum = inet_checksum(raw)
        return raw[:10] + struct.pack("!H", csum) + raw[12:]

    @classmethod
    def unpack(cls, raw: bytes) -> IPv4Header:
        return cls(*cls.STRUCT.unpack(raw[: cls.SIZE]))

    @property
    def src_str(self) -> str:
        return socket.inet_ntoa(self.src_ip)

    @property
    def dst_str(self) -> str:
        return socket.inet_ntoa(self.dst_ip)

    @property
    def proto_name(self) -> str:
        return {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(
            self.protocol, str(self.protocol)
        )

    def __str__(self) -> str:
        version = self.version_ihl >> 4
        ihl = (self.version_ihl & 0xF) * 4
        flags = (self.flags_frag >> 13) & 0x7
        frag_off = self.flags_frag & 0x1FFF
        flag_str = ("DF " if flags & 0x2 else "") + ("MF " if flags & 0x1 else "")
        return (
            f"  [IPv4]\n"
            f"    version   = {version}\n"
            f"    ihl       = {ihl} bytes\n"
            f"    dscp/ecn  = 0x{self.dscp_ecn:02x}\n"
            f"    length    = {self.total_length}\n"
            f"    id        = 0x{self.identification:04x}\n"
            f"    flags     = {flag_str.strip() or 'none'}  (0b{flags:03b})\n"
            f"    frag_off  = {frag_off}\n"
            f"    ttl       = {self.ttl}\n"
            f"    protocol  = {self.proto_name} ({self.protocol})\n"
            f"    checksum  = 0x{self.checksum:04x}\n"
            f"    src       = {self.src_str}\n"
            f"    dst       = {self.dst_str}"
        )


# ── TCP header ──────────────────────────────────────────────────────────────────
@dataclass
class TCPHeader:
    src_port: int       # 2 B
    dst_port: int       # 2 B
    seq_num: int        # 4 B  — sequence number
    ack_num: int        # 4 B  — acknowledgment number
    data_off_flags: int # 2 B  — [data_offset(4) | reserved(3) | flags(9)]
    window: int         # 2 B  — receive window size
    checksum: int       # 2 B
    urgent: int         # 2 B  — urgent pointer (only valid if URG flag set)

    STRUCT: ClassVar[struct.Struct] = struct.Struct("!HHIIHHHH")
    SIZE: ClassVar[int] = 20

    # Flag bitmasks
    FLAG_FIN: ClassVar[int] = 0x001
    FLAG_SYN: ClassVar[int] = 0x002
    FLAG_RST: ClassVar[int] = 0x004
    FLAG_PSH: ClassVar[int] = 0x008
    FLAG_ACK: ClassVar[int] = 0x010
    FLAG_URG: ClassVar[int] = 0x020
    FLAG_ECE: ClassVar[int] = 0x040
    FLAG_CWR: ClassVar[int] = 0x080
    FLAG_NS:  ClassVar[int] = 0x100

    def pack(self) -> bytes:
        return self.STRUCT.pack(
            self.src_port, self.dst_port,
            self.seq_num, self.ack_num,
            self.data_off_flags, self.window,
            self.checksum, self.urgent,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> TCPHeader:
        return cls(*cls.STRUCT.unpack(raw[: cls.SIZE]))

    @property
    def flags_str(self) -> str:
        f = self.data_off_flags & 0x1FF
        pairs = [
            ("FIN", 0), ("SYN", 1), ("RST", 2), ("PSH", 3),
            ("ACK", 4), ("URG", 5), ("ECE", 6), ("CWR", 7), ("NS", 8),
        ]
        active = [name for name, bit in pairs if f & (1 << bit)]
        return " ".join(active) if active else "none"

    def __str__(self) -> str:
        doff = (self.data_off_flags >> 12) * 4
        return (
            f"  [TCP]\n"
            f"    src_port  = {self.src_port}\n"
            f"    dst_port  = {self.dst_port}\n"
            f"    seq       = {self.seq_num}\n"
            f"    ack       = {self.ack_num}\n"
            f"    data_off  = {doff} bytes\n"
            f"    flags     = {self.flags_str}\n"
            f"    window    = {self.window}\n"
            f"    checksum  = 0x{self.checksum:04x}\n"
            f"    urgent    = {self.urgent}"
        )


# ── UDP header ──────────────────────────────────────────────────────────────────
@dataclass
class UDPHeader:
    src_port: int   # 2 B
    dst_port: int   # 2 B
    length: int     # 2 B  — header + payload in bytes
    checksum: int   # 2 B

    STRUCT: ClassVar[struct.Struct] = struct.Struct("!HHHH")
    SIZE: ClassVar[int] = 8

    def pack(self) -> bytes:
        return self.STRUCT.pack(self.src_port, self.dst_port, self.length, self.checksum)

    @classmethod
    def unpack(cls, raw: bytes) -> UDPHeader:
        return cls(*cls.STRUCT.unpack(raw[: cls.SIZE]))

    def __str__(self) -> str:
        return (
            f"  [UDP]\n"
            f"    src_port  = {self.src_port}\n"
            f"    dst_port  = {self.dst_port}\n"
            f"    length    = {self.length}\n"
            f"    checksum  = 0x{self.checksum:04x}"
        )


# ── ICMP header ─────────────────────────────────────────────────────────────────
@dataclass
class ICMPHeader:
    type: int       # 1 B  — message type (8=echo request, 0=echo reply, …)
    code: int       # 1 B  — sub-type code
    checksum: int   # 2 B  — covers header + data
    identifier: int # 2 B  — echo id (type 8/0 only)
    sequence: int   # 2 B  — echo sequence number

    STRUCT: ClassVar[struct.Struct] = struct.Struct("!BBHHH")
    SIZE: ClassVar[int] = 8

    _TYPE_NAMES: ClassVar[dict[int, str]] = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded",
    }

    def pack(self, payload: bytes = b"") -> bytes:
        """Pack header; checksum is calculated over header + payload."""
        raw = self.STRUCT.pack(self.type, self.code, 0, self.identifier, self.sequence)
        csum = inet_checksum(raw + payload)
        return raw[:2] + struct.pack("!H", csum) + raw[4:]

    @classmethod
    def unpack(cls, raw: bytes) -> ICMPHeader:
        return cls(*cls.STRUCT.unpack(raw[: cls.SIZE]))

    @property
    def type_name(self) -> str:
        return self._TYPE_NAMES.get(self.type, f"Type {self.type}")

    def __str__(self) -> str:
        return (
            f"  [ICMP]\n"
            f"    type      = {self.type_name} ({self.type})\n"
            f"    code      = {self.code}\n"
            f"    checksum  = 0x{self.checksum:04x}\n"
            f"    id        = {self.identifier}\n"
            f"    sequence  = {self.sequence}"
        )


# ── Packet builders ─────────────────────────────────────────────────────────────
def _make_mac(hex_str: str) -> bytes:
    """Parse a MAC address string like 'aa:bb:cc:dd:ee:ff' → 6 bytes."""
    return bytes(int(h, 16) for h in hex_str.split(":"))


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    window: int,
    payload: bytes,
    src_mac: str = "aa:bb:cc:dd:ee:ff",
    dst_mac: str = "ff:ee:dd:cc:bb:aa",
    ttl: int = 64,
    ip_id: int = 0x1234,
) -> bytes:
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    # data_offset = 5 (20-byte header), stored in upper nibble of upper byte
    data_off_flags = (5 << 12) | (flags & 0x1FF)
    tcp_hdr = TCPHeader(
        src_port=src_port, dst_port=dst_port,
        seq_num=seq, ack_num=ack,
        data_off_flags=data_off_flags, window=window,
        checksum=0, urgent=0,
    )
    tcp_raw_no_csum = tcp_hdr.pack()
    csum = _transport_checksum(ip_src, ip_dst, PROTO_TCP, tcp_raw_no_csum + payload)
    tcp_hdr.checksum = csum
    tcp_bytes = tcp_hdr.pack() + payload

    total_len = IPv4Header.SIZE + len(tcp_bytes)
    ip_hdr = IPv4Header(
        version_ihl=0x45, dscp_ecn=0, total_length=total_len,
        identification=ip_id, flags_frag=0x4000,  # DF bit set
        ttl=ttl, protocol=PROTO_TCP, checksum=0,
        src_ip=ip_src, dst_ip=ip_dst,
    )

    eth = EthernetHeader(
        dst_mac=_make_mac(dst_mac), src_mac=_make_mac(src_mac),
        ethertype=ETHERTYPE_IPV4,
    )
    return eth.pack() + ip_hdr.pack() + tcp_bytes


def build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    src_mac: str = "aa:bb:cc:dd:ee:ff",
    dst_mac: str = "ff:ee:dd:cc:bb:aa",
    ttl: int = 64,
    ip_id: int = 0x5678,
) -> bytes:
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    udp_len = UDPHeader.SIZE + len(payload)
    udp_hdr = UDPHeader(
        src_port=src_port, dst_port=dst_port, length=udp_len, checksum=0
    )
    csum = _transport_checksum(ip_src, ip_dst, PROTO_UDP, udp_hdr.pack() + payload)
    udp_hdr.checksum = csum
    udp_bytes = udp_hdr.pack() + payload

    total_len = IPv4Header.SIZE + len(udp_bytes)
    ip_hdr = IPv4Header(
        version_ihl=0x45, dscp_ecn=0, total_length=total_len,
        identification=ip_id, flags_frag=0x0000,
        ttl=ttl, protocol=PROTO_UDP, checksum=0,
        src_ip=ip_src, dst_ip=ip_dst,
    )

    eth = EthernetHeader(
        dst_mac=_make_mac(dst_mac), src_mac=_make_mac(src_mac),
        ethertype=ETHERTYPE_IPV4,
    )
    return eth.pack() + ip_hdr.pack() + udp_bytes


def build_icmp_packet(
    src_ip: str,
    dst_ip: str,
    icmp_type: int = 8,
    icmp_code: int = 0,
    identifier: int = 0x0001,
    sequence: int = 1,
    payload: bytes = b"Hello CS333!",
    src_mac: str = "aa:bb:cc:dd:ee:ff",
    dst_mac: str = "ff:ee:dd:cc:bb:aa",
    ttl: int = 64,
    ip_id: int = 0x9abc,
) -> bytes:
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    icmp_hdr = ICMPHeader(
        type=icmp_type, code=icmp_code, checksum=0,
        identifier=identifier, sequence=sequence,
    )
    icmp_bytes = icmp_hdr.pack(payload) + payload

    total_len = IPv4Header.SIZE + len(icmp_bytes)
    ip_hdr = IPv4Header(
        version_ihl=0x45, dscp_ecn=0, total_length=total_len,
        identification=ip_id, flags_frag=0x0000,
        ttl=ttl, protocol=PROTO_ICMP, checksum=0,
        src_ip=ip_src, dst_ip=ip_dst,
    )

    eth = EthernetHeader(
        dst_mac=_make_mac(dst_mac), src_mac=_make_mac(src_mac),
        ethertype=ETHERTYPE_IPV4,
    )
    return eth.pack() + ip_hdr.pack() + icmp_bytes


# ── Packet presets ──────────────────────────────────────────────────────────────
def _dns_query(name: str = "example.com") -> bytes:
    """Build a minimal DNS A-record query for the given domain name."""
    # Header: id=0x1234, flags=0x0100 (standard query, RD=1), 1 question
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    # Encode QNAME: split on '.', prefix each label with its length byte
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE=A(1), QCLASS=IN(1)
    return header + question


PRESETS: dict[str, dict[str, object]] = {
    "syn-scan": {
        "description": "TCP SYN packet — used in port scanning (e.g. nmap -sS)",
        "kind": "tcp",
        "dst_port": 80,
        "flags": TCPHeader.FLAG_SYN,
        "payload": b"",
    },
    "http-get": {
        "description": "TCP PSH+ACK with HTTP GET request payload",
        "kind": "tcp",
        "dst_port": 80,
        "flags": TCPHeader.FLAG_PSH | TCPHeader.FLAG_ACK,
        "payload": b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pkt/1.0\r\n\r\n",
    },
    "dns-query": {
        "description": "UDP DNS A-record query for example.com to port 53",
        "kind": "udp",
        "dst_port": 53,
        "payload": _dns_query("example.com"),
    },
    "ping": {
        "description": "ICMP Echo Request (type 8) — standard ping",
        "kind": "icmp",
        "icmp_type": 8,
        "payload": b"Hello CS333!",
    },
}


# ── File I/O ────────────────────────────────────────────────────────────────────
def write_pkt(frame: bytes, kind: str, path: str) -> None:
    """Write an Ethernet frame to a .pkt binary file."""
    meta = _FILE_META.pack(time.time(), _KIND_TO_BYTE[kind], len(frame))
    with open(path, "wb") as f:
        f.write(MAGIC + meta + frame)
    print(f"Written {len(frame)} bytes → {path}")


def read_pkt(path: str) -> tuple[str, float, bytes]:
    """Read a .pkt file. Returns (kind, timestamp, raw_frame)."""
    with open(path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError(f"Not a valid .pkt file (bad magic: {magic!r})")
        meta_raw = f.read(_FILE_META.size)
        ts, kind_byte, frame_len = _FILE_META.unpack(meta_raw)
        frame = f.read(frame_len)
    if len(frame) != frame_len:
        raise ValueError(f"Truncated file: expected {frame_len} bytes, got {len(frame)}")
    kind = _BYTE_TO_KIND.get(kind_byte, "unknown")
    return kind, ts, frame


# ── Network send ────────────────────────────────────────────────────────────────
def _patch_ip_for_platform(ip_data: bytes) -> bytes:
    """
    macOS/BSD raw sockets with IP_HDRINCL expect ip_len (offset 2) and ip_off
    (offset 6) in host byte order, not network byte order.  The kernel converts
    them back to network byte order before putting the packet on the wire, so
    the checksum — computed over the network-byte-order header — stays correct.

    Linux expects network byte order throughout; no patching needed.
    """
    if sys.platform != "darwin":
        return ip_data
    buf = bytearray(ip_data)
    for offset in (2, 6):
        (val,) = struct.unpack_from("!H", buf, offset)
        struct.pack_into("=H", buf, offset, val)  # native (little-endian on x86/ARM)
    return bytes(buf)


def send_frame(frame: bytes) -> None:
    """Send the IP portion of an Ethernet frame via a raw socket.

    Strips the 14-byte Ethernet header — the OS kernel handles Layer 2 routing.
    Requires root/Administrator privileges (raw sockets are privileged operations).

    Uses AF_INET + SOCK_RAW + IPPROTO_RAW with IP_HDRINCL, which works on both
    Linux and macOS.  The kernel routes the datagram based on the destination IP
    in the header we provide.

    Note: the OS TCP stack may send RST replies for inbound responses to SYN
    packets that don't match an open socket — this is expected when injecting
    raw TCP packets and is a useful observation for in-class discussion.
    """
    ip_data = _patch_ip_for_platform(frame[EthernetHeader.SIZE :])
    ip = IPv4Header.unpack(ip_data)
    dst = ip.dst_str

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sent = sock.sendto(ip_data, (dst, 0))
        print(f"Sent {sent} bytes → {dst}")
    except PermissionError:
        print("error: raw sockets require root privileges")
        print("  try: sudo uv run main.py send <file>")
        raise SystemExit(1)
    except OSError as exc:
        print(f"error: {exc}")
        raise SystemExit(1)


# ── Display ─────────────────────────────────────────────────────────────────────
def hexdump(data: bytes, width: int = 16) -> str:
    """Classic hexdump: offset | hex bytes | ASCII."""
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<{width * 3}}  {asc_part}")
    return "\n".join(lines)


def display_frame(kind: str, ts: float, frame: bytes, show_hexdump: bool = False) -> None:
    """Parse and pretty-print all headers in a captured frame."""
    captured = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    print(f"\nCapture timestamp : {captured}")
    print(f"Packet type       : {kind.upper()}")
    print(f"Frame length      : {len(frame)} bytes\n")

    offset = 0

    # Ethernet
    if len(frame) < EthernetHeader.SIZE:
        print("  [!] Frame too short for Ethernet header")
        return
    eth = EthernetHeader.unpack(frame)
    print(eth)
    offset += EthernetHeader.SIZE

    # IPv4
    if eth.ethertype != ETHERTYPE_IPV4:
        print(f"  [!] Unsupported EtherType 0x{eth.ethertype:04x}")
        return
    if len(frame) < offset + IPv4Header.SIZE:
        print("  [!] Frame too short for IPv4 header")
        return
    ip = IPv4Header.unpack(frame[offset:])
    print(ip)
    ihl_bytes = (ip.version_ihl & 0xF) * 4
    offset += ihl_bytes

    # Transport layer
    remaining = frame[offset:]
    if kind == "tcp":
        if len(remaining) < TCPHeader.SIZE:
            print("  [!] Too short for TCP header")
            return
        tcp = TCPHeader.unpack(remaining)
        print(tcp)
        payload = remaining[TCPHeader.SIZE :]
    elif kind == "udp":
        if len(remaining) < UDPHeader.SIZE:
            print("  [!] Too short for UDP header")
            return
        udp = UDPHeader.unpack(remaining)
        print(udp)
        payload = remaining[UDPHeader.SIZE :]
    elif kind == "icmp":
        if len(remaining) < ICMPHeader.SIZE:
            print("  [!] Too short for ICMP header")
            return
        icmp = ICMPHeader.unpack(remaining)
        print(icmp)
        payload = remaining[ICMPHeader.SIZE :]
    else:
        payload = remaining

    if payload:
        try:
            text = payload.decode("utf-8")
            print(f"\n  [Payload — {len(payload)} bytes — UTF-8]\n    {text!r}")
        except UnicodeDecodeError:
            print(f"\n  [Payload — {len(payload)} bytes — binary]")

    if show_hexdump:
        print(f"\n  [Hexdump — full frame]\n{hexdump(frame)}")

    print()


# ── TCP flag parser ─────────────────────────────────────────────────────────────
_FLAG_NAMES: dict[str, int] = {
    "FIN": TCPHeader.FLAG_FIN,
    "SYN": TCPHeader.FLAG_SYN,
    "RST": TCPHeader.FLAG_RST,
    "PSH": TCPHeader.FLAG_PSH,
    "ACK": TCPHeader.FLAG_ACK,
    "URG": TCPHeader.FLAG_URG,
    "ECE": TCPHeader.FLAG_ECE,
    "CWR": TCPHeader.FLAG_CWR,
    "NS":  TCPHeader.FLAG_NS,
}


def parse_flags(flag_str: str) -> int:
    """Parse comma-separated flag names like 'SYN,ACK' into a bitmask."""
    bits = 0
    for name in flag_str.upper().split(","):
        name = name.strip()
        if name not in _FLAG_NAMES:
            raise argparse.ArgumentTypeError(
                f"Unknown flag '{name}'. Valid flags: {', '.join(_FLAG_NAMES)}"
            )
        bits |= _FLAG_NAMES[name]
    return bits


# ── CLI ─────────────────────────────────────────────────────────────────────────
def handle_create(args: argparse.Namespace) -> None:
    src_ip: str = args.src_ip
    dst_ip: str = args.dst_ip
    output: str = args.output

    if args.preset:
        preset = PRESETS[args.preset]
        print(f"Preset '{args.preset}': {preset['description']}")
        kind = str(preset["kind"])

        if kind == "tcp":
            flags = int(preset["flags"])  # type: ignore[arg-type]
            frame = build_tcp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=args.src_port,
                dst_port=int(preset["dst_port"]),
                seq=args.seq, ack=args.ack,
                flags=flags, window=args.window,
                payload=bytes(preset["payload"]),  # type: ignore[arg-type]
            )
        elif kind == "udp":
            frame = build_udp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=args.src_port,
                dst_port=int(preset["dst_port"]),
                payload=bytes(preset["payload"]),  # type: ignore[arg-type]
            )
        else:  # icmp
            frame = build_icmp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                icmp_type=int(preset.get("icmp_type", 8)),
                payload=bytes(preset["payload"]),  # type: ignore[arg-type]
            )
    else:
        if not args.type:
            print("error: --type is required when --preset is not used")
            raise SystemExit(1)
        kind = args.type
        payload = args.payload.encode("utf-8") if args.payload else b""

        if kind == "tcp":
            flags = parse_flags(args.flags)
            frame = build_tcp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=args.src_port, dst_port=args.dst_port,
                seq=args.seq, ack=args.ack,
                flags=flags, window=args.window,
                payload=payload,
            )
        elif kind == "udp":
            frame = build_udp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=args.src_port, dst_port=args.dst_port,
                payload=payload,
            )
        else:  # icmp
            frame = build_icmp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                payload=payload,
            )

    write_pkt(frame, kind, output)

    # Immediately display what was written so the user can verify.
    ts = time.time()
    print()
    display_frame(kind, ts, frame, show_hexdump=args.hexdump)

    if args.send:
        send_frame(frame)


def handle_read(args: argparse.Namespace) -> None:
    kind, ts, frame = read_pkt(args.file)
    display_frame(kind, ts, frame, show_hexdump=args.hexdump)


def handle_send(args: argparse.Namespace) -> None:
    kind, ts, frame = read_pkt(args.file)
    display_frame(kind, ts, frame, show_hexdump=args.hexdump)
    send_frame(frame)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkt",
        description="CS333 Network Packet Builder — craft and inspect binary packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py create --type tcp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --dst-port 443 --flags SYN\n"
            "  python main.py create --preset http-get --dst-ip 93.184.216.34 --output get.pkt\n"
            "  python main.py create --preset dns-query --dst-ip 8.8.8.8 --output dns.pkt\n"
            "  python main.py create --preset ping --dst-ip 8.8.8.8\n"
            "  python main.py read packet.pkt --hexdump\n"
            f"\npresets: {', '.join(PRESETS)}"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── create ──────────────────────────────────────────────────────────────────
    c = sub.add_parser("create", help="Build a packet and write it to a .pkt file")

    kind_group = c.add_mutually_exclusive_group()
    kind_group.add_argument(
        "--type", choices=["tcp", "udp", "icmp"],
        help="Protocol for the transport layer",
    )
    kind_group.add_argument(
        "--preset", choices=list(PRESETS),
        metavar="PRESET",
        help=f"Use a named example packet. Options: {', '.join(PRESETS)}",
    )

    c.add_argument("--src-ip",   default="192.168.1.100", metavar="IP", help="Source IP address")
    c.add_argument("--dst-ip",   default="10.0.0.1",      metavar="IP", help="Destination IP address")
    c.add_argument("--src-port", default=54321, type=int,  metavar="PORT")
    c.add_argument("--dst-port", default=80,    type=int,  metavar="PORT")
    c.add_argument("--ttl",      default=64,    type=int,  metavar="N",  help="IP time-to-live (default 64)")
    c.add_argument("--seq",      default=1000,  type=int,  metavar="N",  help="TCP sequence number")
    c.add_argument("--ack",      default=0,     type=int,  metavar="N",  help="TCP acknowledgment number")
    c.add_argument(
        "--flags", default="SYN", metavar="FLAGS",
        help="TCP flags, comma-separated (e.g. SYN or SYN,ACK). Default: SYN",
    )
    c.add_argument("--window",  default=65535, type=int, metavar="N",    help="TCP window size")
    c.add_argument("--payload", default="",   metavar="TEXT",            help="UTF-8 payload string")
    c.add_argument("--output",  default="packet.pkt", metavar="FILE", help="Output .pkt file (default: packet.pkt)")
    c.add_argument("--hexdump", action="store_true", help="Also print hexdump after writing")
    c.add_argument("--send", action="store_true", help="Send the packet immediately after writing (requires root)")

    # ── read ────────────────────────────────────────────────────────────────────
    r = sub.add_parser("read", help="Parse and display a .pkt file")
    r.add_argument("file", help="Path to a .pkt file")
    r.add_argument("--hexdump", action="store_true", help="Print full hexdump of the frame")

    # ── send ────────────────────────────────────────────────────────────────────
    s = sub.add_parser(
        "send",
        help="Send a .pkt file over the network (requires root)",
        description=(
            "Parse a .pkt file and inject its IP datagram via a raw socket.\n"
            "The Ethernet header is stripped — the OS kernel handles Layer 2.\n\n"
            "Requires root: sudo uv run main.py send <file>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    s.add_argument("file", help="Path to a .pkt file")
    s.add_argument("--hexdump", action="store_true", help="Print hexdump before sending")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "create":
        handle_create(args)
    elif args.command == "read":
        handle_read(args)
    elif args.command == "send":
        handle_send(args)


if __name__ == "__main__":
    main()
