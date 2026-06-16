"""Segment Routing TLV parsing and serialization for OSPF (RFC 8665).

TLV structure:
  2-byte type, 2-byte length, variable value
  Values are padded to 4-byte boundaries (padding not counted in length).
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Optional


TLV_HDR_FORMAT = "!HH"
TLV_HDR_LEN = 4


def _pad4(length: int) -> int:
    """Round up to 4-byte boundary."""
    return (length + 3) & ~3


def parse_tlvs(data: bytes, offset: int = 0) -> list[tuple[int, bytes]]:
    """Parse a sequence of TLVs from data, returning (type, value_bytes) pairs."""
    tlvs = []
    pos = offset
    while pos + TLV_HDR_LEN <= len(data):
        tlv_type, tlv_len = struct.unpack_from(TLV_HDR_FORMAT, data, pos)
        pos += TLV_HDR_LEN
        if pos + tlv_len > len(data):
            break
        value = data[pos:pos + tlv_len]
        tlvs.append((tlv_type, value))
        pos += _pad4(tlv_len)
    return tlvs


def encode_tlv(tlv_type: int, value: bytes) -> bytes:
    """Encode a TLV with type, length, and padded value."""
    hdr = struct.pack(TLV_HDR_FORMAT, tlv_type, len(value))
    pad = bytes(_pad4(len(value)) - len(value))
    return hdr + value + pad


@dataclass
class SidLabelRange:
    """A SID/label range (SRGB or SRLB). Section 3.1 RFC 8665."""
    start: int   # first label/SID in range
    size: int    # number of labels/SIDs

    def contains(self, index: int) -> bool:
        return 0 <= index < self.size

    def label_for_index(self, index: int) -> int:
        """Convert a global SID index to an MPLS label."""
        return self.start + index


@dataclass
class SrCapabilities:
    """SR-Capabilities TLV content."""
    flags: int = 0
    ranges: list[SidLabelRange] = field(default_factory=list)

    @classmethod
    def deserialize(cls, data: bytes) -> SrCapabilities:
        """Parse SR-Capabilities value bytes (after TLV header)."""
        if len(data) < 2:
            raise ValueError("SR-Capabilities too short")
        flags = data[0]
        # reserved = data[1]
        cap = cls(flags=flags)
        # Sub-TLVs follow (SID/Label Sub-TLV type 1)
        pos = 2
        while pos + TLV_HDR_LEN <= len(data):
            st_type, st_len = struct.unpack_from(TLV_HDR_FORMAT, data, pos)
            pos += TLV_HDR_LEN
            if st_type == 1 and st_len >= 3:  # SID/Label sub-TLV
                # range size is 3 bytes preceding the sub-TLV
                # Actually per RFC 8665: flags(1), reserved(1), then range sub-TLV
                # The range is embedded in the capability directly as:
                # range_size(3 bytes) then SID/Label sub-TLV
                pass
            pos += _pad4(st_len)
        return cap

    def serialize(self) -> bytes:
        value = bytes([self.flags, 0])  # flags + reserved
        for r in self.ranges:
            # Encode range size (3 bytes big-endian) + SID/Label sub-TLV
            range_bytes = struct.pack("!I", r.size)[1:]  # 3 bytes
            label_bytes = struct.pack("!I", r.start)[1:]  # 3 bytes
            stlv = encode_tlv(1, label_bytes)  # SID/Label sub-TLV
            value += range_bytes + stlv
        return value


@dataclass
class SrAlgorithm:
    """SR-Algorithm TLV: list of algorithms this router supports."""
    algorithms: list[int] = field(default_factory=lambda: [0])  # default: SPF

    @classmethod
    def deserialize(cls, data: bytes) -> SrAlgorithm:
        return cls(algorithms=list(data))

    def serialize(self) -> bytes:
        return bytes(self.algorithms)


@dataclass
class PrefixSid:
    """Prefix-SID Sub-TLV per RFC 8665 Section 5."""
    flags: int
    algorithm: int
    sid: int      # SID index (or absolute label if V-flag set)

    @property
    def is_value(self) -> bool:
        from ospfd.const import PREFIX_SID_FLAG_V
        return bool(self.flags & PREFIX_SID_FLAG_V)

    @property
    def no_php(self) -> bool:
        from ospfd.const import PREFIX_SID_FLAG_NP
        return bool(self.flags & PREFIX_SID_FLAG_NP)

    @classmethod
    def deserialize(cls, data: bytes) -> PrefixSid:
        """Parse Prefix-SID sub-TLV value bytes."""
        if len(data) < 7:
            raise ValueError(f"Prefix-SID sub-TLV too short: {len(data)}")
        flags = data[0]
        # reserved = data[1]
        algorithm = data[2]
        # reserved = data[3]
        # SID: 4 bytes (index) or 3 bytes (label)
        from ospfd.const import PREFIX_SID_FLAG_V
        if flags & PREFIX_SID_FLAG_V:
            # V-flag: 3-byte label
            if len(data) < 7:
                raise ValueError("Prefix-SID with V-flag requires 7 bytes")
            sid = struct.unpack("!I", b'\x00' + data[4:7])[0]
        else:
            # index: 4 bytes
            if len(data) < 8:
                raise ValueError("Prefix-SID index requires 8 bytes")
            sid = struct.unpack_from("!I", data, 4)[0]
        return cls(flags=flags, algorithm=algorithm, sid=sid)

    def serialize(self) -> bytes:
        from ospfd.const import PREFIX_SID_FLAG_V
        if self.flags & PREFIX_SID_FLAG_V:
            sid_bytes = struct.pack("!I", self.sid)[1:]  # 3 bytes
        else:
            sid_bytes = struct.pack("!I", self.sid)  # 4 bytes
        return bytes([self.flags, 0, self.algorithm, 0]) + sid_bytes


@dataclass
class AdjSid:
    """Adjacency-SID Sub-TLV per RFC 8665 Section 6."""
    flags: int
    weight: int
    sid: int     # label value (V-flag) or index

    @property
    def is_value(self) -> bool:
        from ospfd.const import ADJ_SID_FLAG_V
        return bool(self.flags & ADJ_SID_FLAG_V)

    @classmethod
    def deserialize(cls, data: bytes) -> AdjSid:
        if len(data) < 7:
            raise ValueError(f"Adj-SID sub-TLV too short: {len(data)}")
        flags = data[0]
        # reserved = data[1]
        weight = data[2]
        # reserved = data[3]
        from ospfd.const import ADJ_SID_FLAG_V
        if flags & ADJ_SID_FLAG_V:
            sid = struct.unpack("!I", b'\x00' + data[4:7])[0]
        else:
            sid = struct.unpack_from("!I", data, 4)[0]
        return cls(flags=flags, weight=weight, sid=sid)

    def serialize(self) -> bytes:
        from ospfd.const import ADJ_SID_FLAG_V
        if self.flags & ADJ_SID_FLAG_V:
            sid_bytes = struct.pack("!I", self.sid)[1:]
        else:
            sid_bytes = struct.pack("!I", self.sid)
        return bytes([self.flags, 0, self.weight, 0]) + sid_bytes


@dataclass
class ExtendedPrefixEntry:
    """An Extended Prefix TLV entry from an Extended Prefix LSA."""
    route_type: int          # 1=intra-area, 3=inter-area, 5=AS external, 7=NSSA
    prefix_len: int
    af: int                  # 0 = IPv4
    flags: int
    prefix: IPv4Address
    prefix_sid: Optional[PrefixSid] = None

    @classmethod
    def deserialize(cls, data: bytes) -> ExtendedPrefixEntry:
        if len(data) < 8:
            raise ValueError("ExtendedPrefix TLV too short")
        route_type = data[0]
        prefix_len = data[1]
        af = data[2]
        flags = data[3]
        prefix = IPv4Address(data[4:8])
        entry = cls(route_type=route_type, prefix_len=prefix_len,
                    af=af, flags=flags, prefix=prefix)
        # Parse sub-TLVs
        for st_type, st_value in parse_tlvs(data, offset=8):
            if st_type == 2:  # Prefix-SID
                try:
                    entry.prefix_sid = PrefixSid.deserialize(st_value)
                except ValueError:
                    pass
        return entry


@dataclass
class ExtendedLinkEntry:
    """An Extended Link TLV entry from an Extended Link LSA."""
    link_type: int
    link_id: IPv4Address
    link_data: IPv4Address
    adj_sids: list[AdjSid] = field(default_factory=list)
    lan_adj_sids: list[tuple[IPv4Address, AdjSid]] = field(default_factory=list)

    @classmethod
    def deserialize(cls, data: bytes) -> ExtendedLinkEntry:
        if len(data) < 12:
            raise ValueError("ExtendedLink TLV too short")
        link_type = data[0]
        # reserved = data[1:4]
        link_id = IPv4Address(data[4:8])
        link_data = IPv4Address(data[8:12])
        entry = cls(link_type=link_type, link_id=link_id, link_data=link_data)
        # Parse sub-TLVs
        for st_type, st_value in parse_tlvs(data, offset=12):
            if st_type == 2:  # Adj-SID
                try:
                    entry.adj_sids.append(AdjSid.deserialize(st_value))
                except ValueError:
                    pass
            elif st_type == 3:  # LAN Adj-SID
                if len(st_value) >= 10:
                    nbr_rid = IPv4Address(st_value[4:8])
                    try:
                        asid = AdjSid.deserialize(st_value[:4] + st_value[8:])
                        entry.lan_adj_sids.append((nbr_rid, asid))
                    except ValueError:
                        pass
        return entry
