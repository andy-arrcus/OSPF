"""Opaque LSA body parsers for Segment Routing (RFC 8665).

Handles:
  - Router Information LSA (opaque type 4, RFC 7770)
  - Extended Prefix LSA (opaque type 7, RFC 7684)
  - Extended Link LSA (opaque type 8, RFC 7684)
"""
from __future__ import annotations
import struct
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Optional

from ospfd.const import (
    OPAQUE_TYPE_RI, OPAQUE_TYPE_EXTENDED_PREFIX, OPAQUE_TYPE_EXTENDED_LINK,
    RI_TLV_SR_CAPABILITIES, RI_TLV_SR_ALGORITHM, RI_TLV_SID_LABEL_RANGE,
    EP_TLV_EXTENDED_PREFIX, EL_TLV_EXTENDED_LINK,
    SR_STLV_SID_LABEL,
)
from ospfd.sr.tlv import (
    parse_tlvs, encode_tlv, SidLabelRange, SrCapabilities, SrAlgorithm,
    PrefixSid, AdjSid, ExtendedPrefixEntry, ExtendedLinkEntry,
)

logger = logging.getLogger(__name__)


@dataclass
class RouterInfoLsa:
    """Parsed Router Information LSA body."""
    sr_capabilities: Optional[SrCapabilities] = None
    sr_algorithms: list[int] = field(default_factory=lambda: [0])
    srgb: Optional[SidLabelRange] = None

    @classmethod
    def deserialize(cls, data: bytes) -> RouterInfoLsa:
        lsa = cls()
        for tlv_type, value in parse_tlvs(data):
            try:
                if tlv_type == RI_TLV_SR_CAPABILITIES:
                    lsa.sr_capabilities = _parse_sr_capabilities(value)
                elif tlv_type == RI_TLV_SR_ALGORITHM:
                    lsa.sr_algorithms = list(value)
                elif tlv_type == RI_TLV_SID_LABEL_RANGE:
                    lsa.srgb = _parse_sid_label_range(value)
            except Exception as e:
                logger.debug("Error parsing RI LSA TLV type=%d: %s", tlv_type, e)
        return lsa

    def serialize(self) -> bytes:
        data = b""
        if self.sr_capabilities is not None:
            data += encode_tlv(RI_TLV_SR_CAPABILITIES, self.sr_capabilities.serialize())
        if self.sr_algorithms:
            data += encode_tlv(RI_TLV_SR_ALGORITHM, bytes(self.sr_algorithms))
        if self.srgb is not None:
            data += encode_tlv(RI_TLV_SID_LABEL_RANGE, _encode_sid_label_range(self.srgb))
        return data


def _parse_sr_capabilities(data: bytes) -> SrCapabilities:
    """Parse SR-Capabilities TLV value."""
    if len(data) < 2:
        raise ValueError("SR-Capabilities too short")
    flags = data[0]
    # reserved = data[1]
    cap = SrCapabilities(flags=flags)
    # Per RFC 8665 Section 3.1: flags(1) + reserved(1) + range_size(3) + SID/Label Sub-TLV
    pos = 2
    while pos + 3 <= len(data):
        range_size = struct.unpack("!I", b'\x00' + data[pos:pos+3])[0]
        pos += 3
        if pos + 4 <= len(data):
            st_type, st_len = struct.unpack_from("!HH", data, pos)
            pos += 4
            if st_type == SR_STLV_SID_LABEL and st_len == 3 and pos + 3 <= len(data):
                label = struct.unpack("!I", b'\x00' + data[pos:pos+3])[0]
                cap.ranges.append(SidLabelRange(start=label, size=range_size))
                pos += 3
            else:
                pos += st_len
    return cap


def _parse_sid_label_range(data: bytes) -> SidLabelRange:
    """Parse SID/Label Range TLV value (SRGB advertisement)."""
    if len(data) < 3:
        raise ValueError("SID/Label Range TLV too short")
    range_size = struct.unpack("!I", b'\x00' + data[0:3])[0]
    start = 0
    pos = 3
    if pos + 4 <= len(data):
        st_type, st_len = struct.unpack_from("!HH", data, pos)
        pos += 4
        if st_type == SR_STLV_SID_LABEL and pos + st_len <= len(data):
            if st_len == 3:
                start = struct.unpack("!I", b'\x00' + data[pos:pos+3])[0]
            elif st_len == 4:
                start = struct.unpack_from("!I", data, pos)[0]
    return SidLabelRange(start=start, size=range_size)


def _encode_sid_label_range(r: SidLabelRange) -> bytes:
    """Encode a SID/Label Range TLV value."""
    range_bytes = struct.pack("!I", r.size)[1:]  # 3 bytes
    label_bytes = struct.pack("!I", r.start)[1:]  # 3 bytes
    stlv = encode_tlv(SR_STLV_SID_LABEL, label_bytes)
    return range_bytes + stlv


@dataclass
class ExtendedPrefixLsa:
    """Parsed Extended Prefix LSA body."""
    prefixes: list[ExtendedPrefixEntry] = field(default_factory=list)

    @classmethod
    def deserialize(cls, data: bytes) -> ExtendedPrefixLsa:
        lsa = cls()
        for tlv_type, value in parse_tlvs(data):
            if tlv_type == EP_TLV_EXTENDED_PREFIX:
                try:
                    lsa.prefixes.append(ExtendedPrefixEntry.deserialize(value))
                except Exception as e:
                    logger.debug("Error parsing Extended Prefix TLV: %s", e)
        return lsa


@dataclass
class ExtendedLinkLsa:
    """Parsed Extended Link LSA body."""
    links: list[ExtendedLinkEntry] = field(default_factory=list)

    @classmethod
    def deserialize(cls, data: bytes) -> ExtendedLinkLsa:
        lsa = cls()
        for tlv_type, value in parse_tlvs(data):
            if tlv_type == EL_TLV_EXTENDED_LINK:
                try:
                    lsa.links.append(ExtendedLinkEntry.deserialize(value))
                except Exception as e:
                    logger.debug("Error parsing Extended Link TLV: %s", e)
        return lsa


def opaque_type_from_lsa_id(link_state_id: IPv4Address) -> int:
    """Extract opaque type (upper 8 bits) from link_state_id."""
    return (int(link_state_id) >> 24) & 0xFF


def opaque_id_from_lsa_id(link_state_id: IPv4Address) -> int:
    """Extract opaque ID (lower 24 bits) from link_state_id."""
    return int(link_state_id) & 0x00FFFFFF


def make_opaque_lsa_id(opaque_type: int, opaque_id: int) -> IPv4Address:
    """Build link_state_id for an opaque LSA."""
    return IPv4Address((opaque_type << 24) | (opaque_id & 0x00FFFFFF))
