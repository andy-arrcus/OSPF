"""OSPF v2 common packet header (24 bytes).

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version #   |     Type      |         Packet length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Router ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Area ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |             AuType            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from ospfd.const import AUTH_NONE, OSPF_VERSION

OSPF_HDR_FORMAT = "!BBH4s4sHH8s"
OSPF_HDR_LEN = 24


@dataclass
class OspfHeader:
    """OSPF v2 common packet header."""

    version: int
    type: int
    length: int
    router_id: IPv4Address
    area_id: IPv4Address
    checksum: int
    auth_type: int
    auth_data: bytes

    def serialize(self) -> bytes:
        """Serialize header to 24 bytes."""
        return struct.pack(
            OSPF_HDR_FORMAT,
            self.version,
            self.type,
            self.length,
            self.router_id.packed,
            self.area_id.packed,
            self.checksum,
            self.auth_type,
            self.auth_data,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> OspfHeader:
        """Deserialize 24 bytes into an OspfHeader."""
        if len(data) < OSPF_HDR_LEN:
            raise ValueError(f"OSPF header requires {OSPF_HDR_LEN} bytes, got {len(data)}")
        (
            version,
            pkt_type,
            length,
            router_id_bytes,
            area_id_bytes,
            checksum,
            auth_type,
            auth_data,
        ) = struct.unpack(OSPF_HDR_FORMAT, data[:OSPF_HDR_LEN])
        return cls(
            version=version,
            type=pkt_type,
            length=length,
            router_id=IPv4Address(router_id_bytes),
            area_id=IPv4Address(area_id_bytes),
            checksum=checksum,
            auth_type=auth_type,
            auth_data=auth_data,
        )

    @classmethod
    def build(
        cls,
        pkt_type: int,
        router_id: IPv4Address,
        area_id: IPv4Address,
        auth_type: int = AUTH_NONE,
        auth_data: bytes = b"\x00" * 8,
    ) -> OspfHeader:
        """Create a header with version preset. Length and checksum filled later."""
        return cls(
            version=OSPF_VERSION,
            type=pkt_type,
            length=0,  # filled by caller
            router_id=router_id,
            area_id=area_id,
            checksum=0,  # filled after serialization
            auth_type=auth_type,
            auth_data=auth_data,
        )
