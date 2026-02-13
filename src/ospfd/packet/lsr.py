"""OSPF Link State Request packet (Type 3) per RFC 2328 Section A.3.4.

Each request item is 12 bytes:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          LS type                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Link State ID                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Advertising Router                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address

LSR_ITEM_FORMAT = "!I4s4s"
LSR_ITEM_LEN = 12


@dataclass
class LsrItem:
    """A single LS Request item."""

    ls_type: int
    link_state_id: IPv4Address
    advertising_router: IPv4Address

    def serialize(self) -> bytes:
        return struct.pack(
            LSR_ITEM_FORMAT,
            self.ls_type,
            self.link_state_id.packed,
            self.advertising_router.packed,
        )

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> LsrItem:
        ls_type, ls_id_bytes, adv_rtr_bytes = struct.unpack_from(
            LSR_ITEM_FORMAT, data, offset
        )
        return cls(
            ls_type=ls_type,
            link_state_id=IPv4Address(ls_id_bytes),
            advertising_router=IPv4Address(adv_rtr_bytes),
        )

    @property
    def key(self) -> tuple[int, IPv4Address, IPv4Address]:
        return (self.ls_type, self.link_state_id, self.advertising_router)


@dataclass
class LsrPacket:
    """OSPF Link State Request packet body."""

    items: list[LsrItem] = field(default_factory=list)

    def serialize(self) -> bytes:
        data = b""
        for item in self.items:
            data += item.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> LsrPacket:
        items = []
        pos = offset
        while pos + LSR_ITEM_LEN <= len(data):
            items.append(LsrItem.deserialize(data, pos))
            pos += LSR_ITEM_LEN
        return cls(items=items)
