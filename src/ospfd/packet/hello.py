"""OSPF Hello packet (Type 1) per RFC 2328 Section A.3.2.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Network Mask                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         HelloInterval         |    Options    |    Rtr Pri    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     RouterDeadInterval                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Designated Router                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Backup Designated Router                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Neighbor                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address

HELLO_FORMAT = "!4sHBBI4s4s"
HELLO_FIXED_LEN = 20


@dataclass
class HelloPacket:
    """OSPF Hello packet body."""

    network_mask: IPv4Address
    hello_interval: int
    options: int
    priority: int
    dead_interval: int
    designated_router: IPv4Address
    backup_designated_router: IPv4Address
    neighbors: list[IPv4Address] = field(default_factory=list)

    def serialize(self) -> bytes:
        data = struct.pack(
            HELLO_FORMAT,
            self.network_mask.packed,
            self.hello_interval,
            self.options,
            self.priority,
            self.dead_interval,
            self.designated_router.packed,
            self.backup_designated_router.packed,
        )
        for nbr in self.neighbors:
            data += nbr.packed
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> HelloPacket:
        (
            mask_bytes, hello_int, options, priority, dead_int,
            dr_bytes, bdr_bytes,
        ) = struct.unpack_from(HELLO_FORMAT, data, offset)
        neighbors = []
        pos = offset + HELLO_FIXED_LEN
        while pos + 4 <= len(data):
            neighbors.append(IPv4Address(data[pos : pos + 4]))
            pos += 4
        return cls(
            network_mask=IPv4Address(mask_bytes),
            hello_interval=hello_int,
            options=options,
            priority=priority,
            dead_interval=dead_int,
            designated_router=IPv4Address(dr_bytes),
            backup_designated_router=IPv4Address(bdr_bytes),
            neighbors=neighbors,
        )
