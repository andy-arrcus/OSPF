"""OSPF Link State Update packet (Type 4) per RFC 2328 Section A.3.5.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            # LSAs                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-                                                             -+
|                             LSAs                              |
+-                                                             -+
|                              ...                              |
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ospfd.packet.lsa import Lsa

LSU_HEADER_FORMAT = "!I"
LSU_HEADER_LEN = 4


@dataclass
class LsuPacket:
    """OSPF Link State Update packet body."""

    lsas: list[Lsa] = field(default_factory=list)

    @property
    def num_lsas(self) -> int:
        return len(self.lsas)

    def serialize(self) -> bytes:
        data = struct.pack(LSU_HEADER_FORMAT, self.num_lsas)
        for lsa in self.lsas:
            data += lsa.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> LsuPacket:
        num_lsas = struct.unpack_from(LSU_HEADER_FORMAT, data, offset)[0]
        lsas = []
        pos = offset + LSU_HEADER_LEN
        for _ in range(num_lsas):
            lsa, consumed = Lsa.deserialize(data, pos)
            lsas.append(lsa)
            pos += consumed
        return cls(lsas=lsas)
