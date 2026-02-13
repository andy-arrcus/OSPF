"""OSPF Link State Acknowledgment packet (Type 5) per RFC 2328 Section A.3.6.

The body is simply a list of LSA headers (20 bytes each).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ospfd.packet.lsa import LsaHeader, LSA_HDR_LEN


@dataclass
class LsackPacket:
    """OSPF Link State Acknowledgment packet body."""

    lsa_headers: list[LsaHeader] = field(default_factory=list)

    def serialize(self) -> bytes:
        data = b""
        for hdr in self.lsa_headers:
            data += hdr.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> LsackPacket:
        headers = []
        pos = offset
        while pos + LSA_HDR_LEN <= len(data):
            headers.append(LsaHeader.deserialize(data[pos:]))
            pos += LSA_HDR_LEN
        return cls(lsa_headers=headers)
