"""OSPF Database Description packet (Type 2) per RFC 2328 Section A.3.3.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     DD sequence number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-                                                             -+
|                                                               |
+-                      An LSA Header                          -+
|                                                               |
+-                                                             -+
|                                                               |
+-                                                             -+
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address

from ospfd.const import DD_FLAG_I, DD_FLAG_M, DD_FLAG_MS
from ospfd.packet.lsa import LsaHeader, LSA_HDR_LEN

DD_FORMAT = "!HBBi"
DD_FIXED_LEN = 8


@dataclass
class DDPacket:
    """OSPF Database Description packet body."""

    interface_mtu: int
    options: int
    flags: int           # I, M, MS bits
    dd_seq_number: int   # unsigned but stored as signed for struct 'i'
    lsa_headers: list[LsaHeader] = field(default_factory=list)

    @property
    def is_init(self) -> bool:
        return bool(self.flags & DD_FLAG_I)

    @property
    def is_more(self) -> bool:
        return bool(self.flags & DD_FLAG_M)

    @property
    def is_master(self) -> bool:
        return bool(self.flags & DD_FLAG_MS)

    def serialize(self) -> bytes:
        data = struct.pack(
            DD_FORMAT,
            self.interface_mtu,
            self.options,
            self.flags,
            self.dd_seq_number,
        )
        for hdr in self.lsa_headers:
            data += hdr.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> DDPacket:
        mtu, options, flags, seq_num = struct.unpack_from(DD_FORMAT, data, offset)
        headers = []
        pos = offset + DD_FIXED_LEN
        while pos + LSA_HDR_LEN <= len(data):
            headers.append(LsaHeader.deserialize(data[pos:]))
            pos += LSA_HDR_LEN
        return cls(
            interface_mtu=mtu,
            options=options,
            flags=flags,
            dd_seq_number=seq_num,
            lsa_headers=headers,
        )
