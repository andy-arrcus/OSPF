"""OSPF LSA header and body types (RFC 2328 Section 12.1).

LSA Header (20 bytes):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            LS age             |    Options    |    LS type    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Link State ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Advertising Router                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     LS sequence number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         LS checksum           |             length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

LSA body types:
  Type 1: Router LSA
  Type 2: Network LSA
  Type 3: Summary LSA (Network)
  Type 4: Summary LSA (ASBR)
  Type 5: AS External LSA
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Optional, Union

from ospfd.const import (
    INITIAL_SEQ_NUM,
    LINK_TYPE_P2P,
    LINK_TYPE_STUB,
    LINK_TYPE_TRANSIT,
    LINK_TYPE_VIRTUAL,
    LSA_TYPE_ASBR_SUMMARY,
    LSA_TYPE_EXTERNAL,
    LSA_TYPE_NETWORK,
    LSA_TYPE_ROUTER,
    LSA_TYPE_SUMMARY,
    MAX_AGE,
)
from ospfd.packet.checksum import fletcher_checksum

# ── LSA Header ──────────────────────────────────────────────────────────────

LSA_HDR_FORMAT = "!HBB4s4sIHH"
LSA_HDR_LEN = 20


@dataclass
class LsaHeader:
    """20-byte LSA header common to all LSA types."""

    ls_age: int                      # 2 bytes
    options: int                     # 1 byte
    ls_type: int                     # 1 byte
    link_state_id: IPv4Address       # 4 bytes
    advertising_router: IPv4Address  # 4 bytes
    ls_sequence_number: int          # 4 bytes (signed 32-bit)
    ls_checksum: int                 # 2 bytes (Fletcher)
    length: int                      # 2 bytes

    def serialize(self) -> bytes:
        """Serialize to 20 bytes."""
        return struct.pack(
            LSA_HDR_FORMAT,
            self.ls_age,
            self.options,
            self.ls_type,
            self.link_state_id.packed,
            self.advertising_router.packed,
            self.ls_sequence_number,
            self.ls_checksum,
            self.length,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> LsaHeader:
        """Deserialize 20 bytes into an LsaHeader."""
        if len(data) < LSA_HDR_LEN:
            raise ValueError(f"LSA header requires {LSA_HDR_LEN} bytes, got {len(data)}")
        (
            ls_age, options, ls_type,
            ls_id_bytes, adv_rtr_bytes,
            seq_num, checksum, length,
        ) = struct.unpack(LSA_HDR_FORMAT, data[:LSA_HDR_LEN])
        return cls(
            ls_age=ls_age,
            options=options,
            ls_type=ls_type,
            link_state_id=IPv4Address(ls_id_bytes),
            advertising_router=IPv4Address(adv_rtr_bytes),
            ls_sequence_number=seq_num,
            ls_checksum=checksum,
            length=length,
        )

    @property
    def key(self) -> tuple[int, IPv4Address, IPv4Address]:
        """Unique key for LSDB lookup: (ls_type, link_state_id, advertising_router)."""
        return (self.ls_type, self.link_state_id, self.advertising_router)

    def is_maxage(self) -> bool:
        return self.ls_age >= MAX_AGE


# ── Router LSA (Type 1) ────────────────────────────────────────────────────

# Router LSA flags
ROUTER_FLAG_V = 0x04  # Virtual link endpoint
ROUTER_FLAG_E = 0x02  # AS Boundary Router (ASBR)
ROUTER_FLAG_B = 0x01  # Area Border Router (ABR)

ROUTER_LSA_BODY_FORMAT = "!BBH"  # flags(1), reserved(1), num_links(2)
ROUTER_LSA_BODY_LEN = 4

ROUTER_LINK_FORMAT = "!4s4sBBH"  # link_id(4), link_data(4), type(1), num_tos(1), metric(2)
ROUTER_LINK_LEN = 12

TOS_METRIC_FORMAT = "!BBH"  # tos(1), reserved(1), tos_metric(2)
TOS_METRIC_LEN = 4


@dataclass
class RouterLsaLink:
    """A single link in a Router LSA."""

    link_id: IPv4Address     # 4 bytes - depends on link type
    link_data: IPv4Address   # 4 bytes - depends on link type
    type: int                # 1 byte  - LINK_TYPE_P2P/TRANSIT/STUB/VIRTUAL
    num_tos: int             # 1 byte  - number of TOS metrics (usually 0)
    metric: int              # 2 bytes - cost of this link
    tos_metrics: list[tuple[int, int]] = field(default_factory=list)  # (tos, metric) pairs

    def serialize(self) -> bytes:
        data = struct.pack(
            ROUTER_LINK_FORMAT,
            self.link_id.packed,
            self.link_data.packed,
            self.type,
            self.num_tos,
            self.metric,
        )
        for tos, metric in self.tos_metrics:
            data += struct.pack(TOS_METRIC_FORMAT, tos, 0, metric)
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> tuple[RouterLsaLink, int]:
        """Deserialize a router link. Returns (link, bytes_consumed)."""
        link_id_bytes, link_data_bytes, ltype, num_tos, metric = struct.unpack_from(
            ROUTER_LINK_FORMAT, data, offset
        )
        tos_metrics = []
        pos = offset + ROUTER_LINK_LEN
        for _ in range(num_tos):
            tos, _, tos_metric = struct.unpack_from(TOS_METRIC_FORMAT, data, pos)
            tos_metrics.append((tos, tos_metric))
            pos += TOS_METRIC_LEN
        link = cls(
            link_id=IPv4Address(link_id_bytes),
            link_data=IPv4Address(link_data_bytes),
            type=ltype,
            num_tos=num_tos,
            metric=metric,
            tos_metrics=tos_metrics,
        )
        return link, pos - offset


@dataclass
class RouterLsa:
    """Type 1: Router LSA body."""

    flags: int                       # V, E, B bits
    num_links: int                   # number of links
    links: list[RouterLsaLink] = field(default_factory=list)

    def serialize(self) -> bytes:
        data = struct.pack(ROUTER_LSA_BODY_FORMAT, self.flags, 0, self.num_links)
        for link in self.links:
            data += link.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> RouterLsa:
        flags, _, num_links = struct.unpack_from(ROUTER_LSA_BODY_FORMAT, data, offset)
        pos = offset + ROUTER_LSA_BODY_LEN
        links = []
        for _ in range(num_links):
            link, consumed = RouterLsaLink.deserialize(data, pos)
            links.append(link)
            pos += consumed
        return cls(flags=flags, num_links=num_links, links=links)


# ── Network LSA (Type 2) ───────────────────────────────────────────────────

@dataclass
class NetworkLsa:
    """Type 2: Network LSA body."""

    network_mask: IPv4Address                             # 4 bytes
    attached_routers: list[IPv4Address] = field(default_factory=list)  # 4 bytes each

    def serialize(self) -> bytes:
        data = self.network_mask.packed
        for rtr in self.attached_routers:
            data += rtr.packed
        return data

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0, length: int = 0) -> NetworkLsa:
        """Deserialize. `length` is the body length (total LSA length - 20)."""
        mask = IPv4Address(data[offset : offset + 4])
        routers = []
        pos = offset + 4
        end = offset + length if length else len(data)
        while pos + 4 <= end:
            routers.append(IPv4Address(data[pos : pos + 4]))
            pos += 4
        return cls(network_mask=mask, attached_routers=routers)


# ── Summary LSA (Type 3 and 4) ─────────────────────────────────────────────

SUMMARY_LSA_BODY_FORMAT = "!4sBBH"  # mask(4), reserved(1), reserved(1), metric_high_reserved...
# Actually: mask(4), then 1 byte zero, then 3 bytes metric
# We'll handle it manually

@dataclass
class SummaryLsa:
    """Type 3 (Network Summary) and Type 4 (ASBR Summary) LSA body."""

    network_mask: IPv4Address   # 4 bytes
    metric: int                 # 24 bits (3 bytes, preceded by 1 zero byte)

    def serialize(self) -> bytes:
        # 4 bytes mask + 1 byte zero + 3 bytes metric
        return self.network_mask.packed + struct.pack("!I", self.metric & 0x00FFFFFF)

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> SummaryLsa:
        mask = IPv4Address(data[offset : offset + 4])
        metric_word = struct.unpack_from("!I", data, offset + 4)[0]
        metric = metric_word & 0x00FFFFFF
        return cls(network_mask=mask, metric=metric)


# ── AS External LSA (Type 5) ───────────────────────────────────────────────

@dataclass
class ExternalLsa:
    """Type 5: AS External LSA body."""

    network_mask: IPv4Address       # 4 bytes
    e_bit: bool                     # 1 bit (high bit of metric field)
    metric: int                     # 24 bits
    forwarding_address: IPv4Address  # 4 bytes
    external_route_tag: int         # 4 bytes

    def serialize(self) -> bytes:
        metric_word = self.metric & 0x00FFFFFF
        if self.e_bit:
            metric_word |= 0x80000000
        return (
            self.network_mask.packed
            + struct.pack("!I", metric_word)
            + self.forwarding_address.packed
            + struct.pack("!I", self.external_route_tag)
        )

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> ExternalLsa:
        mask = IPv4Address(data[offset : offset + 4])
        metric_word = struct.unpack_from("!I", data, offset + 4)[0]
        e_bit = bool(metric_word & 0x80000000)
        metric = metric_word & 0x00FFFFFF
        fwd_addr = IPv4Address(data[offset + 8 : offset + 12])
        tag = struct.unpack_from("!I", data, offset + 12)[0]
        return cls(
            network_mask=mask,
            e_bit=e_bit,
            metric=metric,
            forwarding_address=fwd_addr,
            external_route_tag=tag,
        )


# ── Full LSA (Header + Body) ───────────────────────────────────────────────

LsaBody = Union[RouterLsa, NetworkLsa, SummaryLsa, ExternalLsa]

_BODY_DESERIALIZERS = {
    LSA_TYPE_ROUTER: RouterLsa.deserialize,
    LSA_TYPE_NETWORK: NetworkLsa.deserialize,
    LSA_TYPE_SUMMARY: SummaryLsa.deserialize,
    LSA_TYPE_ASBR_SUMMARY: SummaryLsa.deserialize,
    LSA_TYPE_EXTERNAL: ExternalLsa.deserialize,
}


@dataclass
class Lsa:
    """Complete LSA: header + body.

    Also tracks installation metadata for age computation.
    """

    header: LsaHeader
    body: Optional[LsaBody] = None

    # Installation metadata (not serialized)
    install_time: Optional[float] = field(default=None, repr=False)
    installed_age: int = field(default=0, repr=False)

    @property
    def key(self) -> tuple[int, IPv4Address, IPv4Address]:
        return self.header.key

    @property
    def current_age(self) -> int:
        """Compute current age based on installation time."""
        if self.install_time is None:
            return self.header.ls_age
        elapsed = int(time.monotonic() - self.install_time)
        return min(self.installed_age + elapsed, MAX_AGE)

    def serialize(self, recompute_checksum: bool = True) -> bytes:
        """Serialize complete LSA (header + body).

        If recompute_checksum is True, updates the header length,
        age (from current_age), and recomputes the Fletcher checksum.
        """
        body_bytes = self.body.serialize() if self.body else b""
        total_len = LSA_HDR_LEN + len(body_bytes)

        self.header.length = total_len
        self.header.ls_age = min(self.current_age, MAX_AGE)

        if recompute_checksum:
            self.header.ls_checksum = 0
            raw = self.header.serialize() + body_bytes
            self.header.ls_checksum = fletcher_checksum(raw)

        return self.header.serialize() + body_bytes

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> tuple[Lsa, int]:
        """Deserialize a complete LSA from data.

        Returns (Lsa, bytes_consumed).
        """
        header = LsaHeader.deserialize(data[offset:])
        body_offset = offset + LSA_HDR_LEN
        body_len = header.length - LSA_HDR_LEN
        body: Optional[LsaBody] = None

        deserializer = _BODY_DESERIALIZERS.get(header.ls_type)
        if deserializer and body_len > 0:
            if header.ls_type == LSA_TYPE_NETWORK:
                body = deserializer(data, body_offset, length=body_len)
            else:
                body = deserializer(data, body_offset)

        lsa = cls(header=header, body=body)
        return lsa, header.length

    def mark_installed(self) -> None:
        """Record installation timestamp for age tracking."""
        self.installed_age = self.header.ls_age
        self.install_time = time.monotonic()
