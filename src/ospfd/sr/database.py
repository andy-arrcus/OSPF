"""SR Information Database.

Scans the LSDB for SR-related Opaque LSAs and builds a per-router
view of SR capabilities, SRGBs, Node-SIDs, and Adj-SIDs.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, TYPE_CHECKING

from ospfd.const import (
    LSA_TYPE_OPAQUE_AREA,
    OPAQUE_TYPE_RI,
    OPAQUE_TYPE_EXTENDED_PREFIX,
    OPAQUE_TYPE_EXTENDED_LINK,
)
from ospfd.sr.lsa import (
    RouterInfoLsa, ExtendedPrefixLsa, ExtendedLinkLsa,
    opaque_type_from_lsa_id,
)
from ospfd.sr.tlv import SidLabelRange, PrefixSid, AdjSid

if TYPE_CHECKING:
    from ospfd.lsdb.database import LinkStateDatabase

logger = logging.getLogger(__name__)


@dataclass
class NodeSrInfo:
    """SR information collected for a single router."""
    router_id: IPv4Address
    srgb: Optional[SidLabelRange] = None
    algorithms: list[int] = field(default_factory=lambda: [0])
    node_sids: list[tuple[IPv4Network, PrefixSid]] = field(default_factory=list)
    adj_sids: list[tuple[IPv4Address, IPv4Address, AdjSid]] = field(default_factory=list)
    # adj_sids: list of (link_id, link_data, adj_sid)

    def label_for_prefix_sid(self, psid: PrefixSid) -> Optional[int]:
        """Compute MPLS label for a Prefix-SID."""
        from ospfd.const import PREFIX_SID_FLAG_V
        if psid.flags & PREFIX_SID_FLAG_V:
            return psid.sid  # absolute label
        if self.srgb and self.srgb.contains(psid.sid):
            return self.srgb.label_for_index(psid.sid)
        return None


class SrDatabase:
    """Aggregated SR topology view built from LSDB Opaque LSAs."""

    def __init__(self) -> None:
        self._nodes: dict[IPv4Address, NodeSrInfo] = {}

    def rebuild(self, lsdb: LinkStateDatabase, area_id: IPv4Address) -> None:
        """Scan the LSDB and rebuild the SR information database."""
        self._nodes.clear()

        lsas = lsdb.get_all(area_id, ls_type=LSA_TYPE_OPAQUE_AREA)
        for lsa in lsas:
            opaque_type = opaque_type_from_lsa_id(lsa.header.link_state_id)
            adv_router = lsa.header.advertising_router
            body_data = lsa.body.raw_data if hasattr(lsa.body, 'raw_data') else b""

            node = self._nodes.setdefault(adv_router, NodeSrInfo(router_id=adv_router))

            try:
                if opaque_type == OPAQUE_TYPE_RI:
                    ri = RouterInfoLsa.deserialize(body_data)
                    if ri.srgb:
                        node.srgb = ri.srgb
                    node.algorithms = ri.sr_algorithms

                elif opaque_type == OPAQUE_TYPE_EXTENDED_PREFIX:
                    ep = ExtendedPrefixLsa.deserialize(body_data)
                    for prefix_entry in ep.prefixes:
                        if prefix_entry.prefix_sid is not None:
                            net = IPv4Network(
                                f"{prefix_entry.prefix}/{prefix_entry.prefix_len}", strict=False
                            )
                            node.node_sids.append((net, prefix_entry.prefix_sid))

                elif opaque_type == OPAQUE_TYPE_EXTENDED_LINK:
                    el = ExtendedLinkLsa.deserialize(body_data)
                    for link_entry in el.links:
                        for asid in link_entry.adj_sids:
                            node.adj_sids.append(
                                (link_entry.link_id, link_entry.link_data, asid)
                            )
            except Exception as e:
                logger.debug("Error parsing SR opaque LSA from %s: %s", adv_router, e)

        logger.debug("SR database rebuilt: %d SR-capable nodes", len(self._nodes))

    def get_node(self, router_id: IPv4Address) -> Optional[NodeSrInfo]:
        return self._nodes.get(router_id)

    def get_all_nodes(self) -> list[NodeSrInfo]:
        return list(self._nodes.values())

    def get_prefix_label(
        self, dest_router_id: IPv4Address, prefix: IPv4Network
    ) -> Optional[int]:
        """Get the incoming MPLS label to reach a prefix at dest_router via SR."""
        node = self._nodes.get(dest_router_id)
        if not node:
            return None
        for net, psid in node.node_sids:
            if net == prefix:
                return node.label_for_prefix_sid(psid)
        return None
