"""SR label stack computation post-SPF.

After standard Dijkstra SPF runs, this module uses the SR database
to compute MPLS label stacks for each SR-reachable destination.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, TYPE_CHECKING

from ospfd.const import (
    MPLS_LABEL_IMPLICIT_NULL,
    PREFIX_SID_FLAG_NP,
    PREFIX_SID_FLAG_V,
    ADJ_SID_FLAG_V,
)

if TYPE_CHECKING:
    from ospfd.sr.database import SrDatabase, NodeSrInfo
    from ospfd.spf.dijkstra import SpfVertex
    from ospfd.sr.tlv import PrefixSid

logger = logging.getLogger(__name__)


@dataclass
class SrRoute:
    """An SR-computed route with MPLS label stack."""
    destination: IPv4Network
    nexthop_ip: IPv4Address
    nexthop_intf: str
    outgoing_label: int       # label to push when forwarding
    dest_router_id: IPv4Address
    metric: int


def compute_sr_routes(
    spf_tree: dict[IPv4Address, SpfVertex],
    sr_db: SrDatabase,
    my_router_id: IPv4Address,
    my_srgb_start: int,
) -> list[SrRoute]:
    """Compute SR MPLS routes for all reachable SR-capable nodes.

    For each router in the SPF tree that has SR info:
    1. Determine the outgoing label:
       - If the nexthop router supports SR and the dest uses a global SID:
         outgoing = nexthop_srgb.start + sid_index
       - If dest is the nexthop (one hop away) and no-PHP not set:
         outgoing = IMPLICIT_NULL (PHP)
    """
    routes: list[SrRoute] = []

    for vertex_id, vertex in spf_tree.items():
        node = sr_db.get_node(vertex_id)
        if not node or not node.node_sids:
            continue

        for net, psid in node.node_sids:
            label = _compute_outgoing_label(vertex, psid, node, spf_tree, sr_db)
            if label is None:
                continue

            for nexthop in vertex.nexthops:
                routes.append(SrRoute(
                    destination=net,
                    nexthop_ip=nexthop.next_hop_ip,
                    nexthop_intf=nexthop.interface_name,
                    outgoing_label=label,
                    dest_router_id=vertex_id,
                    metric=vertex.distance,
                ))

    return routes


def _compute_outgoing_label(
    vertex: SpfVertex,
    psid: PrefixSid,
    dest_node: NodeSrInfo,
    spf_tree: dict[IPv4Address, SpfVertex],
    sr_db: SrDatabase,
) -> Optional[int]:
    """Determine the outgoing MPLS label for a Prefix-SID."""
    if psid.flags & PREFIX_SID_FLAG_V:
        # Absolute label value
        incoming_label = psid.sid
    else:
        # Global SID index: use destination router's SRGB
        if not dest_node.srgb:
            return None
        if not dest_node.srgb.contains(psid.sid):
            return None
        incoming_label = dest_node.srgb.label_for_index(psid.sid)

    # PHP: if nexthop IS the destination and no-PHP not set, use implicit-null
    if not (psid.flags & PREFIX_SID_FLAG_NP):
        # Check if destination is directly adjacent
        if vertex.parent is None:
            # This is the root (us) — skip
            return None
        if vertex.parent.vertex_id is None or str(vertex.parent.vertex_id) == "0.0.0.0":
            return MPLS_LABEL_IMPLICIT_NULL

    return incoming_label
