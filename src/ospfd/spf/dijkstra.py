"""Dijkstra's SPF algorithm per RFC 2328 Section 16.1.

Computes the shortest path tree from the root (this router)
using Router LSAs and Network LSAs from the LSDB.
"""

from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import Optional

from ospfd.const import (
    LINK_TYPE_P2P,
    LINK_TYPE_STUB,
    LINK_TYPE_TRANSIT,
    LSA_TYPE_NETWORK,
    LSA_TYPE_ROUTER,
    MAX_AGE,
    SPF_VERTEX_NETWORK,
    SPF_VERTEX_ROUTER,
)
from ospfd.packet.lsa import Lsa, NetworkLsa, RouterLsa, RouterLsaLink

logger = logging.getLogger(__name__)


@dataclass
class SpfNexthop:
    """A single nexthop: the outgoing interface and next-hop IP address."""
    interface_name: str
    next_hop_ip: IPv4Address
    interface_index: int = 0

    def __hash__(self) -> int:
        return hash((self.interface_name, self.next_hop_ip))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SpfNexthop):
            return NotImplemented
        return (self.interface_name == other.interface_name
                and self.next_hop_ip == other.next_hop_ip)


@dataclass
class SpfVertex:
    """A vertex in the SPF tree."""
    vertex_id: IPv4Address
    vertex_type: int  # SPF_VERTEX_ROUTER or SPF_VERTEX_NETWORK
    lsa: Lsa
    distance: int = 0
    parent: Optional[SpfVertex] = field(default=None, repr=False)
    nexthops: set[SpfNexthop] = field(default_factory=set)

    def __lt__(self, other: SpfVertex) -> bool:
        return self.distance < other.distance


class DijkstraEngine:
    """Implements Dijkstra's SPF algorithm per Section 16.1."""

    def __init__(self, instance):
        self._instance = instance

    def calculate(self, area_id: IPv4Address) -> dict[IPv4Address, SpfVertex]:
        """Run Dijkstra for one area.

        Returns dict mapping vertex_id -> SpfVertex for the SPF tree.
        """
        instance = self._instance
        lsdb = instance.lsdb
        router_id = instance.router_id

        # Find our own Router LSA
        root_key = (LSA_TYPE_ROUTER, router_id, router_id)
        root_lsa = lsdb.lookup(area_id, root_key)
        if root_lsa is None or root_lsa.current_age >= MAX_AGE:
            logger.warning("No valid Router LSA for self in area %s", area_id)
            return {}

        root = SpfVertex(
            vertex_id=router_id,
            vertex_type=SPF_VERTEX_ROUTER,
            lsa=root_lsa,
            distance=0,
        )

        # SPF tree: vertex_id -> SpfVertex
        tree: dict[IPv4Address, SpfVertex] = {}
        # Candidate list (priority queue)
        candidates: list[tuple[int, int, SpfVertex]] = []
        counter = 0  # tie-breaker for heapq

        # Initialize with root
        heapq.heappush(candidates, (0, counter, root))
        counter += 1

        while candidates:
            dist, _, vertex = heapq.heappop(candidates)

            if vertex.vertex_id in tree:
                continue

            tree[vertex.vertex_id] = vertex

            # Examine links from this vertex
            if vertex.vertex_type == SPF_VERTEX_ROUTER:
                self._process_router_vertex(
                    vertex, area_id, lsdb, tree, candidates, counter, instance
                )
            elif vertex.vertex_type == SPF_VERTEX_NETWORK:
                self._process_network_vertex(
                    vertex, area_id, lsdb, tree, candidates, counter, instance
                )

            # counter may have been updated in the process methods
            # We use a mutable list trick for counter
            # Actually, let's just use a different approach:
            counter = self._counter

        logger.debug("SPF for area %s: %d vertices in tree", area_id, len(tree))
        return tree

    def _process_router_vertex(
        self, vertex: SpfVertex, area_id: IPv4Address,
        lsdb, tree, candidates, counter, instance
    ) -> None:
        """Process links from a Router LSA vertex."""
        self._counter = counter
        if not isinstance(vertex.lsa.body, RouterLsa):
            return

        for link in vertex.lsa.body.links:
            if link.type == LINK_TYPE_STUB:
                # Stub networks are handled in route extraction, not SPF tree
                continue

            if link.type == LINK_TYPE_TRANSIT:
                # Transit network: find the Network LSA
                net_lsa_key = (LSA_TYPE_NETWORK, link.link_id, link.link_id)
                # Actually, for transit links, link_id is the DR's interface IP
                # We need to find the Network LSA where link_state_id = DR's IP
                # and advertising_router = DR's router ID
                # But we don't know the DR's router ID — search by link_state_id
                net_lsa = self._find_network_lsa(area_id, link.link_id, lsdb)
                if net_lsa is None or net_lsa.current_age >= MAX_AGE:
                    continue
                if net_lsa.header.link_state_id in tree:
                    continue

                new_dist = vertex.distance + link.metric
                self._update_candidate(
                    candidates, tree, net_lsa.header.link_state_id,
                    SPF_VERTEX_NETWORK, net_lsa, new_dist, vertex, instance, link
                )

            elif link.type == LINK_TYPE_P2P:
                # P2P: find the neighbor's Router LSA
                nbr_key = (LSA_TYPE_ROUTER, link.link_id, link.link_id)
                nbr_lsa = lsdb.lookup(area_id, nbr_key)
                if nbr_lsa is None or nbr_lsa.current_age >= MAX_AGE:
                    continue
                if link.link_id in tree:
                    continue

                new_dist = vertex.distance + link.metric
                self._update_candidate(
                    candidates, tree, link.link_id,
                    SPF_VERTEX_ROUTER, nbr_lsa, new_dist, vertex, instance, link
                )

    def _process_network_vertex(
        self, vertex: SpfVertex, area_id: IPv4Address,
        lsdb, tree, candidates, counter, instance
    ) -> None:
        """Process links from a Network LSA vertex."""
        self._counter = counter
        if not isinstance(vertex.lsa.body, NetworkLsa):
            return

        for rtr_id in vertex.lsa.body.attached_routers:
            if rtr_id in tree:
                continue

            rtr_key = (LSA_TYPE_ROUTER, rtr_id, rtr_id)
            rtr_lsa = lsdb.lookup(area_id, rtr_key)
            if rtr_lsa is None or rtr_lsa.current_age >= MAX_AGE:
                continue

            new_dist = vertex.distance + 0  # Network vertex to router is cost 0
            self._update_candidate(
                candidates, tree, rtr_id,
                SPF_VERTEX_ROUTER, rtr_lsa, new_dist, vertex, instance, None
            )

    def _update_candidate(
        self, candidates, tree, vertex_id, vertex_type,
        lsa, new_dist, parent, instance, link
    ) -> None:
        """Add or update a candidate vertex."""
        # Calculate nexthops
        nexthops = self._calculate_nexthops(parent, vertex_id, instance, link)
        if not nexthops:
            nexthops = parent.nexthops.copy()

        # Check if already a candidate with higher distance
        # (We use lazy deletion with the heap)
        new_vertex = SpfVertex(
            vertex_id=vertex_id,
            vertex_type=vertex_type,
            lsa=lsa,
            distance=new_dist,
            parent=parent,
            nexthops=nexthops,
        )

        heapq.heappush(candidates, (new_dist, self._counter, new_vertex))
        self._counter += 1

    def _calculate_nexthops(
        self, parent: SpfVertex, dest_id: IPv4Address,
        instance, link: Optional[RouterLsaLink]
    ) -> set[SpfNexthop]:
        """Calculate nexthops for a vertex.

        If the vertex is directly connected, the nexthop is determined
        from the interface. Otherwise, inherit nexthops from the parent.
        """
        if parent.distance == 0 and parent.parent is None:
            # Parent is root — this vertex is directly connected
            return self._get_direct_nexthops(dest_id, instance, link)

        # Inherit from parent
        return parent.nexthops.copy()

    def _get_direct_nexthops(
        self, dest_id: IPv4Address, instance, link: Optional[RouterLsaLink]
    ) -> set[SpfNexthop]:
        """Get nexthops for a directly connected vertex."""
        nexthops: set[SpfNexthop] = set()

        for area in instance.areas.values():
            for intf in area.interfaces:
                if link and link.type == LINK_TYPE_P2P:
                    # P2P: nexthop is the neighbor's IP
                    for nbr in intf.neighbors.values():
                        if nbr.router_id == dest_id:
                            nexthops.add(SpfNexthop(
                                interface_name=intf.name,
                                next_hop_ip=nbr.ip_addr,
                                interface_index=intf.if_index,
                            ))
                elif link and link.type == LINK_TYPE_TRANSIT:
                    # Transit: nexthop is on the shared network
                    # If we are DR, nexthop is 0.0.0.0 (connected)
                    if intf.dr == link.link_id or intf.ip_addr == link.link_id:
                        nexthops.add(SpfNexthop(
                            interface_name=intf.name,
                            next_hop_ip=IPv4Address("0.0.0.0"),
                            interface_index=intf.if_index,
                        ))

        return nexthops

    def _find_network_lsa(
        self, area_id: IPv4Address, dr_ip: IPv4Address, lsdb
    ) -> Optional[Lsa]:
        """Find a Network LSA by the DR's interface IP address."""
        for lsa in lsdb.get_all(area_id, LSA_TYPE_NETWORK):
            if lsa.header.link_state_id == dr_ip:
                return lsa
        return None
