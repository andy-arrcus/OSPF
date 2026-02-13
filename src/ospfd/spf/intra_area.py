"""Intra-area route calculation per RFC 2328 Section 16.1.

Extracts routes from the SPF tree produced by Dijkstra's algorithm.
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv4Network

from ospfd.const import (
    LINK_TYPE_STUB,
    LSA_TYPE_ROUTER,
    PATH_INTRA_AREA,
    SPF_VERTEX_NETWORK,
    SPF_VERTEX_ROUTER,
)
from ospfd.packet.lsa import NetworkLsa, RouterLsa
from ospfd.spf.dijkstra import SpfVertex
from ospfd.spf.routing_table import OspfRoute
from ospfd.util.ip import mask_to_prefix_len

logger = logging.getLogger(__name__)


def calculate_intra_area_routes(
    spf_tree: dict[IPv4Address, SpfVertex],
    area_id: IPv4Address,
) -> list[OspfRoute]:
    """Extract intra-area routes from the SPF tree.

    For each vertex in the tree:
    - Router vertex with stub links: create route to stub network
    - Network vertex: create route to the transit network
    """
    routes: list[OspfRoute] = []

    for vertex in spf_tree.values():
        if vertex.vertex_type == SPF_VERTEX_ROUTER:
            # Extract stub network routes from Router LSA
            if isinstance(vertex.lsa.body, RouterLsa):
                for link in vertex.lsa.body.links:
                    if link.type == LINK_TYPE_STUB:
                        prefix_len = mask_to_prefix_len(link.link_data)
                        network = IPv4Network(
                            f"{link.link_id}/{prefix_len}", strict=False
                        )
                        cost = vertex.distance + link.metric
                        route = OspfRoute(
                            destination=network,
                            path_type=PATH_INTRA_AREA,
                            cost=cost,
                            type2_cost=0,
                            area_id=area_id,
                            nexthops=vertex.nexthops.copy(),
                            advertising_router=vertex.vertex_id,
                        )
                        routes.append(route)

        elif vertex.vertex_type == SPF_VERTEX_NETWORK:
            # Route to the transit network itself
            if isinstance(vertex.lsa.body, NetworkLsa):
                mask = vertex.lsa.body.network_mask
                prefix_len = mask_to_prefix_len(mask)
                net_addr = IPv4Address(
                    int(vertex.vertex_id) & int(mask)
                )
                network = IPv4Network(
                    f"{net_addr}/{prefix_len}", strict=False
                )
                route = OspfRoute(
                    destination=network,
                    path_type=PATH_INTRA_AREA,
                    cost=vertex.distance,
                    type2_cost=0,
                    area_id=area_id,
                    nexthops=vertex.nexthops.copy(),
                    advertising_router=vertex.lsa.header.advertising_router,
                )
                routes.append(route)

    return routes
