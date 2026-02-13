"""AS External route calculation per RFC 2328 Section 16.4.

Processes AS External LSAs (Type 5) to compute external routes.
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Optional

from ospfd.const import (
    LSA_TYPE_EXTERNAL,
    LSA_TYPE_ROUTER,
    MAX_AGE,
    PATH_TYPE1_EXTERNAL,
    PATH_TYPE2_EXTERNAL,
    ROUTER_FLAG_E,
)
from ospfd.packet.lsa import ExternalLsa, RouterLsa
from ospfd.spf.dijkstra import SpfNexthop, SpfVertex
from ospfd.spf.routing_table import OspfRoute
from ospfd.util.ip import mask_to_prefix_len

if TYPE_CHECKING:
    from ospfd.lsdb.database import LinkStateDatabase

logger = logging.getLogger(__name__)

ZERO_ADDR = IPv4Address("0.0.0.0")


def calculate_external_routes(
    lsdb: LinkStateDatabase,
    spf_trees: dict[IPv4Address, dict[IPv4Address, SpfVertex]],
    asbr_costs: dict[IPv4Address, int],
    intra_routes: list[OspfRoute],
    inter_routes: list[OspfRoute],
) -> list[OspfRoute]:
    """Calculate AS External routes from Type 5 LSAs.

    For each Type 5 LSA:
    1. Find the ASBR via intra-area SPF tree or ASBR summary routes.
    2. Calculate cost:
       - Type 1 (E1): cost = cost-to-ASBR + external metric
       - Type 2 (E2): primary sort by external metric, secondary by cost-to-ASBR
    3. If forwarding address != 0.0.0.0, route through it instead.

    Args:
        lsdb: The link state database.
        spf_trees: SPF trees per area.
        asbr_costs: Cost to reach each ASBR (from inter-area calculation).
        intra_routes: Intra-area routes.
        inter_routes: Inter-area routes.

    Returns:
        List of external OspfRoute objects.
    """
    routes: list[OspfRoute] = []

    for lsa in lsdb.get_all_external():
        if lsa.current_age >= MAX_AGE:
            continue
        if not isinstance(lsa.body, ExternalLsa):
            continue

        asbr_id = lsa.header.advertising_router
        fwd_addr = lsa.body.forwarding_address

        # Find cost to ASBR
        asbr_vertex = None
        asbr_cost = None
        asbr_nexthops: set[SpfNexthop] = set()

        # Check intra-area SPF trees first
        for area_id, tree in spf_trees.items():
            if asbr_id in tree:
                v = tree[asbr_id]
                if asbr_cost is None or v.distance < asbr_cost:
                    asbr_cost = v.distance
                    asbr_nexthops = v.nexthops.copy()

        # Check inter-area ASBR costs
        if asbr_id in asbr_costs:
            inter_cost = asbr_costs[asbr_id]
            if asbr_cost is None or inter_cost < asbr_cost:
                asbr_cost = inter_cost
                # Nexthops from inter-area would come from ABR — simplified
                # In practice, we'd need to look up the ABR in the SPF tree

        if asbr_cost is None:
            # ASBR not reachable
            continue

        # Handle forwarding address
        if fwd_addr != ZERO_ADDR:
            # Route through forwarding address instead of ASBR
            # Find the route to the forwarding address in intra/inter routes
            # Simplified: use the nexthops of the best matching route
            best_route = _find_route_to(fwd_addr, intra_routes + inter_routes)
            if best_route:
                asbr_nexthops = best_route.nexthops.copy()
                asbr_cost = best_route.cost

        # Build destination
        mask = lsa.body.network_mask
        prefix_len = mask_to_prefix_len(mask)
        destination = IPv4Network(
            f"{lsa.header.link_state_id}/{prefix_len}", strict=False
        )

        if lsa.body.e_bit:
            # Type 2 external
            route = OspfRoute(
                destination=destination,
                path_type=PATH_TYPE2_EXTERNAL,
                cost=asbr_cost,
                type2_cost=lsa.body.metric,
                area_id=ZERO_ADDR,
                nexthops=asbr_nexthops,
                advertising_router=asbr_id,
            )
        else:
            # Type 1 external
            route = OspfRoute(
                destination=destination,
                path_type=PATH_TYPE1_EXTERNAL,
                cost=asbr_cost + lsa.body.metric,
                type2_cost=0,
                area_id=ZERO_ADDR,
                nexthops=asbr_nexthops,
                advertising_router=asbr_id,
            )
        routes.append(route)

    return routes


def _find_route_to(addr: IPv4Address, routes: list[OspfRoute]) -> Optional[OspfRoute]:
    """Find the best (longest prefix match) route to an address."""
    best: Optional[OspfRoute] = None
    best_prefix = -1
    for route in routes:
        if addr in route.destination and route.destination.prefixlen > best_prefix:
            best = route
            best_prefix = route.destination.prefixlen
    return best
