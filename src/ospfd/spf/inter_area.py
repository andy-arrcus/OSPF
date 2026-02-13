"""Inter-area route calculation per RFC 2328 Section 16.2.

Processes Summary LSAs (Types 3 and 4) from other areas
to compute inter-area routes.
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING

from ospfd.const import (
    BACKBONE_AREA,
    LSA_TYPE_ASBR_SUMMARY,
    LSA_TYPE_ROUTER,
    LSA_TYPE_SUMMARY,
    MAX_AGE,
    PATH_INTER_AREA,
)
from ospfd.packet.lsa import SummaryLsa
from ospfd.spf.dijkstra import SpfVertex
from ospfd.spf.routing_table import OspfRoute
from ospfd.util.ip import mask_to_prefix_len

if TYPE_CHECKING:
    from ospfd.lsdb.database import LinkStateDatabase

logger = logging.getLogger(__name__)


def calculate_inter_area_routes(
    lsdb: LinkStateDatabase,
    spf_tree: dict[IPv4Address, SpfVertex],
    area_id: IPv4Address,
    intra_routes: list[OspfRoute],
) -> list[OspfRoute]:
    """Calculate inter-area routes from Summary LSAs.

    For each Type 3 Summary LSA in the area:
    1. The advertising router (ABR) must be reachable in the SPF tree.
    2. Total cost = cost-to-ABR + LSA metric.
    3. Only install if no better intra-area route exists.

    Args:
        lsdb: The link state database.
        spf_tree: The SPF tree for this area.
        area_id: The area ID being processed.
        intra_routes: Already computed intra-area routes (for preference check).

    Returns:
        List of inter-area OspfRoute objects.
    """
    routes: list[OspfRoute] = []

    # Build set of intra-area destinations for preference check
    intra_dests = {r.destination for r in intra_routes}

    # Process Type 3 Summary LSAs
    for lsa in lsdb.get_all(area_id, LSA_TYPE_SUMMARY):
        if lsa.current_age >= MAX_AGE:
            continue
        if not isinstance(lsa.body, SummaryLsa):
            continue
        if lsa.body.metric >= 0xFFFFFF:  # LSInfinity
            continue

        # The advertising router must be in the SPF tree
        abr_id = lsa.header.advertising_router
        abr_vertex = spf_tree.get(abr_id)
        if abr_vertex is None:
            continue

        # Don't use self-originated summaries
        if abr_id == lsdb.router_id:
            continue

        # Calculate total cost
        cost = abr_vertex.distance + lsa.body.metric

        # Build destination network
        mask = lsa.body.network_mask
        prefix_len = mask_to_prefix_len(mask)
        destination = IPv4Network(
            f"{lsa.header.link_state_id}/{prefix_len}", strict=False
        )

        # Skip if we have a better intra-area route
        if destination in intra_dests:
            continue

        route = OspfRoute(
            destination=destination,
            path_type=PATH_INTER_AREA,
            cost=cost,
            type2_cost=0,
            area_id=area_id,
            nexthops=abr_vertex.nexthops.copy(),
            advertising_router=abr_id,
        )
        routes.append(route)

    return routes


def calculate_asbr_routes(
    lsdb: LinkStateDatabase,
    spf_tree: dict[IPv4Address, SpfVertex],
    area_id: IPv4Address,
) -> dict[IPv4Address, int]:
    """Calculate routes to ASBRs from Type 4 Summary LSAs.

    Returns: dict mapping ASBR router_id -> cost to reach it.
    """
    asbr_costs: dict[IPv4Address, int] = {}

    for lsa in lsdb.get_all(area_id, LSA_TYPE_ASBR_SUMMARY):
        if lsa.current_age >= MAX_AGE:
            continue
        if not isinstance(lsa.body, SummaryLsa):
            continue
        if lsa.body.metric >= 0xFFFFFF:
            continue

        abr_id = lsa.header.advertising_router
        abr_vertex = spf_tree.get(abr_id)
        if abr_vertex is None:
            continue

        asbr_id = lsa.header.link_state_id
        cost = abr_vertex.distance + lsa.body.metric

        if asbr_id not in asbr_costs or cost < asbr_costs[asbr_id]:
            asbr_costs[asbr_id] = cost

    return asbr_costs
