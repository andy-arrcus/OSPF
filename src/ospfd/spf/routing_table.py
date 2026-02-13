"""OSPF routing table per RFC 2328 Section 11.

Manages OSPF-computed routes and synchronizes them with the
Linux kernel routing table via Netlink.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Optional

from ospfd.const import (
    PATH_INTER_AREA,
    PATH_INTRA_AREA,
    PATH_TYPE1_EXTERNAL,
    PATH_TYPE2_EXTERNAL,
)
from ospfd.spf.dijkstra import SpfNexthop

if TYPE_CHECKING:
    from ospfd.io.netlink import NetlinkManager, Nexthop

logger = logging.getLogger(__name__)

ZERO_ADDR = IPv4Address("0.0.0.0")


@dataclass
class OspfRoute:
    """A single OSPF routing table entry per Section 11."""

    destination: IPv4Network
    path_type: int  # PATH_INTRA_AREA, PATH_INTER_AREA, etc.
    cost: int
    type2_cost: int = 0  # Only for Type 2 external
    area_id: IPv4Address = field(default_factory=lambda: ZERO_ADDR)
    nexthops: set[SpfNexthop] = field(default_factory=set)
    advertising_router: IPv4Address = field(default_factory=lambda: ZERO_ADDR)

    def is_better_than(self, other: OspfRoute) -> bool:
        """Compare routes per Section 16.3.2.

        Preference order:
          intra-area > inter-area > type-1-external > type-2-external

        Within same path type:
          - Lower cost wins
          - For type-2-external: lower type2_cost wins, then lower cost
        """
        if self.path_type != other.path_type:
            return self.path_type < other.path_type

        if self.path_type == PATH_TYPE2_EXTERNAL:
            if self.type2_cost != other.type2_cost:
                return self.type2_cost < other.type2_cost
            return self.cost < other.cost

        return self.cost < other.cost


class OspfRoutingTable:
    """Manages the OSPF routing table and kernel synchronization.

    Computes the delta between old and new route sets, and pushes
    only the changes to the Linux kernel via Netlink.
    """

    def __init__(self) -> None:
        self._routes: dict[IPv4Network, OspfRoute] = {}

    @property
    def routes(self) -> dict[IPv4Network, OspfRoute]:
        return self._routes

    def update(
        self,
        intra_routes: list[OspfRoute],
        inter_routes: list[OspfRoute],
        external_routes: list[OspfRoute],
    ) -> tuple[list[OspfRoute], list[OspfRoute], list[OspfRoute]]:
        """Build a new routing table from SPF results.

        For each destination, keep the best route (by path type preference,
        then cost). Returns (added, changed, removed) route lists.
        """
        new_routes: dict[IPv4Network, OspfRoute] = {}

        # Process in priority order: intra first (best preference)
        all_routes = intra_routes + inter_routes + external_routes
        for route in all_routes:
            dest = route.destination
            if dest in new_routes:
                existing = new_routes[dest]
                if route.is_better_than(existing):
                    new_routes[dest] = route
                elif not existing.is_better_than(route) and route.path_type == existing.path_type:
                    # Equal cost: merge nexthops (ECMP)
                    existing.nexthops.update(route.nexthops)
            else:
                new_routes[dest] = route

        # Compute delta
        added: list[OspfRoute] = []
        changed: list[OspfRoute] = []
        removed: list[OspfRoute] = []

        # New or changed routes
        for dest, route in new_routes.items():
            old = self._routes.get(dest)
            if old is None:
                added.append(route)
            elif (old.cost != route.cost or old.path_type != route.path_type
                  or old.nexthops != route.nexthops or old.type2_cost != route.type2_cost):
                changed.append(route)

        # Removed routes
        for dest in self._routes:
            if dest not in new_routes:
                removed.append(self._routes[dest])

        self._routes = new_routes
        return added, changed, removed

    def sync_to_kernel(
        self,
        netlink: NetlinkManager,
        added: list[OspfRoute],
        changed: list[OspfRoute],
        removed: list[OspfRoute],
    ) -> None:
        """Push route changes to the Linux kernel via Netlink."""
        from ospfd.io.netlink import Nexthop as NlNexthop

        for route in removed:
            netlink.remove_route(route.destination)

        for route in added + changed:
            nexthops = self._convert_nexthops(route)
            if nexthops:
                netlink.install_route(
                    destination=route.destination,
                    nexthops=nexthops,
                    metric=route.cost,
                )

    def _convert_nexthops(self, route: OspfRoute) -> list:
        """Convert SpfNexthop set to Netlink Nexthop list."""
        from ospfd.io.netlink import Nexthop as NlNexthop

        result = []
        for nh in route.nexthops:
            if nh.next_hop_ip == ZERO_ADDR:
                # Connected route — no gateway needed
                continue
            result.append(NlNexthop(
                gateway=nh.next_hop_ip,
                interface_index=nh.interface_index,
                interface_name=nh.interface_name,
            ))
        return result

    def clear(self) -> None:
        """Clear all routes (used during shutdown)."""
        self._routes.clear()
