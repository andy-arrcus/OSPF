"""OSPF area data structure per RFC 2328.

An area is a collection of interfaces and their associated
link state database partition.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Optional

from ospfd.const import BACKBONE_AREA

if TYPE_CHECKING:
    from ospfd.config import AreaConfig
    from ospfd.protocol.interface import OspfInterface

logger = logging.getLogger(__name__)


class OspfArea:
    """Represents a single OSPF area.

    Owns a set of interfaces and manages area-scoped operations
    like Router LSA origination and summary generation.
    """

    def __init__(self, area_id: IPv4Address, stub: bool = False, default_cost: int = 1):
        self.area_id = area_id
        self.stub = stub
        self.default_cost = default_cost
        self.interfaces: list[OspfInterface] = []

    @property
    def is_backbone(self) -> bool:
        return self.area_id == BACKBONE_AREA

    @property
    def is_stub(self) -> bool:
        return self.stub

    def add_interface(self, interface: OspfInterface) -> None:
        """Add an interface to this area."""
        self.interfaces.append(interface)
        logger.info("Added interface %s to area %s", interface.name, self.area_id)

    def remove_interface(self, interface: OspfInterface) -> None:
        """Remove an interface from this area."""
        self.interfaces = [i for i in self.interfaces if i is not interface]

    def has_full_adjacency(self) -> bool:
        """Check if any interface in this area has a Full adjacency."""
        from ospfd.const import NBR_STATE_FULL
        for intf in self.interfaces:
            for nbr in intf.neighbors.values():
                if nbr.state == NBR_STATE_FULL:
                    return True
        return False

    def get_full_neighbor_count(self) -> int:
        """Count Full adjacencies across all interfaces."""
        from ospfd.const import NBR_STATE_FULL
        count = 0
        for intf in self.interfaces:
            for nbr in intf.neighbors.values():
                if nbr.state == NBR_STATE_FULL:
                    count += 1
        return count

    def shutdown(self) -> None:
        """Shut down all interfaces in this area."""
        for intf in self.interfaces:
            intf.shutdown()

    @classmethod
    def from_config(cls, config: AreaConfig) -> OspfArea:
        """Create an area from configuration."""
        return cls(
            area_id=config.area_id,
            stub=config.stub,
            default_cost=config.default_cost,
        )
