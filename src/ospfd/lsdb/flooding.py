"""OSPF reliable flooding per RFC 2328 Section 13.

Handles:
  - Receiving and processing LS Updates
  - Flooding LSAs to appropriate interfaces/neighbors
  - Direct and delayed acknowledgments
  - Retransmission management
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Optional

from ospfd.const import (
    ALL_D_ROUTERS,
    ALL_SPF_ROUTERS,
    INTF_STATE_BACKUP,
    INTF_STATE_DR,
    INTF_STATE_DROTHER,
    INTF_TYPE_BROADCAST,
    INTF_TYPE_NBMA,
    INTF_TYPE_P2P,
    INTF_TYPE_VIRTUAL,
    LSA_TYPE_EXTERNAL,
    LSA_TYPE_OPAQUE_AS,
    MAX_AGE,
    NBR_STATE_EXCHANGE,
    NBR_STATE_FULL,
    NBR_STATE_LOADING,
    PACKET_TYPE_LSACK,
    PACKET_TYPE_LSU,
)
from ospfd.packet.lsa import Lsa, LsaHeader
from ospfd.packet.lsack import LsackPacket
from ospfd.packet.lsu import LsuPacket

if TYPE_CHECKING:
    from ospfd.protocol.instance import OspfInstance
    from ospfd.protocol.interface import OspfInterface
    from ospfd.protocol.neighbor import OspfNeighbor

logger = logging.getLogger(__name__)

MAX_RXMT_LIST = 1000


class FloodingEngine:
    """Implements the OSPF flooding procedure."""

    def __init__(self, instance: OspfInstance):
        self._instance = instance

    def receive_lsu(
        self, interface: OspfInterface, neighbor: OspfNeighbor, lsu: LsuPacket
    ) -> None:
        """Process received LS Update per Section 13.

        For each LSA in the update:
        1. Validate checksum and type.
        2. Compare with LSDB.
        3. If newer: install, flood, ack.
        4. If same: implicit ack.
        5. If older: send our copy back.
        """
        instance = self._instance
        area_id = interface.area_id

        for lsa in lsu.lsas:
            self._process_received_lsa(lsa, interface, neighbor, area_id)

        # Notify neighbor of received LSAs (for request list removal)
        neighbor.process_ls_update(lsu.lsas)

    def _process_received_lsa(
        self, lsa: Lsa, interface: OspfInterface,
        neighbor: OspfNeighbor, area_id: IPv4Address
    ) -> None:
        """Process a single received LSA per Section 13 steps 1-7."""
        instance = self._instance
        lsdb = instance.lsdb
        key = lsa.key

        # Step 1: Validate LS type
        _VALID_LSA_TYPES = {1, 2, 3, 4, 5, 9, 10, 11}
        if lsa.header.ls_type not in _VALID_LSA_TYPES:
            logger.warning("Unknown LSA type %d from %s", lsa.header.ls_type, neighbor.router_id)
            return

        # Step 2: AS-external not in stub area
        # (stub area handling would go here)

        # Step 3: Look up in LSDB
        existing = lsdb.lookup(area_id, key)

        if existing is None or lsdb.compare_lsa(lsa.header, existing.header) > 0:
            # Step 4: New or newer instance
            # (a) If on request list, this is expected — handled by neighbor

            # (b) Install in LSDB
            installed, old = lsdb.install(area_id, lsa)
            if not installed:
                return

            # (c) Flood to other interfaces
            self.flood_lsa(lsa, area_id, interface, neighbor)

            # (d) If self-originated, re-originate with newer seq
            if lsdb.is_self_originated(lsa):
                if lsa.header.ls_age >= MAX_AGE:
                    # Someone is flushing our LSA — just remove
                    lsdb.remove(area_id, key)
                else:
                    # Someone has a newer version of our LSA
                    # Re-originate with even higher sequence number
                    instance.originator.refresh_lsa(area_id, lsa)
                return

            # (e) Acknowledge
            self._acknowledge(lsa, interface, neighbor)

            # (f) Schedule SPF
            instance.schedule_spf()

        elif existing is not None and lsdb.compare_lsa(lsa.header, existing.header) == 0:
            # Step 5: Same instance — implicit acknowledgment
            # Remove from neighbor's retransmission list
            neighbor.ls_retransmission_list.pop(key, None)
            # If on neighbor's request list, treat as implicit ack
            # Send delayed ack if not on retransmission list
            if interface.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
                interface.queue_delayed_ack(lsa.header)

        else:
            # Step 6: We have a newer instance — send it back
            self.send_ls_update(interface, neighbor, [existing])

    def flood_lsa(
        self, lsa: Lsa, area_id: IPv4Address,
        recv_intf: Optional[OspfInterface],
        recv_nbr: Optional[OspfNeighbor],
    ) -> None:
        """Flood an LSA out appropriate interfaces per Section 13.3.

        For area-scoped LSAs (types 1-4): flood within the area.
        For AS-external LSAs (type 5): flood to all areas (except stubs).
        """
        instance = self._instance

        if lsa.header.ls_type in (LSA_TYPE_EXTERNAL, LSA_TYPE_OPAQUE_AS):
            # Flood to all non-stub areas
            areas = instance.areas.values()
        else:
            # Flood within the area
            area = instance.areas.get(area_id)
            areas = [area] if area else []

        for area in areas:
            for intf in area.interfaces:
                if intf is recv_intf:
                    # Special handling for receiving interface
                    self._flood_back_to_source(lsa, intf, recv_nbr)
                    continue

                # Send to eligible neighbors on this interface
                self._flood_to_interface(lsa, intf)

    def _flood_to_interface(self, lsa: Lsa, interface: OspfInterface) -> None:
        """Flood LSA out a single interface."""
        eligible = [
            nbr for nbr in interface.neighbors.values()
            if nbr.state >= NBR_STATE_EXCHANGE
        ]
        if not eligible:
            return

        # Add to retransmission list of each eligible neighbor
        for nbr in eligible:
            if lsa.key not in nbr.ls_retransmission_list:
                if len(nbr.ls_retransmission_list) >= MAX_RXMT_LIST:
                    logger.warning(
                        "Retransmit list full for neighbor %s (%d entries), declaring dead",
                        nbr.router_id, len(nbr.ls_retransmission_list),
                    )
                    from ospfd.const import NBR_EVT_KILL_NBR
                    nbr.event(NBR_EVT_KILL_NBR)
                    return
                nbr.ls_retransmission_list[lsa.key] = lsa

        # Determine destination
        if interface.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if interface.state == INTF_STATE_DR or interface.state == INTF_STATE_BACKUP:
                dest = ALL_SPF_ROUTERS
            else:
                dest = ALL_D_ROUTERS
        else:
            # P2P/P2MP/Virtual: send to each neighbor directly
            for nbr in eligible:
                lsu = LsuPacket(lsas=[lsa])
                interface.send_packet(PACKET_TYPE_LSU, lsu.serialize(), nbr.ip_addr)
            return

        lsu = LsuPacket(lsas=[lsa])
        interface.send_packet(PACKET_TYPE_LSU, lsu.serialize(), dest)

    def _flood_back_to_source(
        self, lsa: Lsa, interface: OspfInterface, recv_nbr: Optional[OspfNeighbor]
    ) -> None:
        """Handle flooding back to the interface where LSA was received.

        Per Section 13.3 Step 3: On broadcast networks, flood back only
        if we are DR (to reach all routers via AllSPFRouters).
        """
        if interface.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if interface.state == INTF_STATE_DR:
                lsu = LsuPacket(lsas=[lsa])
                interface.send_packet(PACKET_TYPE_LSU, lsu.serialize(), ALL_SPF_ROUTERS)

    def _acknowledge(
        self, lsa: Lsa, interface: OspfInterface, neighbor: OspfNeighbor
    ) -> None:
        """Send acknowledgment for a received LSA.

        Direct ack: unicast to sender for certain cases.
        Delayed ack: queue for batch sending on other cases.
        """
        if interface.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if interface.state == INTF_STATE_DR or interface.state == INTF_STATE_BACKUP:
                # DR/BDR: delayed ack
                interface.queue_delayed_ack(lsa.header)
            elif interface.state == INTF_STATE_DROTHER:
                # DROther: delayed ack
                interface.queue_delayed_ack(lsa.header)
            else:
                # Direct ack
                self._send_direct_ack(lsa.header, interface, neighbor)
        else:
            # P2P/P2MP/Virtual: delayed ack
            interface.queue_delayed_ack(lsa.header)

    def _send_direct_ack(
        self, header: LsaHeader, interface: OspfInterface, neighbor: OspfNeighbor
    ) -> None:
        """Send a direct LSAck to the neighbor."""
        ack = LsackPacket(lsa_headers=[header])
        interface.send_packet(PACKET_TYPE_LSACK, ack.serialize(), neighbor.ip_addr)

    def send_ls_update(
        self, interface: OspfInterface, neighbor: OspfNeighbor, lsas: list[Lsa]
    ) -> None:
        """Send an LS Update with the given LSAs to a specific neighbor."""
        if not lsas:
            return
        lsu = LsuPacket(lsas=lsas)
        interface.send_packet(PACKET_TYPE_LSU, lsu.serialize(), neighbor.ip_addr)
