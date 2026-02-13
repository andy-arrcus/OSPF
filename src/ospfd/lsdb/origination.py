"""Self-originated LSA generation per RFC 2328 Section 12.4.

Generates Router LSAs (Type 1), Network LSAs (Type 2),
Summary LSAs (Type 3/4), and External LSAs (Type 5)
for this router.
"""

from __future__ import annotations

import logging
import time
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Optional

from ospfd.const import (
    BACKBONE_AREA,
    INITIAL_SEQ_NUM,
    INTF_STATE_DR,
    INTF_STATE_DROTHER,
    INTF_STATE_LOOPBACK,
    INTF_STATE_P2P,
    INTF_TYPE_BROADCAST,
    INTF_TYPE_NBMA,
    INTF_TYPE_P2P,
    INTF_TYPE_P2MP,
    INTF_TYPE_VIRTUAL,
    LINK_TYPE_P2P,
    LINK_TYPE_STUB,
    LINK_TYPE_TRANSIT,
    LSA_TYPE_ASBR_SUMMARY,
    LSA_TYPE_EXTERNAL,
    LSA_TYPE_NETWORK,
    LSA_TYPE_ROUTER,
    LSA_TYPE_SUMMARY,
    MAX_SEQ_NUM,
    MIN_LS_INTERVAL,
    NBR_STATE_FULL,
    OPT_E,
    ROUTER_FLAG_B,
    ROUTER_FLAG_E,
)
from ospfd.packet.lsa import (
    ExternalLsa,
    Lsa,
    LsaHeader,
    NetworkLsa,
    RouterLsa,
    RouterLsaLink,
    SummaryLsa,
)
from ospfd.util.ip import mask_to_prefix_len, network_address, prefix_len_to_mask

if TYPE_CHECKING:
    from ospfd.protocol.instance import OspfInstance
    from ospfd.protocol.interface import OspfInterface

logger = logging.getLogger(__name__)


class LsaOriginator:
    """Generates and re-originates LSAs for this router."""

    def __init__(self, instance: OspfInstance):
        self._instance = instance
        self._last_origination: dict[tuple, float] = {}  # key -> timestamp

    def originate_router_lsa(self, area_id: IPv4Address) -> Optional[Lsa]:
        """Generate a Type 1 Router LSA for the given area.

        Describes all of this router's links in the area:
          - P2P neighbors: link type 1
          - Transit networks (broadcast with DR+Full adjacency): link type 2
          - Stub networks (broadcast without adjacency, or P2P): link type 3
        """
        instance = self._instance
        links: list[RouterLsaLink] = []
        flags = 0

        # Check if we're an ABR (interfaces in multiple areas)
        if len(instance.areas) > 1:
            flags |= ROUTER_FLAG_B

        # Check if we're an ASBR
        if instance.is_asbr:
            flags |= ROUTER_FLAG_E

        # Process each interface in this area
        for intf in instance.get_interfaces_for_area(area_id):
            if intf.state == INTF_STATE_LOOPBACK:
                # Loopback: stub link to host
                links.append(RouterLsaLink(
                    link_id=intf.ip_addr,
                    link_data=IPv4Address("255.255.255.255"),
                    type=LINK_TYPE_STUB,
                    num_tos=0,
                    metric=0,
                ))
                continue

            if intf.state <= 0:  # Down
                continue

            if intf.intf_type == INTF_TYPE_P2P:
                # P2P: one link per Full neighbor, plus stub for the subnet
                for nbr in intf.neighbors.values():
                    if nbr.state == NBR_STATE_FULL:
                        links.append(RouterLsaLink(
                            link_id=nbr.router_id,
                            link_data=intf.ip_addr,
                            type=LINK_TYPE_P2P,
                            num_tos=0,
                            metric=intf.cost,
                        ))
                # Stub link for the P2P subnet
                net_addr = network_address(intf.ip_addr, intf.ip_mask)
                links.append(RouterLsaLink(
                    link_id=net_addr,
                    link_data=intf.ip_mask,
                    type=LINK_TYPE_STUB,
                    num_tos=0,
                    metric=intf.cost,
                ))

            elif intf.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
                if intf.state == INTF_STATE_DR and intf.full_neighbors:
                    # Transit: link to the network (DR's IP as link state ID)
                    links.append(RouterLsaLink(
                        link_id=intf.dr,
                        link_data=intf.ip_addr,
                        type=LINK_TYPE_TRANSIT,
                        num_tos=0,
                        metric=intf.cost,
                    ))
                elif intf.full_neighbors and intf.dr != IPv4Address("0.0.0.0"):
                    # We have a Full adjacency (with DR/BDR): transit link
                    links.append(RouterLsaLink(
                        link_id=intf.dr,
                        link_data=intf.ip_addr,
                        type=LINK_TYPE_TRANSIT,
                        num_tos=0,
                        metric=intf.cost,
                    ))
                else:
                    # Stub link
                    net_addr = network_address(intf.ip_addr, intf.ip_mask)
                    links.append(RouterLsaLink(
                        link_id=net_addr,
                        link_data=intf.ip_mask,
                        type=LINK_TYPE_STUB,
                        num_tos=0,
                        metric=intf.cost,
                    ))

            elif intf.intf_type == INTF_TYPE_P2MP:
                # Stub link for own address
                links.append(RouterLsaLink(
                    link_id=intf.ip_addr,
                    link_data=IPv4Address("255.255.255.255"),
                    type=LINK_TYPE_STUB,
                    num_tos=0,
                    metric=0,
                ))
                # P2P link per Full neighbor
                for nbr in intf.neighbors.values():
                    if nbr.state == NBR_STATE_FULL:
                        links.append(RouterLsaLink(
                            link_id=nbr.router_id,
                            link_data=intf.ip_addr,
                            type=LINK_TYPE_P2P,
                            num_tos=0,
                            metric=intf.cost,
                        ))

        body = RouterLsa(flags=flags, num_links=len(links), links=links)
        return self._originate(
            area_id=area_id,
            ls_type=LSA_TYPE_ROUTER,
            link_state_id=instance.router_id,
            body=body,
        )

    def originate_network_lsa(self, interface: OspfInterface) -> Optional[Lsa]:
        """Generate a Type 2 Network LSA.

        Only originated by the DR on a broadcast/NBMA interface
        when there is at least one Full adjacency.
        """
        if interface.state != INTF_STATE_DR:
            return None
        if not interface.full_neighbors:
            return None

        # Attached routers: all Full neighbors + self
        attached = [nbr.router_id for nbr in interface.full_neighbors]
        attached.append(self._instance.router_id)

        body = NetworkLsa(
            network_mask=interface.ip_mask,
            attached_routers=attached,
        )
        return self._originate(
            area_id=interface.area_id,
            ls_type=LSA_TYPE_NETWORK,
            link_state_id=interface.dr,  # DR's interface IP
            body=body,
        )

    def originate_summary_lsa(
        self, area_id: IPv4Address, destination: IPv4Address,
        mask: IPv4Address, metric: int
    ) -> Optional[Lsa]:
        """Generate a Type 3 Summary LSA for inter-area routes (ABR only)."""
        body = SummaryLsa(network_mask=mask, metric=metric)
        return self._originate(
            area_id=area_id,
            ls_type=LSA_TYPE_SUMMARY,
            link_state_id=destination,
            body=body,
        )

    def originate_asbr_summary_lsa(
        self, area_id: IPv4Address, asbr_id: IPv4Address, metric: int
    ) -> Optional[Lsa]:
        """Generate a Type 4 ASBR Summary LSA (ABR only)."""
        body = SummaryLsa(network_mask=IPv4Address("0.0.0.0"), metric=metric)
        return self._originate(
            area_id=area_id,
            ls_type=LSA_TYPE_ASBR_SUMMARY,
            link_state_id=asbr_id,
            body=body,
        )

    def originate_external_lsa(
        self, destination: IPv4Address, mask: IPv4Address,
        metric: int, metric_type: int = 2,
        forwarding_address: IPv4Address = IPv4Address("0.0.0.0"),
        tag: int = 0,
    ) -> Optional[Lsa]:
        """Generate a Type 5 AS External LSA (ASBR only)."""
        body = ExternalLsa(
            network_mask=mask,
            e_bit=(metric_type == 2),
            metric=metric,
            forwarding_address=forwarding_address,
            external_route_tag=tag,
        )
        return self._originate(
            area_id=BACKBONE_AREA,
            ls_type=LSA_TYPE_EXTERNAL,
            link_state_id=destination,
            body=body,
        )

    def refresh_lsa(self, area_id: IPv4Address, lsa: Lsa) -> Optional[Lsa]:
        """Re-originate an existing LSA with incremented sequence number.

        Called by the LSA refresh timer (every LS_REFRESH_TIME).
        """
        key = lsa.key
        old = self._instance.lsdb.lookup(area_id, key)
        if old is None or not self._instance.lsdb.is_self_originated(old):
            return None

        # Increment sequence number
        new_seq = old.header.ls_sequence_number + 1
        if new_seq > MAX_SEQ_NUM:
            # Must flush and re-originate after MaxAge
            logger.warning("LSA sequence number wrap for %s", key)
            return None

        return self._originate(
            area_id=area_id,
            ls_type=lsa.header.ls_type,
            link_state_id=lsa.header.link_state_id,
            body=lsa.body,
            seq_num=new_seq,
        )

    def _originate(
        self, area_id: IPv4Address, ls_type: int,
        link_state_id: IPv4Address, body, seq_num: Optional[int] = None,
    ) -> Optional[Lsa]:
        """Common origination logic with MinLSInterval enforcement."""
        instance = self._instance
        key = (ls_type, link_state_id, instance.router_id)

        # MinLSInterval check
        now = time.monotonic()
        last = self._last_origination.get(key, 0.0)
        if now - last < MIN_LS_INTERVAL:
            logger.debug("MinLSInterval: deferring LSA origination for %s", key)
            return None

        # Determine sequence number
        if seq_num is None:
            existing = instance.lsdb.lookup(area_id, key)
            if existing is not None and instance.lsdb.is_self_originated(existing):
                seq_num = existing.header.ls_sequence_number + 1
                if seq_num > MAX_SEQ_NUM:
                    return None
            else:
                seq_num = INITIAL_SEQ_NUM

        # Build LSA
        header = LsaHeader(
            ls_age=0,
            options=instance.options,
            ls_type=ls_type,
            link_state_id=link_state_id,
            advertising_router=instance.router_id,
            ls_sequence_number=seq_num,
            ls_checksum=0,  # computed during serialize
            length=0,       # computed during serialize
        )
        lsa = Lsa(header=header, body=body)

        # Serialize to compute checksum and length
        lsa.serialize(recompute_checksum=True)

        # Install in LSDB
        installed, old = instance.lsdb.install(area_id, lsa)
        if installed:
            self._last_origination[key] = now
            # Flood
            instance.flooding.flood_lsa(lsa, area_id, None, None)
            logger.info(
                "Originated LSA: type=%d id=%s seq=0x%08x",
                ls_type, link_state_id, seq_num,
            )

        return lsa
