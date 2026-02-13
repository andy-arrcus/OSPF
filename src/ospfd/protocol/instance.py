"""OSPF protocol instance — top-level orchestrator.

The OspfInstance is the central coordinator that owns:
  - Router identity (router_id, options)
  - Areas and their interfaces
  - The LSDB
  - The SPF engine
  - The flooding engine
  - The routing table
  - The Netlink manager
"""

from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address
from typing import Optional

from ospfd.config import OspfConfig
from ospfd.const import (
    BACKBONE_AREA,
    INTF_EVT_IF_UP,
    LSA_TYPE_EXTERNAL,
    OPT_E,
    PACKET_TYPE_DD,
    PACKET_TYPE_HELLO,
    PACKET_TYPE_LSACK,
    PACKET_TYPE_LSR,
    PACKET_TYPE_LSU,
)
from ospfd.io.netlink import NetlinkManager
from ospfd.io.raw_socket import OspfSocket
from ospfd.lsdb.aging import LsaAgingManager
from ospfd.lsdb.database import LinkStateDatabase
from ospfd.lsdb.flooding import FloodingEngine
from ospfd.lsdb.origination import LsaOriginator
from ospfd.packet.checksum import ip_checksum, verify_ip_checksum
from ospfd.packet.auth import verify_auth
from ospfd.packet.dd import DDPacket
from ospfd.packet.header import OSPF_HDR_LEN, OspfHeader
from ospfd.packet.hello import HelloPacket
from ospfd.packet.lsack import LsackPacket
from ospfd.packet.lsr import LsrPacket
from ospfd.packet.lsu import LsuPacket
from ospfd.protocol.area import OspfArea
from ospfd.protocol.interface import OspfInterface
from ospfd.spf.dijkstra import DijkstraEngine
from ospfd.spf.external import calculate_external_routes
from ospfd.spf.inter_area import calculate_asbr_routes, calculate_inter_area_routes
from ospfd.spf.intra_area import calculate_intra_area_routes
from ospfd.spf.routing_table import OspfRoutingTable
from ospfd.util.identifier import select_router_id
from ospfd.util.ip import prefix_len_to_mask

logger = logging.getLogger(__name__)


class OspfInstance:
    """Top-level OSPF protocol instance."""

    def __init__(self, config: OspfConfig, loop: asyncio.AbstractEventLoop):
        self.config = config
        self.loop = loop
        self.router_id: IPv4Address = IPv4Address("0.0.0.0")
        self.options: int = OPT_E  # E-bit set for non-stub areas
        self.is_asbr: bool = config.redistribute.static or config.redistribute.connected

        # Core components
        self.lsdb = LinkStateDatabase(self.router_id)
        self.flooding = FloodingEngine(self)
        self.originator = LsaOriginator(self)
        self.dijkstra = DijkstraEngine(self)
        self.routing_table = OspfRoutingTable()
        self.aging_manager = LsaAgingManager(self)

        # Areas and interfaces
        self.areas: dict[IPv4Address, OspfArea] = {}
        self._interfaces: dict[str, OspfInterface] = {}

        # Netlink
        self._netlink: Optional[NetlinkManager] = None

        # SPF scheduling
        self._spf_pending = False
        self._spf_timer: Optional[asyncio.TimerHandle] = None
        self._last_spf_time: float = 0

        # LSA origination scheduling
        self._router_lsa_pending: dict[IPv4Address, asyncio.TimerHandle] = {}
        self._network_lsa_pending: dict[str, asyncio.TimerHandle] = {}

    def init_netlink(self) -> None:
        """Initialize Netlink manager synchronously (before event loop runs).

        pyroute2 >= 0.9 uses asyncio internally, so IPRoute() must be
        created before the event loop is running.
        """
        self._netlink = NetlinkManager()
        self._sys_interfaces = self._netlink.discover_interfaces()

    async def start(self) -> None:
        """Initialize and start the OSPF instance.

        1. Select router ID.
        2. Create areas and interfaces.
        3. Open sockets and start protocol.
        """
        logger.info("Starting OSPF instance...")

        sys_interfaces = self._sys_interfaces
        sys_intf_map = {intf.name: intf for intf in sys_interfaces}

        # Select router ID
        intf_dicts = [
            {"name": i.name, "addresses": i.addresses}
            for i in sys_interfaces
        ]
        self.router_id = select_router_id(self.config.router_id, intf_dicts)
        self.lsdb = LinkStateDatabase(self.router_id)
        self.lsdb.router_id = self.router_id

        logger.info("Router ID: %s", self.router_id)

        # Create areas and interfaces
        for area_config in self.config.areas:
            area = OspfArea.from_config(area_config)
            self.areas[area.area_id] = area
            self.lsdb.ensure_area(area.area_id)

            for intf_config in area_config.interfaces:
                sys_intf = sys_intf_map.get(intf_config.name)
                if sys_intf is None:
                    logger.warning(
                        "Interface %s not found on system, skipping",
                        intf_config.name,
                    )
                    continue

                if not sys_intf.addresses:
                    logger.warning(
                        "Interface %s has no IPv4 addresses, skipping",
                        intf_config.name,
                    )
                    continue

                ip_addr, prefix_len = sys_intf.addresses[0]
                ip_mask = prefix_len_to_mask(prefix_len)

                # Create OSPF interface
                intf = OspfInterface(
                    config=intf_config,
                    area_id=area.area_id,
                    ip_addr=ip_addr,
                    ip_mask=ip_mask,
                    instance=self,
                    loop=self.loop,
                    mtu=sys_intf.mtu,
                    if_index=sys_intf.index,
                )

                # Create raw socket
                if not intf_config.passive:
                    try:
                        sock = OspfSocket(
                            self.loop, intf_config.name, str(ip_addr), sys_intf.mtu
                        )
                        sock.register_reader(
                            lambda i=intf, s=sock: self._receive_packet(i, s)
                        )
                        intf.socket = sock
                    except OSError as e:
                        logger.error(
                            "Failed to create socket for %s: %s", intf_config.name, e
                        )
                        continue

                area.add_interface(intf)
                self._interfaces[intf_config.name] = intf

        # Start aging manager
        self.aging_manager.start()

        # Bring up interfaces
        for intf in self._interfaces.values():
            intf.event(INTF_EVT_IF_UP)

        # Originate initial Router LSAs
        for area_id in self.areas:
            self.originator.originate_router_lsa(area_id)

        logger.info(
            "OSPF instance started: %d areas, %d interfaces",
            len(self.areas), len(self._interfaces),
        )

    def _receive_packet(self, interface: OspfInterface, sock: OspfSocket) -> None:
        """Callback for raw socket read events. Dispatches packets."""
        try:
            data, src_addr = sock.recv()
        except (BlockingIOError, OSError):
            return

        if len(data) < OSPF_HDR_LEN:
            return

        # Parse OSPF header
        try:
            header = OspfHeader.deserialize(data)
        except Exception as e:
            logger.debug("Failed to parse OSPF header from %s: %s", src_addr, e)
            return

        # Validate
        if header.version != 2:
            return
        if header.router_id == self.router_id:
            return  # Ignore our own packets
        if header.length > len(data):
            return

        # Verify checksum
        if header.auth_type == 0:
            if not verify_ip_checksum(data[:header.length]):
                logger.debug("Checksum failed from %s", src_addr)
                return

        # Verify authentication
        if not verify_auth(data[:header.length], interface.auth_type,
                          interface.auth_key, interface.auth_key_id):
            logger.debug("Auth failed from %s", src_addr)
            return

        # Area check
        if header.area_id != interface.area_id:
            logger.debug(
                "Area mismatch: pkt=%s intf=%s from %s",
                header.area_id, interface.area_id, src_addr,
            )
            return

        # Dispatch by type
        body_data = data[OSPF_HDR_LEN:header.length]
        router_id = header.router_id
        src = IPv4Address(src_addr)

        try:
            if header.type == PACKET_TYPE_HELLO:
                hello = HelloPacket.deserialize(body_data)
                interface.process_hello(hello, src, router_id)

            elif header.type == PACKET_TYPE_DD:
                dd = DDPacket.deserialize(body_data)
                nbr = interface.neighbors.get(router_id)
                if nbr:
                    nbr.process_dd(dd, src)

            elif header.type == PACKET_TYPE_LSR:
                lsr = LsrPacket.deserialize(body_data)
                nbr = interface.neighbors.get(router_id)
                if nbr:
                    nbr.process_ls_request(lsr)

            elif header.type == PACKET_TYPE_LSU:
                lsu = LsuPacket.deserialize(body_data)
                nbr = interface.neighbors.get(router_id)
                if nbr:
                    self.flooding.receive_lsu(interface, nbr, lsu)

            elif header.type == PACKET_TYPE_LSACK:
                lsack = LsackPacket.deserialize(body_data)
                nbr = interface.neighbors.get(router_id)
                if nbr:
                    nbr.process_ls_ack(lsack.lsa_headers)

        except Exception as e:
            logger.error(
                "Error processing packet type %d from %s: %s",
                header.type, src_addr, e, exc_info=True,
            )

    # ── SPF Scheduling ──────────────────────────────────────────────

    def schedule_spf(self) -> None:
        """Schedule an SPF calculation with debounce."""
        if self._spf_pending:
            return
        self._spf_pending = True

        import time
        now = time.monotonic()
        elapsed = now - self._last_spf_time
        delay = max(0, self.config.spf_delay)
        if elapsed < self.config.spf_hold:
            delay = max(delay, self.config.spf_hold - elapsed)

        self._spf_timer = self.loop.call_later(delay, self._run_spf)

    def _run_spf(self) -> None:
        """Execute the full SPF calculation and update routing table."""
        import time

        self._spf_pending = False
        self._last_spf_time = time.monotonic()

        logger.info("Running SPF calculation...")

        spf_trees: dict[IPv4Address, dict] = {}
        all_intra: list = []
        all_inter: list = []
        all_asbr_costs: dict[IPv4Address, int] = {}

        for area_id, area in self.areas.items():
            # Run Dijkstra
            tree = self.dijkstra.calculate(area_id)
            spf_trees[area_id] = tree

            # Intra-area routes
            intra = calculate_intra_area_routes(tree, area_id)
            all_intra.extend(intra)

            # Inter-area routes
            inter = calculate_inter_area_routes(
                self.lsdb, tree, area_id, intra
            )
            all_inter.extend(inter)

            # ASBR costs
            asbr = calculate_asbr_routes(self.lsdb, tree, area_id)
            for asbr_id, cost in asbr.items():
                if asbr_id not in all_asbr_costs or cost < all_asbr_costs[asbr_id]:
                    all_asbr_costs[asbr_id] = cost

        # External routes
        external = calculate_external_routes(
            self.lsdb, spf_trees, all_asbr_costs,
            all_intra, all_inter,
        )

        # Update routing table
        added, changed, removed = self.routing_table.update(
            all_intra, all_inter, external
        )

        # Sync to kernel
        if self._netlink:
            self.routing_table.sync_to_kernel(self._netlink, added, changed, removed)

        logger.info(
            "SPF done: %d intra, %d inter, %d external routes "
            "(%d added, %d changed, %d removed)",
            len(all_intra), len(all_inter), len(external),
            len(added), len(changed), len(removed),
        )

    # ── LSA Origination Scheduling ──────────────────────────────────

    def schedule_router_lsa(self, area_id: IPv4Address) -> None:
        """Schedule Router LSA re-origination for an area (debounced)."""
        if area_id in self._router_lsa_pending:
            return
        handle = self.loop.call_later(
            1.0, self._originate_router_lsa, area_id
        )
        self._router_lsa_pending[area_id] = handle

    def _originate_router_lsa(self, area_id: IPv4Address) -> None:
        self._router_lsa_pending.pop(area_id, None)
        self.originator.originate_router_lsa(area_id)

    def schedule_network_lsa(self, interface: OspfInterface) -> None:
        """Schedule Network LSA origination (debounced)."""
        key = interface.name
        if key in self._network_lsa_pending:
            return
        handle = self.loop.call_later(
            1.0, self._originate_network_lsa, interface
        )
        self._network_lsa_pending[key] = handle

    def _originate_network_lsa(self, interface: OspfInterface) -> None:
        self._network_lsa_pending.pop(interface.name, None)
        self.originator.originate_network_lsa(interface)

    # ── Helper Methods ──────────────────────────────────────────────

    def get_interfaces_for_area(self, area_id: IPv4Address) -> list[OspfInterface]:
        """Get all interfaces belonging to an area."""
        area = self.areas.get(area_id)
        if area is None:
            return []
        return area.interfaces

    # ── Shutdown ────────────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Graceful shutdown.

        1. Stop aging manager.
        2. Flush OSPF routes from kernel.
        3. Shut down all areas/interfaces.
        4. Close Netlink.
        """
        logger.info("Shutting down OSPF instance...")

        # Cancel pending timers
        self.aging_manager.stop()
        if self._spf_timer:
            self._spf_timer.cancel()
        for handle in self._router_lsa_pending.values():
            handle.cancel()
        for handle in self._network_lsa_pending.values():
            handle.cancel()

        # Shut down areas
        for area in self.areas.values():
            area.shutdown()

        # Flush kernel routes
        if self._netlink:
            self._netlink.flush_ospf_routes()
            self._netlink.close()

        logger.info("OSPF instance shut down")
