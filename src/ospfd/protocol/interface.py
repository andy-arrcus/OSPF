"""OSPF Interface State Machine per RFC 2328 Section 9.

States: Down, Loopback, Waiting, Point-to-Point, DROther, Backup, DR
Events: InterfaceUp, WaitTimer, BackupSeen, NeighborChange,
        LoopInd, UnloopInd, InterfaceDown
"""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Optional, Union

from ospfd.const import (
    ALL_D_ROUTERS,
    ALL_SPF_ROUTERS,
    AUTH_NONE,
    INTF_EVT_BACKUP_SEEN,
    INTF_EVT_IF_DOWN,
    INTF_EVT_IF_UP,
    INTF_EVT_LOOP_IND,
    INTF_EVT_NBR_CHANGE,
    INTF_EVT_UNLOOP_IND,
    INTF_EVT_WAIT_TIMER,
    INTF_STATE_BACKUP,
    INTF_STATE_DOWN,
    INTF_STATE_DR,
    INTF_STATE_DROTHER,
    INTF_STATE_LOOPBACK,
    INTF_STATE_P2P,
    INTF_STATE_WAITING,
    INTF_TYPE_BROADCAST,
    INTF_TYPE_NBMA,
    INTF_TYPE_P2MP,
    INTF_TYPE_P2P,
    INTF_TYPE_VIRTUAL,
    NBR_EVT_1WAY,
    NBR_EVT_2WAY_RECEIVED,
    NBR_EVT_ADJ_OK,
    NBR_EVT_HELLO_RECEIVED,
    NBR_EVT_KILL_NBR,
    NBR_STATE_2WAY,
    NBR_STATE_DOWN,
    NBR_STATE_INIT,
    OPT_E,
    PACKET_TYPE_HELLO,
    PACKET_TYPE_LSACK,
    PACKET_TYPE_LSR,
    PACKET_TYPE_LSU,
)
from ospfd.packet.hello import HelloPacket
from ospfd.packet.header import OspfHeader, OSPF_HDR_LEN
from ospfd.packet.checksum import ip_checksum
from ospfd.packet.auth import apply_auth
from ospfd.protocol.neighbor import OspfNeighbor

if TYPE_CHECKING:
    import asyncio
    from ospfd.config import InterfaceConfig
    from ospfd.io.raw_socket import OspfSocket
    from ospfd.protocol.instance import OspfInstance

logger = logging.getLogger(__name__)

ZERO_ADDR = IPv4Address("0.0.0.0")


class OspfInterface:
    """OSPF interface with its state machine.

    Each interface belongs to exactly one area and manages
    its own set of neighbors, DR/BDR election, and Hello sending.
    """

    def __init__(
        self,
        config: InterfaceConfig,
        area_id: IPv4Address,
        ip_addr: IPv4Address,
        ip_mask: IPv4Address,
        instance: OspfInstance,
        loop: asyncio.AbstractEventLoop,
        mtu: int = 1500,
        if_index: int = 0,
    ):
        # Configuration
        self.name = config.name
        self.intf_type: int = config.type
        self.cost: int = config.cost
        self.priority: int = config.priority
        self.hello_interval: int = config.hello_interval
        self.dead_interval: int = config.dead_interval
        self.retransmit_interval: int = config.retransmit_interval
        self.transmit_delay: int = config.transmit_delay
        self.passive: bool = config.passive
        self.auth_type: int = config.auth.type
        self.auth_key: bytes = config.auth.key
        self.auth_key_id: int = config.auth.key_id

        # Identity
        self.area_id = area_id
        self.ip_addr = ip_addr
        self.ip_mask = ip_mask
        self.mtu = mtu
        self.if_index = if_index

        # Back-references
        self.instance = instance
        self._loop = loop

        # State
        self.state: int = INTF_STATE_DOWN
        self.dr: IPv4Address = ZERO_ADDR
        self.bdr: IPv4Address = ZERO_ADDR

        # Neighbors
        self.neighbors: dict[IPv4Address, OspfNeighbor] = {}

        # Socket
        self.socket: Optional[OspfSocket] = None

        # Timers
        from ospfd.util.timer import PeriodicTimer, OneShotTimer

        self._hello_timer = PeriodicTimer(
            loop, self.hello_interval, self._send_hello,
            jitter=0.1, name=f"hello-{self.name}",
        )
        self._wait_timer = OneShotTimer(
            loop, self.dead_interval, self._wait_timer_fire,
            name=f"wait-{self.name}",
        )

        # Delayed ACK queue
        self._delayed_acks: list = []
        self._ack_timer = PeriodicTimer(
            loop, 1.0, self._flush_delayed_acks,
            name=f"ack-{self.name}",
        )

    # ── FSM ─────────────────────────────────────────────────────────

    def event(self, evt: int) -> None:
        """Process an interface event through the state machine."""
        old_state = self.state
        handler = self._FSM.get((self.state, evt))
        if handler is not None:
            handler(self)

        if self.state != old_state:
            logger.info(
                "Interface %s: state %d -> %d (event %d)",
                self.name, old_state, self.state, evt,
            )
            self._state_changed(old_state)

    # ── FSM Actions ─────────────────────────────────────────────────

    def _if_up_broadcast(self) -> None:
        """InterfaceUp on broadcast/NBMA: -> Waiting, start timers."""
        if self.passive:
            self.state = INTF_STATE_LOOPBACK
            return

        if self.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if self.priority == 0:
                # Cannot be DR/BDR, skip Waiting
                self.state = INTF_STATE_DROTHER
                self._start_hello()
                self._run_dr_election()
            else:
                self.state = INTF_STATE_WAITING
                self._start_hello()
                self._wait_timer.start()
        elif self.intf_type in (INTF_TYPE_P2P, INTF_TYPE_P2MP, INTF_TYPE_VIRTUAL):
            self.state = INTF_STATE_P2P
            self._start_hello()

        # Join multicast groups
        if self.socket:
            self.socket.join_allspf()

    def _wait_timer_action(self) -> None:
        """WaitTimer fires -> run DR election."""
        self._run_dr_election()

    def _backup_seen_action(self) -> None:
        """BackupSeen event -> run DR election (shortcut Waiting)."""
        self._wait_timer.cancel()
        self._run_dr_election()

    def _nbr_change_action(self) -> None:
        """NeighborChange event -> re-run DR election."""
        self._run_dr_election()

    def _loop_ind_action(self) -> None:
        """LoopInd -> Loopback state."""
        self.state = INTF_STATE_LOOPBACK
        self._stop_all()

    def _unloop_ind_action(self) -> None:
        """UnloopInd -> Down, must be brought up again."""
        self.state = INTF_STATE_DOWN

    def _if_down_action(self) -> None:
        """InterfaceDown -> Down, kill all neighbors."""
        self.state = INTF_STATE_DOWN
        self._stop_all()
        for nbr in list(self.neighbors.values()):
            nbr.event(NBR_EVT_KILL_NBR)
        self.neighbors.clear()
        self.dr = ZERO_ADDR
        self.bdr = ZERO_ADDR

    # ── FSM Table ───────────────────────────────────────────────────

    _FSM: dict[tuple[int, int], callable] = {}

    @classmethod
    def _build_fsm(cls) -> None:
        S = cls

        # Down state
        cls._FSM[(INTF_STATE_DOWN, INTF_EVT_IF_UP)] = S._if_up_broadcast
        cls._FSM[(INTF_STATE_DOWN, INTF_EVT_LOOP_IND)] = S._loop_ind_action

        # Loopback state
        cls._FSM[(INTF_STATE_LOOPBACK, INTF_EVT_UNLOOP_IND)] = S._unloop_ind_action
        cls._FSM[(INTF_STATE_LOOPBACK, INTF_EVT_IF_DOWN)] = S._if_down_action

        # Waiting state
        cls._FSM[(INTF_STATE_WAITING, INTF_EVT_WAIT_TIMER)] = S._wait_timer_action
        cls._FSM[(INTF_STATE_WAITING, INTF_EVT_BACKUP_SEEN)] = S._backup_seen_action
        cls._FSM[(INTF_STATE_WAITING, INTF_EVT_IF_DOWN)] = S._if_down_action
        cls._FSM[(INTF_STATE_WAITING, INTF_EVT_LOOP_IND)] = S._loop_ind_action

        # Point-to-Point state
        cls._FSM[(INTF_STATE_P2P, INTF_EVT_IF_DOWN)] = S._if_down_action
        cls._FSM[(INTF_STATE_P2P, INTF_EVT_LOOP_IND)] = S._loop_ind_action

        # DROther state
        cls._FSM[(INTF_STATE_DROTHER, INTF_EVT_NBR_CHANGE)] = S._nbr_change_action
        cls._FSM[(INTF_STATE_DROTHER, INTF_EVT_IF_DOWN)] = S._if_down_action
        cls._FSM[(INTF_STATE_DROTHER, INTF_EVT_LOOP_IND)] = S._loop_ind_action

        # Backup state
        cls._FSM[(INTF_STATE_BACKUP, INTF_EVT_NBR_CHANGE)] = S._nbr_change_action
        cls._FSM[(INTF_STATE_BACKUP, INTF_EVT_IF_DOWN)] = S._if_down_action
        cls._FSM[(INTF_STATE_BACKUP, INTF_EVT_LOOP_IND)] = S._loop_ind_action

        # DR state
        cls._FSM[(INTF_STATE_DR, INTF_EVT_NBR_CHANGE)] = S._nbr_change_action
        cls._FSM[(INTF_STATE_DR, INTF_EVT_IF_DOWN)] = S._if_down_action
        cls._FSM[(INTF_STATE_DR, INTF_EVT_LOOP_IND)] = S._loop_ind_action

    # ── DR Election ─────────────────────────────────────────────────

    def _run_dr_election(self) -> None:
        """Run the DR/BDR election and update state."""
        from ospfd.protocol.dr_election import elect_dr_bdr

        old_dr = self.dr
        old_bdr = self.bdr

        new_dr, new_bdr = elect_dr_bdr(self)
        self.dr = new_dr
        self.bdr = new_bdr

        # Determine our new state
        my_addr = self.ip_addr
        if new_dr == my_addr:
            self.state = INTF_STATE_DR
        elif new_bdr == my_addr:
            self.state = INTF_STATE_BACKUP
        else:
            self.state = INTF_STATE_DROTHER

        # Manage AllDRouters multicast membership
        if self.socket:
            if self.state in (INTF_STATE_DR, INTF_STATE_BACKUP):
                self.socket.join_alld()
            else:
                self.socket.leave_alld()

        # If DR/BDR changed, neighbors may need to form/tear adjacencies
        if old_dr != new_dr or old_bdr != new_bdr:
            for nbr in self.neighbors.values():
                if nbr.state >= NBR_STATE_2WAY:
                    nbr.event(NBR_EVT_ADJ_OK)

    # ── State Change Callback ───────────────────────────────────────

    def _state_changed(self, old_state: int) -> None:
        """Called when interface state changes. Trigger LSA re-origination."""
        self.instance.schedule_router_lsa(self.area_id)
        if self.state == INTF_STATE_DR:
            self.instance.schedule_network_lsa(self)

    # ── Hello Processing ────────────────────────────────────────────

    def receive_hello(self, hello: HelloPacket, src_addr: IPv4Address) -> None:
        """Process a received Hello packet per Section 10.5.

        1. Validate HelloInterval and DeadInterval match.
        2. Validate network mask (broadcast only).
        3. Check E-bit match.
        4. Find or create neighbor.
        5. Update neighbor fields.
        6. Check for 2-way.
        7. Check for DR/BDR changes.
        """
        # Validation
        if hello.hello_interval != self.hello_interval:
            logger.warning("Hello interval mismatch from %s on %s", src_addr, self.name)
            return
        if hello.dead_interval != self.dead_interval:
            logger.warning("Dead interval mismatch from %s on %s", src_addr, self.name)
            return

        if self.intf_type == INTF_TYPE_BROADCAST:
            if hello.network_mask != self.ip_mask:
                logger.warning("Network mask mismatch from %s on %s", src_addr, self.name)
                return

        # E-bit check
        my_options = self.instance.options
        if (hello.options & OPT_E) != (my_options & OPT_E):
            logger.warning("E-bit mismatch from %s on %s", src_addr, self.name)
            return

        # Find or create neighbor by router ID from the OSPF header
        # The caller should have set src_router_id on this call
        # We use src_addr to find/index neighbor, but actually OSPF identifies
        # neighbors by router ID (from the packet header).
        # We need router_id from the OSPF header — it's passed via the instance dispatcher.
        # For now, we look up by src_addr as a key in neighbors, but the actual
        # design uses router_id. We'll handle this by having the instance pass router_id.

    def process_hello(
        self, hello: HelloPacket, src_addr: IPv4Address, router_id: IPv4Address
    ) -> None:
        """Process Hello with known router_id from OSPF header."""
        # Validation
        if hello.hello_interval != self.hello_interval:
            logger.warning("Hello interval mismatch from %s on %s", src_addr, self.name)
            return
        if hello.dead_interval != self.dead_interval:
            logger.warning("Dead interval mismatch from %s on %s", src_addr, self.name)
            return
        if self.intf_type == INTF_TYPE_BROADCAST and hello.network_mask != self.ip_mask:
            logger.warning("Network mask mismatch from %s on %s", src_addr, self.name)
            return
        my_options = self.instance.options
        if (hello.options & OPT_E) != (my_options & OPT_E):
            logger.warning("E-bit mismatch from %s on %s", src_addr, self.name)
            return

        # Find or create neighbor
        nbr = self.neighbors.get(router_id)
        if nbr is None:
            nbr = OspfNeighbor(router_id, src_addr, self, self._loop)
            self.neighbors[router_id] = nbr
            logger.info("New neighbor %s (%s) on %s", router_id, src_addr, self.name)

        # Update neighbor fields
        nbr.ip_addr = src_addr
        nbr.priority = hello.priority
        old_dr = nbr.dr
        old_bdr = nbr.bdr
        nbr.dr = hello.designated_router
        nbr.bdr = hello.backup_designated_router

        # HelloReceived event
        nbr.event(NBR_EVT_HELLO_RECEIVED)

        # Check 2-way: is our router ID in their neighbor list?
        my_rid = self.instance.router_id
        if my_rid in hello.neighbors:
            if nbr.state == NBR_STATE_INIT:
                nbr.event(NBR_EVT_2WAY_RECEIVED)
        else:
            if nbr.state >= NBR_STATE_2WAY:
                nbr.event(NBR_EVT_1WAY)

        # Check for DR/BDR changes that affect the interface
        if self.state == INTF_STATE_WAITING:
            # Check if we see a BDR or a DR that isn't claiming BDR
            if hello.backup_designated_router == src_addr:
                self.event(INTF_EVT_BACKUP_SEEN)
            elif (hello.designated_router == src_addr
                  and hello.backup_designated_router == ZERO_ADDR):
                self.event(INTF_EVT_BACKUP_SEEN)

        # If neighbor's DR/BDR claim changed, trigger NeighborChange
        if nbr.state >= NBR_STATE_2WAY:
            if old_dr != nbr.dr or old_bdr != nbr.bdr:
                self.event(INTF_EVT_NBR_CHANGE)

    # ── Neighbor State Change Notification ──────────────────────────

    def neighbor_state_changed(self, nbr: OspfNeighbor, old_state: int) -> None:
        """Called by a neighbor when its state changes.

        Triggers NeighborChange on broadcast/NBMA networks for DR election.
        Schedules LSA re-origination.
        """
        # NeighborChange for DR election
        if self.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if (old_state < NBR_STATE_2WAY <= nbr.state or
                    old_state >= NBR_STATE_2WAY > nbr.state):
                self.event(INTF_EVT_NBR_CHANGE)

        # Schedule Router LSA re-origination
        self.instance.schedule_router_lsa(self.area_id)

        # If we are DR and adjacency changed, schedule Network LSA
        if self.state == INTF_STATE_DR:
            self.instance.schedule_network_lsa(self)

    # ── Hello Sending ───────────────────────────────────────────────

    def _start_hello(self) -> None:
        """Start the periodic Hello timer."""
        self._hello_timer.start()
        self._ack_timer.start()
        # Send first Hello immediately
        self._send_hello()

    def _send_hello(self) -> None:
        """Build and send a Hello packet on this interface."""
        if self.passive:
            return

        # Build neighbor list: all neighbors in state >= Init
        nbr_list = [
            nbr.router_id
            for nbr in self.neighbors.values()
            if nbr.state >= NBR_STATE_INIT
        ]

        hello = HelloPacket(
            network_mask=self.ip_mask,
            hello_interval=self.hello_interval,
            options=self.instance.options,
            priority=self.priority,
            dead_interval=self.dead_interval,
            designated_router=self.dr,
            backup_designated_router=self.bdr,
            neighbors=nbr_list,
        )

        # Determine destination
        if self.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_P2P, INTF_TYPE_P2MP):
            dest = ALL_SPF_ROUTERS
        else:
            # NBMA: unicast to each neighbor
            for nbr in self.neighbors.values():
                self.send_packet(PACKET_TYPE_HELLO, hello.serialize(), nbr.ip_addr)
            return

        self.send_packet(PACKET_TYPE_HELLO, hello.serialize(), dest)

    # ── Packet Sending ──────────────────────────────────────────────

    def send_packet(self, pkt_type: int, body: bytes, dest: Union[str, IPv4Address]) -> None:
        """Build complete OSPF packet (header + body) and send.

        Handles checksum computation and authentication.
        """
        if self.socket is None:
            return

        dest_str = str(dest)

        header = OspfHeader.build(
            pkt_type=pkt_type,
            router_id=self.instance.router_id,
            area_id=self.area_id,
            auth_type=AUTH_NONE,  # auth applied separately
            auth_data=b"\x00" * 8,
        )
        total_len = OSPF_HDR_LEN + len(body)
        header.length = total_len

        # Serialize header + body
        raw = bytearray(header.serialize() + body)

        # Compute checksum (over header + body, auth_data zeroed for null auth)
        # Zero checksum field first
        raw[12] = 0
        raw[13] = 0
        if self.auth_type == AUTH_NONE:
            chksum = ip_checksum(bytes(raw))
        else:
            # For auth types 1 and 2, checksum excludes auth data (bytes 16-23)
            chk_data = bytes(raw[:16]) + b"\x00" * 8 + bytes(raw[24:])
            chksum = ip_checksum(chk_data)
        raw[12] = (chksum >> 8) & 0xFF
        raw[13] = chksum & 0xFF

        # Apply authentication
        final = apply_auth(raw, self.auth_type, self.auth_key, self.auth_key_id)

        self.socket.send(final, dest_str)

    # ── Delayed ACK ─────────────────────────────────────────────────

    def queue_delayed_ack(self, lsa_header) -> None:
        """Queue an LSA header for delayed acknowledgment."""
        self._delayed_acks.append(lsa_header)

    def _flush_delayed_acks(self) -> None:
        """Send queued delayed ACKs as an LSAck packet."""
        if not self._delayed_acks:
            return

        from ospfd.packet.lsack import LsackPacket

        ack = LsackPacket(lsa_headers=self._delayed_acks[:])
        self._delayed_acks.clear()

        # Send to AllSPFRouters on broadcast, or to neighbor on P2P
        if self.intf_type in (INTF_TYPE_BROADCAST, INTF_TYPE_NBMA):
            if self.state in (INTF_STATE_DR, INTF_STATE_BACKUP):
                dest = ALL_SPF_ROUTERS
            else:
                dest = ALL_D_ROUTERS
        else:
            dest = ALL_SPF_ROUTERS

        self.send_packet(PACKET_TYPE_LSACK, ack.serialize(), dest)

    # ── Wait Timer ──────────────────────────────────────────────────

    def _wait_timer_fire(self) -> None:
        """Wait timer expired: run DR election."""
        self.event(INTF_EVT_WAIT_TIMER)

    # ── Cleanup ─────────────────────────────────────────────────────

    def _stop_all(self) -> None:
        """Stop all timers."""
        self._hello_timer.stop()
        self._wait_timer.cancel()
        self._ack_timer.stop()

    def shutdown(self) -> None:
        """Graceful shutdown: stop timers, kill neighbors, close socket."""
        self._stop_all()
        for nbr in list(self.neighbors.values()):
            nbr.destroy()
        self.neighbors.clear()
        if self.socket:
            self.socket.close()
            self.socket = None

    # ── Properties ──────────────────────────────────────────────────

    @property
    def full_neighbors(self) -> list[OspfNeighbor]:
        """Return neighbors in Full state."""
        from ospfd.const import NBR_STATE_FULL
        return [n for n in self.neighbors.values() if n.state == NBR_STATE_FULL]

    @property
    def adjacent_neighbors(self) -> list[OspfNeighbor]:
        """Return neighbors with state >= Exchange."""
        from ospfd.const import NBR_STATE_EXCHANGE
        return [n for n in self.neighbors.values() if n.state >= NBR_STATE_EXCHANGE]


# Build FSM table at module load time
OspfInterface._build_fsm()
