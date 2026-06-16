"""OSPF Neighbor State Machine per RFC 2328 Section 10.

States: Down, Attempt, Init, 2-Way, ExStart, Exchange, Loading, Full
Events: HelloReceived, Start, 2-WayReceived, NegotiationDone, ExchangeDone,
        BadLSReq, LoadingDone, AdjOK?, SeqNumberMismatch, 1-Way,
        KillNbr, InactivityTimer, LLDown
"""

from __future__ import annotations

import logging
import os
import struct
from collections import deque
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Callable, Optional

from ospfd.const import (
    DD_FLAG_I,
    DD_FLAG_M,
    DD_FLAG_MS,
    INTF_STATE_BACKUP,
    INTF_STATE_DR,
    INTF_TYPE_BROADCAST,
    INTF_TYPE_NBMA,
    INTF_TYPE_P2MP,
    INTF_TYPE_P2P,
    INTF_TYPE_VIRTUAL,
    NBR_EVT_1WAY,
    NBR_EVT_2WAY_RECEIVED,
    NBR_EVT_ADJ_OK,
    NBR_EVT_BAD_LS_REQ,
    NBR_EVT_EXCHANGE_DONE,
    NBR_EVT_HELLO_RECEIVED,
    NBR_EVT_INACTIVITY_TIMER,
    NBR_EVT_KILL_NBR,
    NBR_EVT_LL_DOWN,
    NBR_EVT_LOADING_DONE,
    NBR_EVT_NEGOTIATION_DONE,
    NBR_EVT_SEQ_NUM_MISMATCH,
    NBR_EVT_START,
    NBR_STATE_2WAY,
    NBR_STATE_ATTEMPT,
    NBR_STATE_DOWN,
    NBR_STATE_EXCHANGE,
    NBR_STATE_EXSTART,
    NBR_STATE_FULL,
    NBR_STATE_INIT,
    NBR_STATE_LOADING,
    NBR_STATE_NAMES,
    PACKET_TYPE_DD,
    PACKET_TYPE_LSR,
)
from ospfd.packet.dd import DDPacket
from ospfd.packet.lsa import LsaHeader, Lsa
from ospfd.packet.lsr import LsrItem, LsrPacket

if TYPE_CHECKING:
    from ospfd.protocol.interface import OspfInterface

logger = logging.getLogger(__name__)


class OspfNeighbor:
    """OSPF neighbor with its state machine.

    Each neighbor is associated with an interface and identified
    by its router ID.
    """

    def __init__(
        self,
        router_id: IPv4Address,
        ip_addr: IPv4Address,
        interface: OspfInterface,
    ):
        self.router_id = router_id
        self.ip_addr = ip_addr
        self.interface = interface

        # State
        self.state: int = NBR_STATE_DOWN

        # Hello fields from neighbor
        self.priority: int = 0
        self.dr: IPv4Address = IPv4Address("0.0.0.0")
        self.bdr: IPv4Address = IPv4Address("0.0.0.0")
        self.options: int = 0

        # DD exchange
        self.is_master: bool = False
        self.dd_seq_number: int = 0
        self.dd_options: int = 0
        self.dd_flags: int = 0
        self.last_received_dd: Optional[DDPacket] = None

        # Lists per Section 10
        self.db_summary_list: deque[LsaHeader] = deque()
        self.ls_request_list: dict[tuple, LsaHeader] = {}
        self.ls_retransmission_list: dict[tuple, Lsa] = {}

        # Timers
        from ospfd.util.timer import OneShotTimer, PeriodicTimer

        self._inactivity_timer = OneShotTimer(
            interface.dead_interval, self._inactivity_timeout,
            name=f"inactivity-{router_id}",
        )
        self._rxmt_timer = PeriodicTimer(
            interface.retransmit_interval, self._rxmt_timeout,
            name=f"rxmt-{router_id}",
        )
        self._dd_rxmt_timer = PeriodicTimer(
            interface.retransmit_interval, self._dd_rxmt_timeout,
            name=f"dd-rxmt-{router_id}",
        )

    # ── FSM ─────────────────────────────────────────────────────────

    def event(self, evt: int) -> None:
        """Process a neighbor event through the state machine."""
        old_state = self.state
        handler = self._FSM.get((self.state, evt))
        if handler is not None:
            handler(self)
        elif evt in (NBR_EVT_KILL_NBR, NBR_EVT_LL_DOWN, NBR_EVT_INACTIVITY_TIMER):
            # These events always reset to Down from any state
            self._go_down()

        if self.state != old_state:
            logger.info(
                "Neighbor %s (%s) on %s: %s -> %s",
                self.router_id, self.ip_addr, self.interface.name,
                NBR_STATE_NAMES.get(old_state, str(old_state)),
                NBR_STATE_NAMES.get(self.state, str(self.state)),
            )
            # Notify interface of neighbor state change
            self.interface.neighbor_state_changed(self, old_state)

    # ── FSM Actions ─────────────────────────────────────────────────

    def _hello_received_down(self) -> None:
        """Down + HelloReceived -> Init."""
        self.state = NBR_STATE_INIT
        self._inactivity_timer.start()

    def _hello_received_any(self) -> None:
        """Any state + HelloReceived: restart inactivity timer."""
        self._inactivity_timer.reset()

    def _start(self) -> None:
        """Down + Start -> Attempt (NBMA only)."""
        self.state = NBR_STATE_ATTEMPT
        self._inactivity_timer.start()

    def _two_way_received(self) -> None:
        """Init + 2-WayReceived -> 2-Way or ExStart."""
        if self._should_form_adjacency():
            self.state = NBR_STATE_EXSTART
            self._start_dd_exchange()
        else:
            self.state = NBR_STATE_2WAY

    def _adj_ok_2way(self) -> None:
        """2-Way + AdjOK? -> ExStart if adjacency now needed."""
        if self._should_form_adjacency():
            self.state = NBR_STATE_EXSTART
            self._start_dd_exchange()

    def _adj_ok_adjformed(self) -> None:
        """ExStart/Exchange/Loading/Full + AdjOK? -> may tear down."""
        if not self._should_form_adjacency():
            self.state = NBR_STATE_2WAY
            self._clear_lists()
            self._dd_rxmt_timer.stop()
            self._rxmt_timer.stop()

    def _negotiation_done(self) -> None:
        """ExStart + NegotiationDone -> Exchange."""
        self.state = NBR_STATE_EXCHANGE
        # Build db_summary_list from LSDB
        self._build_db_summary()

    def _exchange_done(self) -> None:
        """Exchange + ExchangeDone -> Loading or Full."""
        if self.ls_request_list:
            self.state = NBR_STATE_LOADING
            self._send_ls_request()
        else:
            self.state = NBR_STATE_FULL
            self._rxmt_timer.stop()

    def _loading_done(self) -> None:
        """Loading + LoadingDone -> Full."""
        self.state = NBR_STATE_FULL

    def _seq_num_mismatch(self) -> None:
        """Any adjacency state + SeqNumberMismatch -> ExStart."""
        self.state = NBR_STATE_EXSTART
        self._clear_lists()
        self._start_dd_exchange()

    def _bad_ls_req(self) -> None:
        """Exchange/Loading + BadLSReq -> ExStart."""
        self._seq_num_mismatch()

    def _one_way(self) -> None:
        """Any state >= 2-Way + 1-Way -> Init."""
        self.state = NBR_STATE_INIT
        self._clear_lists()
        self._dd_rxmt_timer.stop()
        self._rxmt_timer.stop()

    def _go_down(self) -> None:
        """Transition to Down state."""
        old_state = self.state
        self.state = NBR_STATE_DOWN
        self._clear_lists()
        self._inactivity_timer.cancel()
        self._dd_rxmt_timer.stop()
        self._rxmt_timer.stop()
        if old_state != NBR_STATE_DOWN:
            logger.info(
                "Neighbor %s (%s) on %s: %s -> Down",
                self.router_id, self.ip_addr, self.interface.name,
                NBR_STATE_NAMES.get(old_state, str(old_state)),
            )
            self.interface.neighbor_state_changed(self, old_state)

    # ── FSM Transition Table ────────────────────────────────────────

    _FSM: dict[tuple[int, int], Callable[[OspfNeighbor], None]] = {}

    @classmethod
    def _build_fsm(cls) -> None:
        """Build the FSM transition table."""
        S = cls  # for brevity in the table

        # Down state
        cls._FSM[(NBR_STATE_DOWN, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_down
        cls._FSM[(NBR_STATE_DOWN, NBR_EVT_START)] = S._start

        # Init state
        cls._FSM[(NBR_STATE_INIT, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_INIT, NBR_EVT_2WAY_RECEIVED)] = S._two_way_received

        # 2-Way state
        cls._FSM[(NBR_STATE_2WAY, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_2WAY, NBR_EVT_ADJ_OK)] = S._adj_ok_2way
        cls._FSM[(NBR_STATE_2WAY, NBR_EVT_1WAY)] = S._one_way

        # ExStart state
        cls._FSM[(NBR_STATE_EXSTART, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_EXSTART, NBR_EVT_NEGOTIATION_DONE)] = S._negotiation_done
        cls._FSM[(NBR_STATE_EXSTART, NBR_EVT_ADJ_OK)] = S._adj_ok_adjformed
        cls._FSM[(NBR_STATE_EXSTART, NBR_EVT_SEQ_NUM_MISMATCH)] = S._seq_num_mismatch
        cls._FSM[(NBR_STATE_EXSTART, NBR_EVT_1WAY)] = S._one_way

        # Exchange state
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_EXCHANGE_DONE)] = S._exchange_done
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_ADJ_OK)] = S._adj_ok_adjformed
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_SEQ_NUM_MISMATCH)] = S._seq_num_mismatch
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_BAD_LS_REQ)] = S._bad_ls_req
        cls._FSM[(NBR_STATE_EXCHANGE, NBR_EVT_1WAY)] = S._one_way

        # Loading state
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_LOADING_DONE)] = S._loading_done
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_ADJ_OK)] = S._adj_ok_adjformed
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_SEQ_NUM_MISMATCH)] = S._seq_num_mismatch
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_BAD_LS_REQ)] = S._bad_ls_req
        cls._FSM[(NBR_STATE_LOADING, NBR_EVT_1WAY)] = S._one_way

        # Full state
        cls._FSM[(NBR_STATE_FULL, NBR_EVT_HELLO_RECEIVED)] = S._hello_received_any
        cls._FSM[(NBR_STATE_FULL, NBR_EVT_ADJ_OK)] = S._adj_ok_adjformed
        cls._FSM[(NBR_STATE_FULL, NBR_EVT_SEQ_NUM_MISMATCH)] = S._seq_num_mismatch
        cls._FSM[(NBR_STATE_FULL, NBR_EVT_BAD_LS_REQ)] = S._bad_ls_req
        cls._FSM[(NBR_STATE_FULL, NBR_EVT_1WAY)] = S._one_way

        # Kill/Inactivity/LLDown handled in event() directly

    # ── Adjacency Logic ─────────────────────────────────────────────

    def _should_form_adjacency(self) -> bool:
        """Section 10.4: Determine if an adjacency should be formed.

        Always True for P2P, P2MP, and virtual links.
        For broadcast/NBMA: True only if self or neighbor is DR or BDR.
        """
        intf_type = self.interface.intf_type
        if intf_type in (INTF_TYPE_P2P, INTF_TYPE_P2MP, INTF_TYPE_VIRTUAL):
            return True

        # Broadcast or NBMA: need to be DR or BDR
        intf = self.interface
        my_addr = intf.ip_addr

        # We are DR or BDR
        if intf.dr == my_addr or intf.bdr == my_addr:
            return True

        # Neighbor is DR or BDR
        if self.ip_addr == intf.dr or self.ip_addr == intf.bdr:
            return True

        return False

    # ── DD Exchange ─────────────────────────────────────────────────

    def _start_dd_exchange(self) -> None:
        """Begin ExStart: set initial DD seq, I/M/MS flags, send empty DD."""
        self.dd_seq_number = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
        self.is_master = True
        self.db_summary_list.clear()
        self.ls_request_list.clear()
        self.ls_retransmission_list.clear()

        # Send initial DD with I/M/MS flags set, no LSA headers
        self._send_dd(flags=DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS, lsa_headers=[])
        self._dd_rxmt_timer.start()

    def process_dd(self, dd: DDPacket, src: IPv4Address) -> None:
        """Handle a received DD packet based on current state.

        This implements the DD exchange procedure per Section 10.6-10.8.
        """
        if self.state == NBR_STATE_DOWN or self.state == NBR_STATE_ATTEMPT:
            return

        if self.state == NBR_STATE_INIT:
            # Received DD implies 2-way
            self.event(NBR_EVT_2WAY_RECEIVED)
            if self.state != NBR_STATE_EXSTART:
                return

        if self.state == NBR_STATE_EXSTART:
            self._process_dd_exstart(dd)
            return

        if self.state == NBR_STATE_EXCHANGE:
            self._process_dd_exchange(dd)
            return

        if self.state in (NBR_STATE_LOADING, NBR_STATE_FULL):
            # Duplicate DD check
            if self._is_duplicate_dd(dd):
                if not self.is_master:
                    # Slave: retransmit last DD
                    self._retransmit_last_dd()
            else:
                self.event(NBR_EVT_SEQ_NUM_MISMATCH)

    def _process_dd_exstart(self, dd: DDPacket) -> None:
        """Process DD in ExStart state — master/slave negotiation."""
        nbr_rid = self.router_id
        my_rid = self.interface.instance.router_id

        if dd.is_init and dd.is_more and dd.is_master and not dd.lsa_headers:
            # Neighbor also in ExStart, claiming master
            if nbr_rid > my_rid:
                # They are master
                self.is_master = False
                self.dd_seq_number = dd.dd_seq_number
                self.dd_options = dd.options
                self._dd_rxmt_timer.stop()
                self.event(NBR_EVT_NEGOTIATION_DONE)
                # Send our first DD as slave
                self._send_dd_slave()
            # else: we have higher RID, ignore their init, keep retransmitting
            return

        if not dd.is_init and not dd.is_master:
            # Neighbor is acknowledging us as master
            if nbr_rid < my_rid:
                if dd.dd_seq_number == self.dd_seq_number:
                    self.is_master = True
                    self.dd_options = dd.options
                    self._dd_rxmt_timer.stop()
                    self.event(NBR_EVT_NEGOTIATION_DONE)
                    # Process LSA headers from this DD
                    self._process_dd_headers(dd)
                    self.last_received_dd = dd
                    # Increment seq and send next DD as master
                    self.dd_seq_number += 1
                    self._send_dd_master()
                    return

        # Unexpected — could be sequence mismatch
        # Don't generate SeqNumMismatch during ExStart negotiations

    def _process_dd_exchange(self, dd: DDPacket) -> None:
        """Process DD in Exchange state."""
        # Check for duplicate
        if self._is_duplicate_dd(dd):
            if not self.is_master:
                self._retransmit_last_dd()
            return

        # Verify sequence number
        if self.is_master:
            if dd.dd_seq_number != self.dd_seq_number:
                self.event(NBR_EVT_SEQ_NUM_MISMATCH)
                return
            if dd.is_init or dd.is_master:
                self.event(NBR_EVT_SEQ_NUM_MISMATCH)
                return
        else:
            if dd.dd_seq_number != self.dd_seq_number + 1:
                self.event(NBR_EVT_SEQ_NUM_MISMATCH)
                return
            if dd.is_init:
                self.event(NBR_EVT_SEQ_NUM_MISMATCH)
                return
            self.dd_seq_number = dd.dd_seq_number

        # Process LSA headers
        self._process_dd_headers(dd)

        # Check if exchange is done
        if self.is_master:
            self.dd_seq_number += 1
            if not dd.is_more and not self.db_summary_list:
                self.event(NBR_EVT_EXCHANGE_DONE)
            else:
                self._send_dd_master()
        else:
            self._send_dd_slave()
            if not dd.is_more and not self.db_summary_list:
                self.event(NBR_EVT_EXCHANGE_DONE)

        self.last_received_dd = dd

    def _process_dd_headers(self, dd: DDPacket) -> None:
        """Process LSA headers from a DD packet.

        For each header, check against LSDB. If we don't have it
        or the neighbor has a newer version, add to ls_request_list.
        """
        instance = self.interface.instance
        for hdr in dd.lsa_headers:
            existing = instance.lsdb.lookup(
                self.interface.area_id, hdr.key
            )
            if existing is None or instance.lsdb.compare_lsa(hdr, existing.header) > 0:
                # We need this LSA
                self.ls_request_list[hdr.key] = hdr

    def _build_db_summary(self) -> None:
        """Build the db_summary_list from the LSDB."""
        instance = self.interface.instance
        self.db_summary_list = deque(instance.lsdb.get_all_headers(self.interface.area_id))

    def _is_duplicate_dd(self, dd: DDPacket) -> bool:
        """Check if this DD is a duplicate of the last received."""
        if self.last_received_dd is None:
            return False
        last = self.last_received_dd
        return (
            dd.dd_seq_number == last.dd_seq_number
            and dd.flags == last.flags
            and dd.options == last.options
        )

    # ── Packet Sending ──────────────────────────────────────────────

    def _send_dd(self, flags: int, lsa_headers: list[LsaHeader]) -> None:
        """Send a DD packet to this neighbor."""
        dd = DDPacket(
            interface_mtu=self.interface.mtu,
            options=self.interface.instance.options,
            flags=flags,
            dd_seq_number=self.dd_seq_number,
            lsa_headers=lsa_headers,
        )
        self.interface.send_packet(PACKET_TYPE_DD, dd.serialize(), self.ip_addr)
        self._last_sent_dd = dd

    def _send_dd_master(self) -> None:
        """Send DD as master: include next batch from db_summary_list."""
        headers = []
        # Fill up to MTU - headers
        max_headers = (self.interface.mtu - 24 - 8) // 20  # OSPF hdr + DD hdr
        while self.db_summary_list and len(headers) < max_headers:
            headers.append(self.db_summary_list.popleft())

        flags = 0
        if self.db_summary_list:
            flags |= DD_FLAG_M
        flags |= DD_FLAG_MS  # We are master

        self._send_dd(flags=flags, lsa_headers=headers)

    def _send_dd_slave(self) -> None:
        """Send DD as slave: respond with our next batch."""
        headers = []
        max_headers = (self.interface.mtu - 24 - 8) // 20
        while self.db_summary_list and len(headers) < max_headers:
            headers.append(self.db_summary_list.popleft())

        flags = 0
        if self.db_summary_list:
            flags |= DD_FLAG_M
        # Slave: MS bit not set

        self._send_dd(flags=flags, lsa_headers=headers)

    def _retransmit_last_dd(self) -> None:
        """Retransmit the last sent DD packet."""
        if hasattr(self, '_last_sent_dd') and self._last_sent_dd:
            self.interface.send_packet(
                PACKET_TYPE_DD,
                self._last_sent_dd.serialize(),
                self.ip_addr,
            )

    def _send_ls_request(self) -> None:
        """Send LS Request packet with items from ls_request_list."""
        if not self.ls_request_list:
            return
        items = []
        # Send up to ~10 items per request
        batch = list(self.ls_request_list.values())[:10]
        for hdr in batch:
            items.append(LsrItem(
                ls_type=hdr.ls_type,
                link_state_id=hdr.link_state_id,
                advertising_router=hdr.advertising_router,
            ))
        pkt = LsrPacket(items=items)
        self.interface.send_packet(PACKET_TYPE_LSR, pkt.serialize(), self.ip_addr)
        self._rxmt_timer.start()

    def process_ls_request(self, lsr: LsrPacket) -> None:
        """Handle received LS Request — send requested LSAs."""
        if self.state < NBR_STATE_EXCHANGE:
            return

        instance = self.interface.instance
        lsas: list[Lsa] = []
        for item in lsr.items:
            lsa = instance.lsdb.lookup(self.interface.area_id, item.key)
            if lsa is None:
                # Bad LS Request
                self.event(NBR_EVT_BAD_LS_REQ)
                return
            lsas.append(lsa)

        if lsas:
            instance.flooding.send_ls_update(self.interface, self, lsas)

    def process_ls_update(self, lsas: list[Lsa]) -> None:
        """Handle LSAs from an LS Update — process through flooding engine."""
        instance = self.interface.instance
        for lsa in lsas:
            # Remove from request list if present
            key = lsa.key
            self.ls_request_list.pop(key, None)
            # Also remove from retransmission list
            self.ls_retransmission_list.pop(key, None)

        # Check if loading is done
        if self.state == NBR_STATE_LOADING and not self.ls_request_list:
            self.event(NBR_EVT_LOADING_DONE)

    def process_ls_ack(self, headers: list[LsaHeader]) -> None:
        """Handle LS Acknowledgment — remove from retransmission list."""
        for hdr in headers:
            self.ls_retransmission_list.pop(hdr.key, None)

    # ── List Management ─────────────────────────────────────────────

    def _clear_lists(self) -> None:
        """Clear all exchange lists."""
        self.db_summary_list.clear()
        self.ls_request_list.clear()
        self.ls_retransmission_list.clear()
        self.last_received_dd = None

    # ── Timer Callbacks ─────────────────────────────────────────────

    def _inactivity_timeout(self) -> None:
        """Called when inactivity timer fires — neighbor is dead."""
        logger.warning("Inactivity timer fired for neighbor %s on %s",
                      self.router_id, self.interface.name)
        self.event(NBR_EVT_INACTIVITY_TIMER)

    def _rxmt_timeout(self) -> None:
        """Retransmit LS Requests."""
        if self.state == NBR_STATE_LOADING and self.ls_request_list:
            self._send_ls_request()

    def _dd_rxmt_timeout(self) -> None:
        """Retransmit DD packet (ExStart/Exchange)."""
        if self.state in (NBR_STATE_EXSTART, NBR_STATE_EXCHANGE):
            self._retransmit_last_dd()

    # ── Cleanup ─────────────────────────────────────────────────────

    def destroy(self) -> None:
        """Clean up timers and resources."""
        self._inactivity_timer.cancel()
        self._rxmt_timer.stop()
        self._dd_rxmt_timer.stop()
        self._clear_lists()


# Build the FSM table at module load time
OspfNeighbor._build_fsm()
