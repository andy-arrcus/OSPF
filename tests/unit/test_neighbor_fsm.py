"""Tests for the OSPF neighbor state machine."""

import asyncio
from unittest.mock import MagicMock
from ipaddress import IPv4Address

from ospfd.const import (
    NBR_STATE_DOWN, NBR_STATE_INIT, NBR_STATE_2WAY, NBR_STATE_EXSTART,
    NBR_STATE_EXCHANGE, NBR_STATE_LOADING, NBR_STATE_FULL,
    NBR_EVT_HELLO_RECEIVED, NBR_EVT_2WAY_RECEIVED, NBR_EVT_NEGOTIATION_DONE,
    NBR_EVT_EXCHANGE_DONE, NBR_EVT_LOADING_DONE, NBR_EVT_1WAY,
    NBR_EVT_KILL_NBR, NBR_EVT_INACTIVITY_TIMER, NBR_EVT_ADJ_OK,
    INTF_TYPE_P2P, INTF_STATE_P2P,
)


def _make_neighbor(intf_type=INTF_TYPE_P2P, intf_state=INTF_STATE_P2P):
    """Create a mock neighbor for testing."""
    mock_instance = MagicMock()
    mock_instance.router_id = IPv4Address("10.0.0.1")
    mock_instance.options = 0x02
    mock_instance.lsdb = MagicMock()
    mock_instance.lsdb.get_all_headers.return_value = []
    mock_instance.lsdb.lookup.return_value = None
    mock_instance.lsdb.compare_lsa.return_value = 0
    mock_instance.flooding = MagicMock()
    mock_instance.schedule_router_lsa = MagicMock()
    mock_instance.schedule_network_lsa = MagicMock()

    mock_intf = MagicMock()
    mock_intf.name = "eth0"
    mock_intf.instance = mock_instance
    mock_intf.intf_type = intf_type
    mock_intf.state = intf_state
    mock_intf.ip_addr = IPv4Address("10.0.0.1")
    mock_intf.dr = IPv4Address("10.0.0.1")
    mock_intf.bdr = IPv4Address("10.0.0.2")
    mock_intf.dead_interval = 40
    mock_intf.retransmit_interval = 5
    mock_intf.mtu = 1500
    mock_intf.send_packet = MagicMock()
    mock_intf.neighbor_state_changed = MagicMock()
    mock_intf.area_id = IPv4Address("0.0.0.0")

    from ospfd.protocol.neighbor import OspfNeighbor
    return OspfNeighbor(
        router_id=IPv4Address("10.0.0.2"),
        ip_addr=IPv4Address("10.0.0.2"),
        interface=mock_intf,
    )


class TestNeighborFSM:
    def test_initial_state_is_down(self):
        nbr = _make_neighbor()
        assert nbr.state == NBR_STATE_DOWN

    def test_hello_received_down_to_init(self):
        async def run():
            nbr = _make_neighbor()
            nbr.event(NBR_EVT_HELLO_RECEIVED)
            assert nbr.state == NBR_STATE_INIT
        asyncio.run(run())

    def test_two_way_received_init_to_exstart_p2p(self):
        """On P2P, 2-Way should proceed to ExStart."""
        async def run():
            nbr = _make_neighbor(intf_type=INTF_TYPE_P2P)
            nbr.event(NBR_EVT_HELLO_RECEIVED)
            assert nbr.state == NBR_STATE_INIT
            nbr.event(NBR_EVT_2WAY_RECEIVED)
            assert nbr.state == NBR_STATE_EXSTART
        asyncio.run(run())

    def test_negotiation_done_exstart_to_exchange(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_EXSTART
            nbr.event(NBR_EVT_NEGOTIATION_DONE)
            assert nbr.state == NBR_STATE_EXCHANGE
        asyncio.run(run())

    def test_exchange_done_to_full_empty_request(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_EXCHANGE
            nbr.ls_request_list = {}
            nbr.event(NBR_EVT_EXCHANGE_DONE)
            assert nbr.state == NBR_STATE_FULL
        asyncio.run(run())

    def test_exchange_done_to_loading(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_EXCHANGE
            from ospfd.packet.lsa import LsaHeader
            hdr = LsaHeader(ls_age=0, options=0, ls_type=1,
                            link_state_id=IPv4Address("10.0.0.2"),
                            advertising_router=IPv4Address("10.0.0.2"),
                            ls_sequence_number=0x80000001,
                            ls_checksum=0, length=20)
            nbr.ls_request_list = {hdr.key: hdr}
            nbr.event(NBR_EVT_EXCHANGE_DONE)
            assert nbr.state == NBR_STATE_LOADING
        asyncio.run(run())

    def test_loading_done_to_full(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_LOADING
            nbr.event(NBR_EVT_LOADING_DONE)
            assert nbr.state == NBR_STATE_FULL
        asyncio.run(run())

    def test_kill_nbr_any_to_down(self):
        async def run():
            nbr = _make_neighbor()
            for initial_state in [NBR_STATE_INIT, NBR_STATE_2WAY, NBR_STATE_EXSTART,
                                  NBR_STATE_EXCHANGE, NBR_STATE_LOADING, NBR_STATE_FULL]:
                nbr.state = initial_state
                nbr.event(NBR_EVT_KILL_NBR)
                assert nbr.state == NBR_STATE_DOWN
        asyncio.run(run())

    def test_inactivity_timer_to_down(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_FULL
            nbr.event(NBR_EVT_INACTIVITY_TIMER)
            assert nbr.state == NBR_STATE_DOWN
        asyncio.run(run())

    def test_one_way_full_to_init(self):
        async def run():
            nbr = _make_neighbor()
            nbr.state = NBR_STATE_FULL
            nbr.event(NBR_EVT_1WAY)
            assert nbr.state == NBR_STATE_INIT
        asyncio.run(run())
