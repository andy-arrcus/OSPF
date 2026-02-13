"""Tests for the OSPF interface state machine."""

import asyncio
import pytest
from unittest.mock import MagicMock
from ipaddress import IPv4Address

from ospfd.const import (
    INTF_STATE_DOWN, INTF_STATE_WAITING, INTF_STATE_P2P,
    INTF_STATE_DR, INTF_STATE_BACKUP, INTF_STATE_DROTHER,
    INTF_STATE_LOOPBACK,
    INTF_EVT_IF_UP, INTF_EVT_WAIT_TIMER, INTF_EVT_IF_DOWN,
    INTF_EVT_LOOP_IND,
    INTF_TYPE_BROADCAST, INTF_TYPE_P2P,
)


def _make_interface(intf_type=INTF_TYPE_BROADCAST, priority=1, passive=False):
    """Create a mock interface for testing."""
    loop = asyncio.new_event_loop()

    mock_instance = MagicMock()
    mock_instance.router_id = IPv4Address("10.0.0.1")
    mock_instance.options = 0x02
    mock_instance.schedule_router_lsa = MagicMock()
    mock_instance.schedule_network_lsa = MagicMock()
    mock_instance.areas = {IPv4Address("0.0.0.0"): MagicMock()}

    mock_config = MagicMock()
    mock_config.name = "eth0"
    mock_config.type = intf_type
    mock_config.cost = 10
    mock_config.priority = priority
    mock_config.hello_interval = 10
    mock_config.dead_interval = 40
    mock_config.retransmit_interval = 5
    mock_config.transmit_delay = 1
    mock_config.passive = passive
    mock_config.auth = MagicMock()
    mock_config.auth.type = 0
    mock_config.auth.key = b""
    mock_config.auth.key_id = 0

    from ospfd.protocol.interface import OspfInterface
    intf = OspfInterface(
        config=mock_config,
        area_id=IPv4Address("0.0.0.0"),
        ip_addr=IPv4Address("10.0.0.1"),
        ip_mask=IPv4Address("255.255.255.0"),
        instance=mock_instance,
        loop=loop,
    )
    return intf, loop


class TestInterfaceFSM:
    def test_initial_state_down(self):
        intf, loop = _make_interface()
        assert intf.state == INTF_STATE_DOWN
        loop.close()

    def test_if_up_broadcast_to_waiting(self):
        intf, loop = _make_interface(intf_type=INTF_TYPE_BROADCAST, priority=1)
        intf.event(INTF_EVT_IF_UP)
        assert intf.state == INTF_STATE_WAITING
        loop.close()

    def test_if_up_broadcast_priority_zero(self):
        """Priority 0 skips Waiting, goes straight to DROther."""
        intf, loop = _make_interface(intf_type=INTF_TYPE_BROADCAST, priority=0)
        intf.event(INTF_EVT_IF_UP)
        assert intf.state in (INTF_STATE_DROTHER, INTF_STATE_DR, INTF_STATE_BACKUP)
        loop.close()

    def test_if_up_p2p(self):
        intf, loop = _make_interface(intf_type=INTF_TYPE_P2P)
        intf.event(INTF_EVT_IF_UP)
        assert intf.state == INTF_STATE_P2P
        loop.close()

    def test_if_up_passive(self):
        intf, loop = _make_interface(passive=True)
        intf.event(INTF_EVT_IF_UP)
        assert intf.state == INTF_STATE_LOOPBACK
        loop.close()

    def test_if_down_resets(self):
        intf, loop = _make_interface()
        intf.state = INTF_STATE_DROTHER
        intf.event(INTF_EVT_IF_DOWN)
        assert intf.state == INTF_STATE_DOWN
        loop.close()

    def test_loop_ind(self):
        intf, loop = _make_interface()
        intf.state = INTF_STATE_DROTHER
        intf.event(INTF_EVT_LOOP_IND)
        assert intf.state == INTF_STATE_LOOPBACK
        loop.close()
