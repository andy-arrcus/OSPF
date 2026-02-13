"""Tests for DR/BDR election algorithm."""

import asyncio
import pytest
from unittest.mock import MagicMock
from ipaddress import IPv4Address

from ospfd.const import (
    NBR_STATE_FULL, NBR_STATE_2WAY,
    INTF_TYPE_BROADCAST, INTF_STATE_DROTHER,
)
from ospfd.protocol.dr_election import elect_dr_bdr


def _make_election_interface(
    my_rid=IPv4Address("10.0.0.1"),
    my_ip=IPv4Address("192.168.1.1"),
    my_priority=1,
    my_dr=IPv4Address("0.0.0.0"),
    my_bdr=IPv4Address("0.0.0.0"),
):
    """Create a mock interface for DR election testing."""
    mock_instance = MagicMock()
    mock_instance.router_id = my_rid

    intf = MagicMock()
    intf.instance = mock_instance
    intf.ip_addr = my_ip
    intf.priority = my_priority
    intf.dr = my_dr
    intf.bdr = my_bdr
    intf.neighbors = {}
    return intf


def _make_neighbor(rid, ip, priority, dr, bdr, state=NBR_STATE_FULL):
    nbr = MagicMock()
    nbr.router_id = rid
    nbr.ip_addr = ip
    nbr.priority = priority
    nbr.dr = dr
    nbr.bdr = bdr
    nbr.state = state
    return nbr


class TestDrElection:
    def test_single_router_becomes_dr(self):
        """One router alone should become DR."""
        intf = _make_election_interface(
            my_rid=IPv4Address("10.0.0.1"),
            my_ip=IPv4Address("192.168.1.1"),
            my_priority=1,
        )
        new_dr, new_bdr = elect_dr_bdr(intf)
        assert new_dr == IPv4Address("192.168.1.1")

    def test_higher_priority_wins(self):
        """Higher priority router should become DR."""
        intf = _make_election_interface(
            my_rid=IPv4Address("10.0.0.1"),
            my_ip=IPv4Address("192.168.1.1"),
            my_priority=1,
        )
        nbr = _make_neighbor(
            rid=IPv4Address("10.0.0.2"),
            ip=IPv4Address("192.168.1.2"),
            priority=2,
            dr=IPv4Address("192.168.1.2"),
            bdr=IPv4Address("0.0.0.0"),
        )
        intf.neighbors = {IPv4Address("10.0.0.2"): nbr}

        new_dr, new_bdr = elect_dr_bdr(intf)
        assert new_dr == IPv4Address("192.168.1.2")

    def test_higher_rid_breaks_tie(self):
        """With equal priority, higher router ID should win."""
        intf = _make_election_interface(
            my_rid=IPv4Address("10.0.0.1"),
            my_ip=IPv4Address("192.168.1.1"),
            my_priority=1,
            my_dr=IPv4Address("192.168.1.1"),
        )
        nbr = _make_neighbor(
            rid=IPv4Address("10.0.0.2"),
            ip=IPv4Address("192.168.1.2"),
            priority=1,
            dr=IPv4Address("192.168.1.2"),
            bdr=IPv4Address("0.0.0.0"),
        )
        intf.neighbors = {IPv4Address("10.0.0.2"): nbr}

        new_dr, new_bdr = elect_dr_bdr(intf)
        # Higher RID (10.0.0.2) should win
        assert new_dr == IPv4Address("192.168.1.2")

    def test_priority_zero_excluded(self):
        """Routers with priority 0 should never be DR or BDR."""
        intf = _make_election_interface(
            my_rid=IPv4Address("10.0.0.1"),
            my_ip=IPv4Address("192.168.1.1"),
            my_priority=0,
        )
        nbr = _make_neighbor(
            rid=IPv4Address("10.0.0.2"),
            ip=IPv4Address("192.168.1.2"),
            priority=1,
            dr=IPv4Address("192.168.1.2"),
            bdr=IPv4Address("0.0.0.0"),
        )
        intf.neighbors = {IPv4Address("10.0.0.2"): nbr}

        new_dr, new_bdr = elect_dr_bdr(intf)
        assert new_dr == IPv4Address("192.168.1.2")

    def test_no_eligible_candidates(self):
        """All priority 0 should result in 0.0.0.0 DR."""
        intf = _make_election_interface(
            my_priority=0,
        )
        nbr = _make_neighbor(
            rid=IPv4Address("10.0.0.2"),
            ip=IPv4Address("192.168.1.2"),
            priority=0,
            dr=IPv4Address("0.0.0.0"),
            bdr=IPv4Address("0.0.0.0"),
            state=NBR_STATE_2WAY,
        )
        intf.neighbors = {IPv4Address("10.0.0.2"): nbr}

        new_dr, new_bdr = elect_dr_bdr(intf)
        assert new_dr == IPv4Address("0.0.0.0")
        assert new_bdr == IPv4Address("0.0.0.0")
