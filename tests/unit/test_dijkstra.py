"""Tests for SPF/Dijkstra algorithm."""

import pytest
from ipaddress import IPv4Address
from unittest.mock import MagicMock

from ospfd.const import (
    LSA_TYPE_ROUTER, LSA_TYPE_NETWORK, INITIAL_SEQ_NUM,
    LINK_TYPE_P2P, LINK_TYPE_STUB, LINK_TYPE_TRANSIT,
)
from ospfd.packet.lsa import (
    Lsa, LsaHeader, RouterLsa, RouterLsaLink, NetworkLsa,
)
from ospfd.spf.dijkstra import DijkstraEngine, SpfVertex


def _make_router_lsa(rid: str, links: list, flags: int = 0) -> Lsa:
    """Helper to create a Router LSA."""
    router_links = []
    for link_id, link_data, link_type, metric in links:
        router_links.append(RouterLsaLink(
            link_id=IPv4Address(link_id),
            link_data=IPv4Address(link_data),
            type=link_type,
            num_tos=0,
            metric=metric,
        ))
    body = RouterLsa(flags=flags, num_links=len(router_links), links=router_links)
    header = LsaHeader(
        ls_age=0, options=0x02, ls_type=LSA_TYPE_ROUTER,
        link_state_id=IPv4Address(rid),
        advertising_router=IPv4Address(rid),
        ls_sequence_number=INITIAL_SEQ_NUM,
        ls_checksum=0, length=0,
    )
    lsa = Lsa(header=header, body=body)
    lsa.mark_installed()
    return lsa


def _make_network_lsa(dr_ip: str, adv_router: str, mask: str, attached: list) -> Lsa:
    """Helper to create a Network LSA."""
    body = NetworkLsa(
        network_mask=IPv4Address(mask),
        attached_routers=[IPv4Address(r) for r in attached],
    )
    header = LsaHeader(
        ls_age=0, options=0x02, ls_type=LSA_TYPE_NETWORK,
        link_state_id=IPv4Address(dr_ip),
        advertising_router=IPv4Address(adv_router),
        ls_sequence_number=INITIAL_SEQ_NUM,
        ls_checksum=0, length=0,
    )
    lsa = Lsa(header=header, body=body)
    lsa.mark_installed()
    return lsa


class TestDijkstra:
    def test_single_router(self):
        """Single router should produce a tree with just the root."""
        lsdb = MagicMock()
        root_lsa = _make_router_lsa("10.0.0.1", [
            ("192.168.1.0", "255.255.255.0", LINK_TYPE_STUB, 10),
        ])
        lsdb.lookup.return_value = root_lsa
        lsdb.get_all.return_value = []

        instance = MagicMock()
        instance.lsdb = lsdb
        instance.router_id = IPv4Address("10.0.0.1")
        instance.areas = {}

        engine = DijkstraEngine(instance)
        tree = engine.calculate(IPv4Address("0.0.0.0"))

        assert IPv4Address("10.0.0.1") in tree
        assert tree[IPv4Address("10.0.0.1")].distance == 0

    def test_two_routers_p2p(self):
        """Two routers connected P2P should both appear in tree."""
        r1_lsa = _make_router_lsa("10.0.0.1", [
            ("10.0.0.2", "192.168.1.1", LINK_TYPE_P2P, 10),
            ("192.168.1.0", "255.255.255.252", LINK_TYPE_STUB, 10),
        ])
        r2_lsa = _make_router_lsa("10.0.0.2", [
            ("10.0.0.1", "192.168.1.2", LINK_TYPE_P2P, 10),
            ("192.168.2.0", "255.255.255.0", LINK_TYPE_STUB, 20),
        ])

        lsdb = MagicMock()
        def mock_lookup(area_id, key):
            if key == (LSA_TYPE_ROUTER, IPv4Address("10.0.0.1"), IPv4Address("10.0.0.1")):
                return r1_lsa
            if key == (LSA_TYPE_ROUTER, IPv4Address("10.0.0.2"), IPv4Address("10.0.0.2")):
                return r2_lsa
            return None
        lsdb.lookup.side_effect = mock_lookup
        lsdb.get_all.return_value = []

        instance = MagicMock()
        instance.lsdb = lsdb
        instance.router_id = IPv4Address("10.0.0.1")
        instance.areas = {}

        engine = DijkstraEngine(instance)
        tree = engine.calculate(IPv4Address("0.0.0.0"))

        assert IPv4Address("10.0.0.1") in tree
        assert IPv4Address("10.0.0.2") in tree
        assert tree[IPv4Address("10.0.0.1")].distance == 0
        assert tree[IPv4Address("10.0.0.2")].distance == 10
