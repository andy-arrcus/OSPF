"""Tests for OSPF routing table."""

import pytest
from ipaddress import IPv4Address, IPv4Network

from ospfd.const import PATH_INTRA_AREA, PATH_INTER_AREA, PATH_TYPE1_EXTERNAL, PATH_TYPE2_EXTERNAL
from ospfd.spf.routing_table import OspfRoute, OspfRoutingTable
from ospfd.spf.dijkstra import SpfNexthop


def _nh(name="eth0", ip="10.0.0.1", idx=1):
    return SpfNexthop(interface_name=name, next_hop_ip=IPv4Address(ip), interface_index=idx)


class TestOspfRoute:
    def test_intra_better_than_inter(self):
        r1 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=100,
        )
        r2 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTER_AREA, cost=50,
        )
        assert r1.is_better_than(r2)
        assert not r2.is_better_than(r1)

    def test_lower_cost_wins_same_type(self):
        r1 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=10,
        )
        r2 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=20,
        )
        assert r1.is_better_than(r2)

    def test_type2_external_comparison(self):
        r1 = OspfRoute(
            destination=IPv4Network("172.16.0.0/16"),
            path_type=PATH_TYPE2_EXTERNAL,
            cost=100, type2_cost=50,
        )
        r2 = OspfRoute(
            destination=IPv4Network("172.16.0.0/16"),
            path_type=PATH_TYPE2_EXTERNAL,
            cost=50, type2_cost=100,
        )
        # Lower type2_cost wins
        assert r1.is_better_than(r2)


class TestOspfRoutingTable:
    def test_update_adds_routes(self):
        table = OspfRoutingTable()
        intra = [
            OspfRoute(
                destination=IPv4Network("10.0.0.0/24"),
                path_type=PATH_INTRA_AREA, cost=10,
                nexthops={_nh()},
            ),
        ]
        added, changed, removed = table.update(intra, [], [])
        assert len(added) == 1
        assert len(changed) == 0
        assert len(removed) == 0

    def test_update_removes_routes(self):
        table = OspfRoutingTable()
        intra = [
            OspfRoute(
                destination=IPv4Network("10.0.0.0/24"),
                path_type=PATH_INTRA_AREA, cost=10,
                nexthops={_nh()},
            ),
        ]
        table.update(intra, [], [])

        # Now update with empty -> route should be removed
        added, changed, removed = table.update([], [], [])
        assert len(removed) == 1

    def test_update_changes_routes(self):
        table = OspfRoutingTable()
        r1 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=10,
            nexthops={_nh()},
        )
        table.update([r1], [], [])

        r2 = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=20,
            nexthops={_nh()},
        )
        added, changed, removed = table.update([r2], [], [])
        assert len(changed) == 1
        assert len(added) == 0

    def test_best_route_wins(self):
        table = OspfRoutingTable()
        intra = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTRA_AREA, cost=100,
            nexthops={_nh("eth0", "10.0.0.1")},
        )
        inter = OspfRoute(
            destination=IPv4Network("10.0.0.0/24"),
            path_type=PATH_INTER_AREA, cost=10,
            nexthops={_nh("eth1", "10.0.0.2")},
        )
        table.update([intra], [inter], [])
        # Intra should win over inter
        assert table.routes[IPv4Network("10.0.0.0/24")].path_type == PATH_INTRA_AREA
