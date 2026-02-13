"""Tests for OSPF packet serialization/deserialization."""

import struct
import pytest
from ipaddress import IPv4Address

from ospfd.packet.header import OspfHeader, OSPF_HDR_LEN
from ospfd.packet.hello import HelloPacket, HELLO_FIXED_LEN
from ospfd.packet.dd import DDPacket, DD_FIXED_LEN
from ospfd.packet.lsr import LsrPacket, LsrItem, LSR_ITEM_LEN
from ospfd.packet.lsu import LsuPacket
from ospfd.packet.lsack import LsackPacket
from ospfd.packet.lsa import (
    LsaHeader, LSA_HDR_LEN, Lsa,
    RouterLsa, RouterLsaLink, NetworkLsa, SummaryLsa, ExternalLsa,
    LINK_TYPE_P2P, LINK_TYPE_TRANSIT, LINK_TYPE_STUB,
)
from ospfd.const import DD_FLAG_I, DD_FLAG_M, DD_FLAG_MS


class TestOspfHeader:
    def test_serialize_deserialize(self):
        hdr = OspfHeader(
            version=2, type=1, length=44,
            router_id=IPv4Address("10.0.0.1"),
            area_id=IPv4Address("0.0.0.0"),
            checksum=0xABCD,
            auth_type=0,
            auth_data=b"\x00" * 8,
        )
        data = hdr.serialize()
        assert len(data) == OSPF_HDR_LEN

        hdr2 = OspfHeader.deserialize(data)
        assert hdr2.version == 2
        assert hdr2.type == 1
        assert hdr2.length == 44
        assert hdr2.router_id == IPv4Address("10.0.0.1")
        assert hdr2.area_id == IPv4Address("0.0.0.0")
        assert hdr2.checksum == 0xABCD
        assert hdr2.auth_type == 0

    def test_build(self):
        hdr = OspfHeader.build(
            pkt_type=1,
            router_id=IPv4Address("10.0.0.1"),
            area_id=IPv4Address("0.0.0.1"),
        )
        assert hdr.version == 2
        assert hdr.type == 1
        assert hdr.length == 0  # to be filled
        assert hdr.checksum == 0

    def test_short_data_raises(self):
        with pytest.raises(ValueError):
            OspfHeader.deserialize(b"\x00" * 10)


class TestHelloPacket:
    def test_round_trip(self):
        hello = HelloPacket(
            network_mask=IPv4Address("255.255.255.0"),
            hello_interval=10,
            options=0x02,
            priority=1,
            dead_interval=40,
            designated_router=IPv4Address("10.0.0.1"),
            backup_designated_router=IPv4Address("10.0.0.2"),
            neighbors=[IPv4Address("10.0.0.3"), IPv4Address("10.0.0.4")],
        )
        data = hello.serialize()
        assert len(data) == HELLO_FIXED_LEN + 8  # 2 neighbors * 4 bytes

        hello2 = HelloPacket.deserialize(data)
        assert hello2.network_mask == IPv4Address("255.255.255.0")
        assert hello2.hello_interval == 10
        assert hello2.options == 0x02
        assert hello2.priority == 1
        assert hello2.dead_interval == 40
        assert hello2.designated_router == IPv4Address("10.0.0.1")
        assert hello2.backup_designated_router == IPv4Address("10.0.0.2")
        assert len(hello2.neighbors) == 2
        assert hello2.neighbors[0] == IPv4Address("10.0.0.3")

    def test_empty_neighbors(self):
        hello = HelloPacket(
            network_mask=IPv4Address("255.255.255.0"),
            hello_interval=10, options=0, priority=0,
            dead_interval=40,
            designated_router=IPv4Address("0.0.0.0"),
            backup_designated_router=IPv4Address("0.0.0.0"),
        )
        data = hello.serialize()
        assert len(data) == HELLO_FIXED_LEN


class TestDDPacket:
    def test_round_trip(self):
        dd = DDPacket(
            interface_mtu=1500,
            options=0x02,
            flags=DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS,
            dd_seq_number=12345,
        )
        data = dd.serialize()
        assert len(data) == DD_FIXED_LEN

        dd2 = DDPacket.deserialize(data)
        assert dd2.interface_mtu == 1500
        assert dd2.flags == DD_FLAG_I | DD_FLAG_M | DD_FLAG_MS
        assert dd2.dd_seq_number == 12345
        assert dd2.is_init
        assert dd2.is_more
        assert dd2.is_master

    def test_with_lsa_headers(self):
        lsa_hdr = LsaHeader(
            ls_age=10, options=2, ls_type=1,
            link_state_id=IPv4Address("10.0.0.1"),
            advertising_router=IPv4Address("10.0.0.1"),
            ls_sequence_number=0x80000001,
            ls_checksum=0x1234, length=36,
        )
        dd = DDPacket(
            interface_mtu=1500, options=2,
            flags=DD_FLAG_M, dd_seq_number=100,
            lsa_headers=[lsa_hdr],
        )
        data = dd.serialize()
        assert len(data) == DD_FIXED_LEN + LSA_HDR_LEN

        dd2 = DDPacket.deserialize(data)
        assert len(dd2.lsa_headers) == 1
        assert dd2.lsa_headers[0].link_state_id == IPv4Address("10.0.0.1")


class TestLsrPacket:
    def test_round_trip(self):
        items = [
            LsrItem(ls_type=1, link_state_id=IPv4Address("10.0.0.1"),
                     advertising_router=IPv4Address("10.0.0.1")),
            LsrItem(ls_type=2, link_state_id=IPv4Address("10.0.0.2"),
                     advertising_router=IPv4Address("10.0.0.2")),
        ]
        pkt = LsrPacket(items=items)
        data = pkt.serialize()
        assert len(data) == LSR_ITEM_LEN * 2

        pkt2 = LsrPacket.deserialize(data)
        assert len(pkt2.items) == 2
        assert pkt2.items[0].ls_type == 1
        assert pkt2.items[1].link_state_id == IPv4Address("10.0.0.2")


class TestLsaHeader:
    def test_round_trip(self):
        hdr = LsaHeader(
            ls_age=100, options=0x02, ls_type=1,
            link_state_id=IPv4Address("10.0.0.1"),
            advertising_router=IPv4Address("10.0.0.1"),
            ls_sequence_number=0x80000001,
            ls_checksum=0xABCD, length=36,
        )
        data = hdr.serialize()
        assert len(data) == LSA_HDR_LEN

        hdr2 = LsaHeader.deserialize(data)
        assert hdr2.ls_age == 100
        assert hdr2.ls_type == 1
        assert hdr2.link_state_id == IPv4Address("10.0.0.1")
        assert hdr2.ls_sequence_number == 0x80000001

    def test_key(self):
        hdr = LsaHeader(
            ls_age=0, options=0, ls_type=1,
            link_state_id=IPv4Address("10.0.0.1"),
            advertising_router=IPv4Address("10.0.0.1"),
            ls_sequence_number=0, ls_checksum=0, length=20,
        )
        assert hdr.key == (1, IPv4Address("10.0.0.1"), IPv4Address("10.0.0.1"))


class TestRouterLsa:
    def test_round_trip(self):
        link = RouterLsaLink(
            link_id=IPv4Address("10.0.0.2"),
            link_data=IPv4Address("10.0.0.1"),
            type=LINK_TYPE_P2P,
            num_tos=0,
            metric=10,
        )
        lsa = RouterLsa(flags=0x01, num_links=1, links=[link])
        data = lsa.serialize()

        lsa2 = RouterLsa.deserialize(data)
        assert lsa2.flags == 0x01
        assert lsa2.num_links == 1
        assert len(lsa2.links) == 1
        assert lsa2.links[0].link_id == IPv4Address("10.0.0.2")
        assert lsa2.links[0].metric == 10

    def test_multiple_links(self):
        links = [
            RouterLsaLink(
                link_id=IPv4Address("10.0.0.2"),
                link_data=IPv4Address("10.0.0.1"),
                type=LINK_TYPE_P2P, num_tos=0, metric=10,
            ),
            RouterLsaLink(
                link_id=IPv4Address("192.168.1.0"),
                link_data=IPv4Address("255.255.255.0"),
                type=LINK_TYPE_STUB, num_tos=0, metric=1,
            ),
            RouterLsaLink(
                link_id=IPv4Address("10.0.0.3"),
                link_data=IPv4Address("10.0.0.1"),
                type=LINK_TYPE_TRANSIT, num_tos=0, metric=5,
            ),
        ]
        lsa = RouterLsa(flags=0x03, num_links=3, links=links)
        data = lsa.serialize()
        lsa2 = RouterLsa.deserialize(data)
        assert lsa2.num_links == 3
        assert lsa2.links[1].type == LINK_TYPE_STUB
        assert lsa2.links[2].metric == 5


class TestNetworkLsa:
    def test_round_trip(self):
        lsa = NetworkLsa(
            network_mask=IPv4Address("255.255.255.0"),
            attached_routers=[
                IPv4Address("10.0.0.1"),
                IPv4Address("10.0.0.2"),
                IPv4Address("10.0.0.3"),
            ],
        )
        data = lsa.serialize()
        assert len(data) == 4 + 12  # mask + 3 routers

        lsa2 = NetworkLsa.deserialize(data, length=len(data))
        assert lsa2.network_mask == IPv4Address("255.255.255.0")
        assert len(lsa2.attached_routers) == 3


class TestSummaryLsa:
    def test_round_trip(self):
        lsa = SummaryLsa(
            network_mask=IPv4Address("255.255.255.0"),
            metric=100,
        )
        data = lsa.serialize()
        assert len(data) == 8

        lsa2 = SummaryLsa.deserialize(data)
        assert lsa2.network_mask == IPv4Address("255.255.255.0")
        assert lsa2.metric == 100


class TestExternalLsa:
    def test_round_trip_e2(self):
        lsa = ExternalLsa(
            network_mask=IPv4Address("255.255.255.0"),
            e_bit=True,
            metric=200,
            forwarding_address=IPv4Address("10.0.0.1"),
            external_route_tag=42,
        )
        data = lsa.serialize()
        assert len(data) == 16

        lsa2 = ExternalLsa.deserialize(data)
        assert lsa2.e_bit is True
        assert lsa2.metric == 200
        assert lsa2.forwarding_address == IPv4Address("10.0.0.1")
        assert lsa2.external_route_tag == 42

    def test_round_trip_e1(self):
        lsa = ExternalLsa(
            network_mask=IPv4Address("255.255.0.0"),
            e_bit=False,
            metric=50,
            forwarding_address=IPv4Address("0.0.0.0"),
            external_route_tag=0,
        )
        data = lsa.serialize()
        lsa2 = ExternalLsa.deserialize(data)
        assert lsa2.e_bit is False
        assert lsa2.metric == 50


class TestFullLsa:
    def test_router_lsa_serialize_deserialize(self):
        link = RouterLsaLink(
            link_id=IPv4Address("10.0.0.2"),
            link_data=IPv4Address("10.0.0.1"),
            type=LINK_TYPE_P2P, num_tos=0, metric=10,
        )
        body = RouterLsa(flags=0, num_links=1, links=[link])
        header = LsaHeader(
            ls_age=0, options=0x02, ls_type=1,
            link_state_id=IPv4Address("10.0.0.1"),
            advertising_router=IPv4Address("10.0.0.1"),
            ls_sequence_number=0x80000001,
            ls_checksum=0, length=0,
        )
        lsa = Lsa(header=header, body=body)
        data = lsa.serialize(recompute_checksum=True)

        lsa2, consumed = Lsa.deserialize(data)
        assert consumed == len(data)
        assert lsa2.header.ls_type == 1
        assert lsa2.header.ls_checksum != 0
        assert isinstance(lsa2.body, RouterLsa)
        assert lsa2.body.num_links == 1


class TestLsuPacket:
    def test_round_trip(self):
        link = RouterLsaLink(
            link_id=IPv4Address("10.0.0.2"),
            link_data=IPv4Address("10.0.0.1"),
            type=LINK_TYPE_P2P, num_tos=0, metric=10,
        )
        body = RouterLsa(flags=0, num_links=1, links=[link])
        header = LsaHeader(
            ls_age=5, options=0x02, ls_type=1,
            link_state_id=IPv4Address("10.0.0.1"),
            advertising_router=IPv4Address("10.0.0.1"),
            ls_sequence_number=0x80000001,
            ls_checksum=0, length=0,
        )
        lsa = Lsa(header=header, body=body)
        lsa.serialize(recompute_checksum=True)

        lsu = LsuPacket(lsas=[lsa])
        data = lsu.serialize()
        assert data[:4] == struct.pack("!I", 1)  # num_lsas = 1

        lsu2 = LsuPacket.deserialize(data)
        assert lsu2.num_lsas == 1


class TestLsackPacket:
    def test_round_trip(self):
        hdrs = [
            LsaHeader(
                ls_age=10, options=2, ls_type=1,
                link_state_id=IPv4Address("10.0.0.1"),
                advertising_router=IPv4Address("10.0.0.1"),
                ls_sequence_number=0x80000001,
                ls_checksum=0x1234, length=36,
            ),
            LsaHeader(
                ls_age=20, options=2, ls_type=2,
                link_state_id=IPv4Address("10.0.0.2"),
                advertising_router=IPv4Address("10.0.0.2"),
                ls_sequence_number=0x80000002,
                ls_checksum=0x5678, length=28,
            ),
        ]
        ack = LsackPacket(lsa_headers=hdrs)
        data = ack.serialize()
        assert len(data) == LSA_HDR_LEN * 2

        ack2 = LsackPacket.deserialize(data)
        assert len(ack2.lsa_headers) == 2
        assert ack2.lsa_headers[1].ls_type == 2
