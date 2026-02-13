"""Tests for the Link State Database."""

import time
import pytest
from ipaddress import IPv4Address

from ospfd.const import INITIAL_SEQ_NUM, MAX_AGE, LSA_TYPE_ROUTER, LSA_TYPE_EXTERNAL
from ospfd.lsdb.database import LinkStateDatabase
from ospfd.packet.lsa import Lsa, LsaHeader, RouterLsa, RouterLsaLink, LINK_TYPE_STUB


def _make_lsa(ls_type=1, ls_id="10.0.0.1", adv_rtr="10.0.0.1",
              seq=INITIAL_SEQ_NUM, age=0, checksum=0x1234):
    header = LsaHeader(
        ls_age=age, options=0x02, ls_type=ls_type,
        link_state_id=IPv4Address(ls_id),
        advertising_router=IPv4Address(adv_rtr),
        ls_sequence_number=seq,
        ls_checksum=checksum, length=20,
    )
    body = RouterLsa(flags=0, num_links=0, links=[])
    return Lsa(header=header, body=body)


class TestLinkStateDatabase:
    def test_install_new_lsa(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        lsdb.ensure_area(IPv4Address("0.0.0.0"))

        lsa = _make_lsa()
        installed, old = lsdb.install(IPv4Address("0.0.0.0"), lsa)
        assert installed is True
        assert old is None

    def test_install_newer_replaces(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa1 = _make_lsa(seq=INITIAL_SEQ_NUM)
        lsdb.install(area, lsa1)

        # Set last_arrival to far in the past to bypass MinLSArrival in tests
        past = time.monotonic() - 10
        for key in lsdb._last_arrival:
            lsdb._last_arrival[key] = past

        lsa2 = _make_lsa(seq=INITIAL_SEQ_NUM + 1)
        installed, old = lsdb.install(area, lsa2)
        assert installed is True
        assert old is not None

    def test_install_older_rejected(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa_new = _make_lsa(seq=INITIAL_SEQ_NUM + 5)
        lsdb.install(area, lsa_new)

        lsa_old = _make_lsa(seq=INITIAL_SEQ_NUM)
        installed, old = lsdb.install(area, lsa_old)
        assert installed is False

    def test_lookup(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa = _make_lsa()
        lsdb.install(area, lsa)

        key = (1, IPv4Address("10.0.0.1"), IPv4Address("10.0.0.1"))
        result = lsdb.lookup(area, key)
        assert result is not None
        assert result.header.ls_sequence_number == INITIAL_SEQ_NUM

    def test_lookup_nonexistent(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        key = (1, IPv4Address("10.0.0.1"), IPv4Address("10.0.0.1"))
        result = lsdb.lookup(IPv4Address("0.0.0.0"), key)
        assert result is None

    def test_remove(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa = _make_lsa()
        lsdb.install(area, lsa)

        key = lsa.key
        removed = lsdb.remove(area, key)
        assert removed is not None
        assert lsdb.lookup(area, key) is None

    def test_compare_lsa_seq_higher_wins(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        h1 = LsaHeader(ls_age=0, options=0, ls_type=1,
                        link_state_id=IPv4Address("10.0.0.1"),
                        advertising_router=IPv4Address("10.0.0.1"),
                        ls_sequence_number=INITIAL_SEQ_NUM,
                        ls_checksum=0x1234, length=20)
        h2 = LsaHeader(ls_age=0, options=0, ls_type=1,
                        link_state_id=IPv4Address("10.0.0.1"),
                        advertising_router=IPv4Address("10.0.0.1"),
                        ls_sequence_number=INITIAL_SEQ_NUM + 1,
                        ls_checksum=0x1234, length=20)
        assert lsdb.compare_lsa(h2, h1) > 0
        assert lsdb.compare_lsa(h1, h2) < 0

    def test_compare_lsa_maxage_wins(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        h1 = LsaHeader(ls_age=MAX_AGE, options=0, ls_type=1,
                        link_state_id=IPv4Address("10.0.0.1"),
                        advertising_router=IPv4Address("10.0.0.1"),
                        ls_sequence_number=INITIAL_SEQ_NUM,
                        ls_checksum=0x1234, length=20)
        h2 = LsaHeader(ls_age=100, options=0, ls_type=1,
                        link_state_id=IPv4Address("10.0.0.1"),
                        advertising_router=IPv4Address("10.0.0.1"),
                        ls_sequence_number=INITIAL_SEQ_NUM,
                        ls_checksum=0x1234, length=20)
        assert lsdb.compare_lsa(h1, h2) > 0  # MaxAge wins

    def test_is_self_originated(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        lsa_self = _make_lsa(adv_rtr="10.0.0.1")
        lsa_other = _make_lsa(adv_rtr="10.0.0.2")
        assert lsdb.is_self_originated(lsa_self)
        assert not lsdb.is_self_originated(lsa_other)

    def test_external_lsa_storage(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa = _make_lsa(ls_type=LSA_TYPE_EXTERNAL, ls_id="172.16.0.0")
        lsdb.install(area, lsa)

        # Should be in external DB
        result = lsdb.lookup(area, lsa.key)
        assert result is not None

        # Should be in get_all_external
        externals = lsdb.get_all_external()
        assert len(externals) == 1

    def test_get_all_headers(self):
        lsdb = LinkStateDatabase(IPv4Address("10.0.0.1"))
        area = IPv4Address("0.0.0.0")
        lsdb.ensure_area(area)

        lsa1 = _make_lsa(ls_id="10.0.0.1")
        lsa2 = _make_lsa(ls_id="10.0.0.2", adv_rtr="10.0.0.2")
        lsdb.install(area, lsa1)
        lsdb.install(area, lsa2)

        headers = lsdb.get_all_headers(area)
        assert len(headers) == 2
