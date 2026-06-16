"""Tests for RFC 8665 Segment Routing extension."""
import struct
import pytest
from ipaddress import IPv4Address, IPv4Network

from ospfd.const import (
    LSA_TYPE_OPAQUE_AREA, OPAQUE_TYPE_RI, OPAQUE_TYPE_EXTENDED_PREFIX,
    OPAQUE_TYPE_EXTENDED_LINK, RI_TLV_SR_CAPABILITIES, RI_TLV_SR_ALGORITHM,
    RI_TLV_SID_LABEL_RANGE, EP_TLV_EXTENDED_PREFIX, EL_TLV_EXTENDED_LINK,
    SR_STLV_PREFIX_SID, SR_STLV_ADJ_SID, PREFIX_SID_FLAG_NP, PREFIX_SID_FLAG_V,
    ADJ_SID_FLAG_V, ADJ_SID_FLAG_L, SR_DEFAULT_SRGB_START, SR_DEFAULT_SRGB_SIZE,
)
from ospfd.sr.tlv import (
    parse_tlvs, encode_tlv, SidLabelRange, SrCapabilities,
    SrAlgorithm, PrefixSid, AdjSid, ExtendedPrefixEntry, ExtendedLinkEntry,
)
from ospfd.sr.lsa import (
    RouterInfoLsa, ExtendedPrefixLsa, ExtendedLinkLsa,
    opaque_type_from_lsa_id, opaque_id_from_lsa_id, make_opaque_lsa_id,
    _parse_sid_label_range, _encode_sid_label_range,
)


# ── TLV parsing ────────────────────────────────────────────────────────────

class TestTlvParsing:
    def test_encode_and_parse_tlv(self):
        encoded = encode_tlv(1, b"\x01\x02\x03")
        tlvs = parse_tlvs(encoded)
        assert len(tlvs) == 1
        assert tlvs[0][0] == 1
        assert tlvs[0][1] == b"\x01\x02\x03"

    def test_parse_multiple_tlvs(self):
        data = encode_tlv(1, b"abc") + encode_tlv(2, b"de")
        tlvs = parse_tlvs(data)
        assert len(tlvs) == 2
        assert tlvs[0] == (1, b"abc")
        assert tlvs[1] == (2, b"de")

    def test_tlv_padding_to_4_bytes(self):
        # 3-byte value should be padded to 4 bytes total
        encoded = encode_tlv(5, b"\x01\x02\x03")
        assert len(encoded) == 4 + 4  # header + padded value
        # But length field says 3
        _, length = struct.unpack_from("!HH", encoded)
        assert length == 3

    def test_empty_tlv_value(self):
        encoded = encode_tlv(99, b"")
        tlvs = parse_tlvs(encoded)
        assert len(tlvs) == 1
        assert tlvs[0] == (99, b"")

    def test_truncated_tlv_ignored(self):
        # TLV header says length=10 but only 3 bytes of value
        data = struct.pack("!HH", 1, 10) + b"\x01\x02\x03"
        tlvs = parse_tlvs(data)
        assert len(tlvs) == 0  # truncated, should be ignored

    def test_parse_tlvs_with_offset(self):
        prefix = b"\x00\x00"
        data = prefix + encode_tlv(7, b"test")
        tlvs = parse_tlvs(data, offset=2)
        assert len(tlvs) == 1
        assert tlvs[0][0] == 7


# ── SidLabelRange ─────────────────────────────────────────────────────────

class TestSidLabelRange:
    def test_contains(self):
        r = SidLabelRange(start=16000, size=8000)
        assert r.contains(0)
        assert r.contains(7999)
        assert not r.contains(8000)
        assert not r.contains(-1)

    def test_label_for_index(self):
        r = SidLabelRange(start=16000, size=8000)
        assert r.label_for_index(0) == 16000
        assert r.label_for_index(100) == 16100
        assert r.label_for_index(7999) == 23999

    def test_encode_decode_roundtrip(self):
        r = SidLabelRange(start=16000, size=8000)
        encoded = _encode_sid_label_range(r)
        decoded = _parse_sid_label_range(encoded)
        assert decoded.start == r.start
        assert decoded.size == r.size


# ── PrefixSid ─────────────────────────────────────────────────────────────

class TestPrefixSid:
    def test_serialize_index_form(self):
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=100)
        data = psid.serialize()
        # flags(1) + reserved(1) + algo(1) + reserved(1) + index(4)
        assert len(data) == 8
        assert data[0] == PREFIX_SID_FLAG_NP
        assert data[2] == 0  # algorithm SPF
        assert struct.unpack_from("!I", data, 4)[0] == 100

    def test_deserialize_index_form(self):
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=200)
        recovered = PrefixSid.deserialize(psid.serialize())
        assert recovered.flags == psid.flags
        assert recovered.algorithm == psid.algorithm
        assert recovered.sid == psid.sid

    def test_deserialize_label_form(self):
        # V-flag set: 3-byte label
        flags = PREFIX_SID_FLAG_V | PREFIX_SID_FLAG_NP
        label = 16100
        data = bytes([flags, 0, 0, 0]) + struct.pack("!I", label)[1:]  # 3 bytes
        psid = PrefixSid.deserialize(data)
        assert psid.is_value
        assert psid.sid == label

    def test_no_php_flag(self):
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=5)
        assert psid.no_php

    def test_roundtrip_serialize_deserialize(self):
        original = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=42)
        recovered = PrefixSid.deserialize(original.serialize())
        assert recovered.flags == original.flags
        assert recovered.sid == original.sid


# ── AdjSid ────────────────────────────────────────────────────────────────

class TestAdjSid:
    def test_serialize_label_form(self):
        flags = ADJ_SID_FLAG_V | ADJ_SID_FLAG_L
        asid = AdjSid(flags=flags, weight=0, sid=16010)
        data = asid.serialize()
        assert asid.is_value
        assert len(data) == 7  # 4 header + 3 label bytes

    def test_roundtrip(self):
        flags = ADJ_SID_FLAG_V | ADJ_SID_FLAG_L
        original = AdjSid(flags=flags, weight=0, sid=16100)
        recovered = AdjSid.deserialize(original.serialize())
        assert recovered.flags == original.flags
        assert recovered.sid == original.sid
        assert recovered.weight == original.weight


# ── Opaque LSA ID helpers ──────────────────────────────────────────────────

class TestOpaqueLsaId:
    def test_make_opaque_lsa_id(self):
        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_RI, 0)
        assert int(lsa_id) == (OPAQUE_TYPE_RI << 24)

    def test_opaque_type_roundtrip(self):
        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_EXTENDED_PREFIX, 12345)
        assert opaque_type_from_lsa_id(lsa_id) == OPAQUE_TYPE_EXTENDED_PREFIX
        assert opaque_id_from_lsa_id(lsa_id) == 12345

    def test_opaque_type_ri(self):
        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_RI, 0)
        assert opaque_type_from_lsa_id(lsa_id) == OPAQUE_TYPE_RI

    def test_opaque_type_extended_link(self):
        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_EXTENDED_LINK, 1)
        assert opaque_type_from_lsa_id(lsa_id) == OPAQUE_TYPE_EXTENDED_LINK
        assert opaque_id_from_lsa_id(lsa_id) == 1


# ── RouterInfoLsa ─────────────────────────────────────────────────────────

class TestRouterInfoLsa:
    def _make_ri_body(self, srgb_start=16000, srgb_size=8000, algorithms=None):
        """Build a minimal RI LSA body with SRGB."""
        algorithms = algorithms or [0]
        srgb = SidLabelRange(start=srgb_start, size=srgb_size)

        from ospfd.sr.lsa import _encode_sid_label_range
        srgb_encoded = _encode_sid_label_range(srgb)

        # SR-Capabilities TLV (minimal: flags + reserved + range_size + SID/Label sub-TLV)
        range_bytes = struct.pack("!I", srgb_size)[1:]  # 3 bytes
        label_bytes = struct.pack("!I", srgb_start)[1:]  # 3 bytes
        label_stlv = encode_tlv(1, label_bytes)  # SID/Label sub-TLV
        cap_value = bytes([0, 0]) + range_bytes + label_stlv  # flags + reserved + range + stlv
        cap_tlv = encode_tlv(RI_TLV_SR_CAPABILITIES, cap_value)

        algo_tlv = encode_tlv(RI_TLV_SR_ALGORITHM, bytes(algorithms))
        range_tlv = encode_tlv(RI_TLV_SID_LABEL_RANGE, srgb_encoded)

        return cap_tlv + algo_tlv + range_tlv

    def test_deserialize_srgb(self):
        body = self._make_ri_body(srgb_start=16000, srgb_size=8000)
        ri = RouterInfoLsa.deserialize(body)
        assert ri.srgb is not None
        assert ri.srgb.start == 16000
        assert ri.srgb.size == 8000

    def test_deserialize_algorithms(self):
        body = self._make_ri_body(algorithms=[0, 1])
        ri = RouterInfoLsa.deserialize(body)
        assert 0 in ri.sr_algorithms

    def test_serialize_deserialize_roundtrip(self):
        srgb = SidLabelRange(start=16000, size=8000)
        ri = RouterInfoLsa()
        ri.srgb = srgb
        ri.sr_algorithms = [0]
        ri.sr_capabilities = SrCapabilities(flags=0, ranges=[srgb])

        serialized = ri.serialize()
        recovered = RouterInfoLsa.deserialize(serialized)

        assert recovered.srgb is not None
        assert recovered.srgb.start == srgb.start
        assert recovered.srgb.size == srgb.size

    def test_empty_body_produces_no_srgb(self):
        ri = RouterInfoLsa.deserialize(b"")
        assert ri.srgb is None
        assert ri.sr_algorithms == [0]


# ── ExtendedPrefixLsa ─────────────────────────────────────────────────────

class TestExtendedPrefixLsa:
    def _make_ep_body(self, prefix="10.0.1.0", plen=24, sid_index=100):
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=sid_index)
        stlv = encode_tlv(SR_STLV_PREFIX_SID, psid.serialize())

        prefix_ip = IPv4Address(prefix)
        ep_value = bytes([1, plen, 0, PREFIX_SID_FLAG_NP]) + prefix_ip.packed + stlv
        return encode_tlv(EP_TLV_EXTENDED_PREFIX, ep_value)

    def test_deserialize_prefix_sid(self):
        body = self._make_ep_body(prefix="10.0.1.0", plen=24, sid_index=100)
        ep = ExtendedPrefixLsa.deserialize(body)
        assert len(ep.prefixes) == 1
        entry = ep.prefixes[0]
        assert entry.prefix == IPv4Address("10.0.1.0")
        assert entry.prefix_len == 24
        assert entry.prefix_sid is not None
        assert entry.prefix_sid.sid == 100

    def test_deserialize_multiple_prefixes(self):
        body = self._make_ep_body("10.0.1.0", 24, 100) + \
               self._make_ep_body("10.0.2.0", 24, 200)
        ep = ExtendedPrefixLsa.deserialize(body)
        assert len(ep.prefixes) == 2

    def test_empty_body(self):
        ep = ExtendedPrefixLsa.deserialize(b"")
        assert ep.prefixes == []


# ── ExtendedLinkLsa ───────────────────────────────────────────────────────

class TestExtendedLinkLsa:
    def _make_el_body(self, link_id="192.168.1.2", label=16010):
        asid = AdjSid(flags=ADJ_SID_FLAG_V | ADJ_SID_FLAG_L, weight=0, sid=label)
        stlv = encode_tlv(SR_STLV_ADJ_SID, asid.serialize())

        link_id_ip = IPv4Address(link_id)
        link_data_ip = IPv4Address("192.168.1.1")
        # link_type(1) + reserved(3) + link_id(4) + link_data(4)
        el_value = bytes([1, 0, 0, 0]) + link_id_ip.packed + link_data_ip.packed + stlv
        return encode_tlv(EL_TLV_EXTENDED_LINK, el_value)

    def test_deserialize_adj_sid(self):
        body = self._make_el_body(link_id="192.168.1.2", label=16010)
        el = ExtendedLinkLsa.deserialize(body)
        assert len(el.links) == 1
        link = el.links[0]
        assert len(link.adj_sids) == 1
        assert link.adj_sids[0].sid == 16010
        assert link.adj_sids[0].is_value

    def test_empty_body(self):
        el = ExtendedLinkLsa.deserialize(b"")
        assert el.links == []


# ── SR label computation ───────────────────────────────────────────────────

class TestSrLabelComputation:
    def test_label_for_prefix_sid_index(self):
        from ospfd.sr.database import NodeSrInfo
        node = NodeSrInfo(router_id=IPv4Address("1.1.1.1"))
        node.srgb = SidLabelRange(start=16000, size=8000)
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=100)
        label = node.label_for_prefix_sid(psid)
        assert label == 16100

    def test_label_for_prefix_sid_absolute(self):
        from ospfd.sr.database import NodeSrInfo
        node = NodeSrInfo(router_id=IPv4Address("1.1.1.1"))
        node.srgb = SidLabelRange(start=16000, size=8000)
        psid = PrefixSid(flags=PREFIX_SID_FLAG_V | PREFIX_SID_FLAG_NP, algorithm=0, sid=20000)
        label = node.label_for_prefix_sid(psid)
        assert label == 20000  # absolute label

    def test_label_out_of_srgb_returns_none(self):
        from ospfd.sr.database import NodeSrInfo
        node = NodeSrInfo(router_id=IPv4Address("1.1.1.1"))
        node.srgb = SidLabelRange(start=16000, size=100)
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=200)
        label = node.label_for_prefix_sid(psid)
        assert label is None

    def test_no_srgb_returns_none(self):
        from ospfd.sr.database import NodeSrInfo
        node = NodeSrInfo(router_id=IPv4Address("1.1.1.1"))
        node.srgb = None
        psid = PrefixSid(flags=PREFIX_SID_FLAG_NP, algorithm=0, sid=100)
        assert node.label_for_prefix_sid(psid) is None
