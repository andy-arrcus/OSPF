"""SR LSA origination — advertise this router's SR capabilities and SIDs."""
from __future__ import annotations
import logging
import struct
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Optional

from ospfd.const import (
    INITIAL_SEQ_NUM,
    LSA_TYPE_OPAQUE_AREA,
    OPAQUE_TYPE_RI,
    OPAQUE_TYPE_EXTENDED_PREFIX,
    SR_DEFAULT_SRGB_START,
    SR_DEFAULT_SRGB_SIZE,
    SR_ALG_SPF,
    RI_TLV_SR_CAPABILITIES,
    RI_TLV_SR_ALGORITHM,
    RI_TLV_SID_LABEL_RANGE,
    EP_TLV_EXTENDED_PREFIX,
    SR_STLV_PREFIX_SID,
    PREFIX_SID_FLAG_NP,
)
from ospfd.packet.lsa import Lsa, LsaHeader
from ospfd.packet.checksum import fletcher_checksum
from ospfd.sr.lsa import RouterInfoLsa, make_opaque_lsa_id, _encode_sid_label_range
from ospfd.sr.tlv import (
    SidLabelRange, SrCapabilities, SrAlgorithm, encode_tlv, PrefixSid,
)

if TYPE_CHECKING:
    from ospfd.protocol.instance import OspfInstance

logger = logging.getLogger(__name__)


class OpaqueLsaBody:
    """Wrapper for opaque LSA body that satisfies the serialize() interface."""

    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data

    def serialize(self) -> bytes:
        return self.raw_data


class SrOriginator:
    """Generates SR Opaque LSAs for this router."""

    def __init__(self, instance: OspfInstance, srgb: SidLabelRange):
        self._instance = instance
        self.srgb = srgb
        self._node_sid_index: Optional[int] = None  # configured globally

    def set_node_sid(self, index: int) -> None:
        """Set this router's Node-SID index within the SRGB."""
        self._node_sid_index = index

    def originate_ri_lsa(self, area_id: IPv4Address) -> Optional[Lsa]:
        """Originate a Router Information LSA advertising SR capabilities."""
        instance = self._instance
        router_id = instance.router_id

        # Build RI LSA body
        ri = RouterInfoLsa()
        ri.srgb = self.srgb
        ri.sr_algorithms = [SR_ALG_SPF]
        ri.sr_capabilities = SrCapabilities(flags=0, ranges=[self.srgb])

        body = ri.serialize()

        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_RI, 0)
        header = LsaHeader(
            ls_age=0,
            options=0,
            ls_type=LSA_TYPE_OPAQUE_AREA,
            link_state_id=lsa_id,
            advertising_router=router_id,
            ls_sequence_number=INITIAL_SEQ_NUM,
            ls_checksum=0,
            length=0,
        )

        lsa = Lsa(header=header, body=OpaqueLsaBody(body))
        lsa.serialize(recompute_checksum=True)

        installed, _ = instance.lsdb.install(area_id, lsa)
        if installed:
            instance.flooding.flood_lsa(lsa, area_id, None, None)
            logger.info("Originated RI LSA for area %s (SRGB %d+%d)",
                       area_id, self.srgb.start, self.srgb.size)
        return lsa if installed else None

    def originate_prefix_sid_lsa(
        self, area_id: IPv4Address, prefix: IPv4Network, sid_index: int
    ) -> Optional[Lsa]:
        """Originate an Extended Prefix LSA advertising a Prefix-SID."""
        instance = self._instance
        router_id = instance.router_id

        # Extended Prefix TLV value
        prefix_bytes = prefix.network_address.packed
        flags = PREFIX_SID_FLAG_NP  # No-PHP by default
        prefix_hdr = bytes([1, prefix.prefixlen, 0, flags]) + prefix_bytes

        # Prefix-SID sub-TLV
        psid = PrefixSid(flags=flags, algorithm=SR_ALG_SPF, sid=sid_index)
        stlv = encode_tlv(SR_STLV_PREFIX_SID, psid.serialize())

        ep_value = prefix_hdr + stlv
        body = encode_tlv(EP_TLV_EXTENDED_PREFIX, ep_value)

        opaque_id = int(prefix.network_address) & 0x00FFFFFF
        lsa_id = make_opaque_lsa_id(OPAQUE_TYPE_EXTENDED_PREFIX, opaque_id)

        header = LsaHeader(
            ls_age=0,
            options=0,
            ls_type=LSA_TYPE_OPAQUE_AREA,
            link_state_id=lsa_id,
            advertising_router=router_id,
            ls_sequence_number=INITIAL_SEQ_NUM,
            ls_checksum=0,
            length=0,
        )

        lsa = Lsa(header=header, body=OpaqueLsaBody(body))
        lsa.serialize(recompute_checksum=True)

        installed, _ = instance.lsdb.install(area_id, lsa)
        if installed:
            instance.flooding.flood_lsa(lsa, area_id, None, None)
            logger.info("Originated Prefix-SID LSA: %s index=%d", prefix, sid_index)
        return lsa if installed else None
