"""Tests for OSPF checksum algorithms."""

import struct
import pytest
from ospfd.packet.checksum import (
    ip_checksum,
    verify_ip_checksum,
    fletcher_checksum,
    verify_fletcher_checksum,
)


class TestIpChecksum:
    def test_known_vector(self):
        """Test IP checksum with a known vector from RFC 1071."""
        # Example: 0x0001 + 0xf203 + ...
        data = bytes([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
        result = ip_checksum(data)
        assert result != 0

    def test_all_zeros(self):
        """Checksum of all zeros should be 0xFFFF."""
        data = b"\x00" * 20
        result = ip_checksum(data)
        assert result == 0xFFFF

    def test_round_trip(self):
        """Checksum then verify should pass."""
        data = bytearray(b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06"
                         b"\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c")
        # Zero checksum field (bytes 10-11)
        data[10] = 0
        data[11] = 0
        chk = ip_checksum(bytes(data))
        data[10] = (chk >> 8) & 0xFF
        data[11] = chk & 0xFF
        assert verify_ip_checksum(bytes(data))

    def test_odd_length(self):
        """Odd-length data should be handled correctly."""
        data = b"\x01\x02\x03"
        result = ip_checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF


class TestFletcherChecksum:
    def test_basic(self):
        """Fletcher checksum should produce a 16-bit value."""
        # Minimal LSA: 20 bytes header
        lsa_data = bytearray(20)
        lsa_data[0:2] = b"\x00\x00"  # age
        lsa_data[2] = 0x02  # options
        lsa_data[3] = 0x01  # type (Router)
        lsa_data[4:8] = b"\x0a\x00\x00\x01"  # link_state_id
        lsa_data[8:12] = b"\x0a\x00\x00\x01"  # adv_router
        struct.pack_into("!I", lsa_data, 12, 0x80000001)  # seq
        lsa_data[16:18] = b"\x00\x00"  # checksum (will be computed)
        struct.pack_into("!H", lsa_data, 18, 20)  # length

        result = fletcher_checksum(bytes(lsa_data))
        assert isinstance(result, int)
        assert 0 < result <= 0xFFFF

    def test_verify_roundtrip(self):
        """Compute checksum, insert it, verify it."""
        lsa_data = bytearray(24)
        lsa_data[0:2] = b"\x00\x05"  # age = 5
        lsa_data[2] = 0x02  # options
        lsa_data[3] = 0x01  # type
        lsa_data[4:8] = b"\x0a\x00\x00\x01"
        lsa_data[8:12] = b"\x0a\x00\x00\x01"
        struct.pack_into("!I", lsa_data, 12, 0x80000001)
        lsa_data[16:18] = b"\x00\x00"
        struct.pack_into("!H", lsa_data, 18, 24)
        # body bytes
        lsa_data[20:24] = b"\x01\x00\x00\x01"

        chk = fletcher_checksum(bytes(lsa_data))
        lsa_data[16] = (chk >> 8) & 0xFF
        lsa_data[17] = chk & 0xFF

        assert verify_fletcher_checksum(bytes(lsa_data))
