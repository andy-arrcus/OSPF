"""OSPF authentication (RFC 2328 Section D).

Supports:
  - Type 0: Null authentication
  - Type 1: Simple password (8-byte cleartext)
  - Type 2: Cryptographic (MD5) authentication
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from ospfd.const import AUTH_MD5, AUTH_NONE, AUTH_SIMPLE


def apply_auth(packet: bytearray, auth_type: int, auth_key: bytes = b"",
               key_id: int = 0, crypt_seq: int = 0) -> bytes:
    """Apply authentication to a serialized OSPF packet.

    The packet must have the auth fields (bytes 16-23) zeroed before checksum
    computation. This function fills in the auth fields after the checksum
    has been computed.

    Args:
        packet: Mutable OSPF packet bytes (header + body).
        auth_type: AUTH_NONE, AUTH_SIMPLE, or AUTH_MD5.
        auth_key: The authentication key.
        key_id: MD5 key ID (0-255).

    Returns:
        The final packet bytes (may be extended with MD5 digest).
    """
    # Set auth_type in header bytes 14-15
    struct.pack_into("!H", packet, 14, auth_type)

    if auth_type == AUTH_NONE:
        # Auth data is all zeros (already zeroed)
        return bytes(packet)

    elif auth_type == AUTH_SIMPLE:
        # Auth data is the 8-byte password, null-padded
        key = auth_key[:8].ljust(8, b"\x00")
        packet[16:24] = key
        return bytes(packet)

    elif auth_type == AUTH_MD5:
        # Cryptographic authentication per Appendix D
        # Auth data layout (bytes 16-23):
        #   0: zero (reserved)
        #   1: key_id
        #   2: auth_data_len (16 for MD5)
        #   3-7: cryptographic sequence number (4 bytes)
        packet[16] = 0
        packet[17] = key_id & 0xFF
        packet[18] = 16  # MD5 digest length
        packet[19] = 0   # padding
        struct.pack_into("!I", packet, 20, crypt_seq)

        # MD5 digest is appended after the packet
        # The checksum field in the header should be 0 for MD5 auth
        # (already handled by caller zeroing checksum)
        key_padded = auth_key[:16].ljust(16, b"\x00")
        md5 = hashlib.md5()
        md5.update(bytes(packet))
        md5.update(key_padded)
        digest = md5.digest()

        return bytes(packet) + digest

    else:
        raise ValueError(f"Unknown auth type: {auth_type}")


def verify_auth(packet: bytes, auth_type: int, auth_key: bytes = b"",
                key_id: int = 0) -> bool:
    """Verify authentication on a received OSPF packet.

    Args:
        packet: The received OSPF packet bytes (may include MD5 appendix).
        auth_type: Expected authentication type.
        auth_key: The authentication key.
        key_id: Expected MD5 key ID.

    Returns:
        True if authentication passes.
    """
    if len(packet) < 24:
        return False

    pkt_auth_type = struct.unpack_from("!H", packet, 14)[0]
    if pkt_auth_type != auth_type:
        return False

    if auth_type == AUTH_NONE:
        return True

    elif auth_type == AUTH_SIMPLE:
        pkt_key = packet[16:24]
        expected = auth_key[:8].ljust(8, b"\x00")
        return hmac.compare_digest(bytes(pkt_key), bytes(expected))

    elif auth_type == AUTH_MD5:
        if len(packet) < 24 + 16:  # need appended digest
            return False
        pkt_key_id = packet[17]
        if pkt_key_id != key_id:
            return False
        auth_data_len = packet[18]
        if auth_data_len != 16:
            return False

        # The OSPF packet length in header tells us where the digest starts
        ospf_len = struct.unpack_from("!H", packet, 2)[0]
        if len(packet) < ospf_len + 16:
            return False

        received_digest = packet[ospf_len : ospf_len + 16]
        key_padded = auth_key[:16].ljust(16, b"\x00")

        md5 = hashlib.md5()
        md5.update(packet[:ospf_len])
        md5.update(key_padded)
        expected_digest = md5.digest()

        return hmac.compare_digest(bytes(received_digest), bytes(expected_digest))

    return False
