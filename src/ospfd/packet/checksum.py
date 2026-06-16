"""OSPF checksum algorithms.

IP checksum (RFC 1071) for OSPF packet header.
Fletcher checksum (RFC 905 Annex B) for LSA checksums per RFC 2328 Section 12.1.7.
"""

from __future__ import annotations

import struct


def ip_checksum(data: bytes) -> int:
    """Compute the standard IP ones-complement checksum.

    The checksum field within the data should be zeroed before calling.
    Used for the OSPF packet header checksum (auth_data bytes 16-23
    are included in the checksum when auth_type is 0).
    """
    if len(data) % 2:
        data = data + b"\x00"
    total = sum(v for (v,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def verify_ip_checksum(data: bytes) -> bool:
    """Verify IP checksum. Returns True if valid (result should be 0)."""
    if len(data) % 2:
        data = data + b"\x00"
    total = sum(v for (v,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def fletcher_checksum(data: bytes, checksum_offset: int = 16) -> int:
    """Compute the Fletcher checksum for an LSA per RFC 2328 Section 12.1.7.

    The LS age field (first 2 bytes of the LSA) is excluded from the computation.
    The checksum bytes at `checksum_offset` (relative to start of LSA) are
    treated as zero during computation.

    Args:
        data: The complete LSA bytes (starting from LS age).
        checksum_offset: Byte offset of the 2-byte checksum field within the LSA.
                        Default is 16 (standard LSA header position).

    Returns:
        The 16-bit Fletcher checksum value.
    """
    # Work on a mutable copy, zero out the checksum field
    buf = bytearray(data)
    buf[checksum_offset] = 0
    buf[checksum_offset + 1] = 0

    c0 = 0
    c1 = 0
    # Skip the first 2 bytes (LS age)
    for i in range(2, len(buf)):
        c0 = (c0 + buf[i]) % 255
        c1 = (c1 + c0) % 255

    # Compute the checksum bytes
    length = len(buf)
    # Position of checksum within the checksummed portion (offset from byte 2)
    pos = checksum_offset - 2  # because we skip first 2 bytes

    x = ((length - 2 - pos - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255

    return (x << 8) | y


def verify_fletcher_checksum(data: bytes) -> bool:
    """Verify Fletcher checksum of an LSA. Returns True if valid.

    A valid LSA will have c0 == 0 and c1 == 0 after summing all
    bytes (excluding LS age).
    """
    c0 = 0
    c1 = 0
    for i in range(2, len(data)):
        c0 = (c0 + data[i]) % 255
        c1 = (c1 + c0) % 255
    return c0 == 0 and c1 == 0
