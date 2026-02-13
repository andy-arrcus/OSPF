"""IP address and network utility functions."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network


def mask_to_prefix_len(mask: IPv4Address) -> int:
    """Convert a subnet mask to a prefix length.

    Example: IPv4Address('255.255.255.0') -> 24
    """
    mask_int = int(mask)
    if mask_int == 0:
        return 0
    # Count leading 1-bits
    length = 0
    bit = 1 << 31
    while bit and (mask_int & bit):
        length += 1
        bit >>= 1
    return length


def prefix_len_to_mask(prefix_len: int) -> IPv4Address:
    """Convert a prefix length to a subnet mask.

    Example: 24 -> IPv4Address('255.255.255.0')
    """
    if prefix_len == 0:
        return IPv4Address("0.0.0.0")
    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return IPv4Address(mask_int)


def network_address(addr: IPv4Address, mask: IPv4Address) -> IPv4Address:
    """Compute the network address from an IP and mask.

    Example: (10.0.1.5, 255.255.255.0) -> 10.0.1.0
    """
    return IPv4Address(int(addr) & int(mask))


def ip_in_network(addr: IPv4Address, net_addr: IPv4Address, mask: IPv4Address) -> bool:
    """Check if an IP address belongs to a network."""
    return (int(addr) & int(mask)) == (int(net_addr) & int(mask))


def ip_to_network(addr: IPv4Address, mask: IPv4Address) -> IPv4Network:
    """Create an IPv4Network from address and mask."""
    prefix_len = mask_to_prefix_len(mask)
    net_addr = network_address(addr, mask)
    return IPv4Network(f"{net_addr}/{prefix_len}")
