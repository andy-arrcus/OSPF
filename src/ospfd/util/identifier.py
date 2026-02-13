"""Router ID selection logic per RFC 2328 Section C.1."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import Optional

logger = logging.getLogger(__name__)


def select_router_id(
    configured_id: Optional[IPv4Address],
    interfaces: list[dict],
) -> IPv4Address:
    """Select the OSPF router ID.

    Priority:
    1. Explicitly configured router ID.
    2. Highest IPv4 address on any loopback interface.
    3. Highest IPv4 address on any active interface.

    Args:
        configured_id: Explicitly configured router ID (from config file).
        interfaces: List of dicts with 'name' and 'addresses' keys.
                   addresses is a list of (IPv4Address, prefix_len) tuples.

    Returns:
        The selected router ID.

    Raises:
        RuntimeError: If no usable router ID can be determined.
    """
    if configured_id and configured_id != IPv4Address("0.0.0.0"):
        logger.info("Using configured router ID: %s", configured_id)
        return configured_id

    # Collect all addresses, preferring loopback
    loopback_addrs: list[IPv4Address] = []
    other_addrs: list[IPv4Address] = []

    for intf in interfaces:
        name = intf.get("name", "")
        addrs = intf.get("addresses", [])
        for addr, _ in addrs:
            if addr == IPv4Address("127.0.0.1"):
                continue
            if name.startswith("lo"):
                loopback_addrs.append(addr)
            else:
                other_addrs.append(addr)

    if loopback_addrs:
        rid = max(loopback_addrs)
        logger.info("Selected router ID from loopback: %s", rid)
        return rid

    if other_addrs:
        rid = max(other_addrs)
        logger.info("Selected router ID from interface: %s", rid)
        return rid

    raise RuntimeError("Cannot determine OSPF router ID: no usable IPv4 addresses found")
