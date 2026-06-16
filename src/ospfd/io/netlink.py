"""Netlink integration for interface discovery and route programming.

Uses pyroute2 to interact with the Linux kernel via rtnetlink.
All OSPF-installed routes are tagged with proto=89 (RTPROT_OSPF)
for identification and clean removal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Optional

from ospfd.const import RTPROT_OSPF

logger = logging.getLogger(__name__)


@dataclass
class InterfaceInfo:
    """Discovered network interface information."""

    name: str
    index: int
    mtu: int
    addresses: list[tuple[IPv4Address, int]]  # (address, prefix_length)
    state: str  # 'up' or 'down'
    mac: str = ""


@dataclass
class Nexthop:
    """A single nexthop for a route."""

    gateway: IPv4Address
    interface_index: int
    interface_name: str = ""


class NetlinkManager:
    """Manages Linux routing table and interface discovery via Netlink.

    Uses pyroute2.IPRoute for:
    1. Interface discovery (name, index, addresses, MTU, state)
    2. Installing/removing OSPF routes in the kernel FIB
    3. Monitoring interface state changes

    All OSPF routes use proto=RTPROT_OSPF (89) so they can be
    identified and cleaned up independently of other routes.
    """

    def __init__(self) -> None:
        # Import here so the rest of the code can be tested without pyroute2
        from pyroute2 import IPRoute

        self._ipr = IPRoute()
        logger.info("Netlink manager initialized")

    def discover_interfaces(self) -> list[InterfaceInfo]:
        """Discover all network interfaces with IPv4 addresses.

        Returns a list of InterfaceInfo for each interface that is UP
        and has at least one IPv4 address.
        """
        interfaces = []
        links = self._ipr.get_links()
        addrs = self._ipr.get_addr(family=2)  # AF_INET = 2

        # Build index -> addresses mapping
        addr_map: dict[int, list[tuple[IPv4Address, int]]] = {}
        for a in addrs:
            idx = a["index"]
            addr_val = a.get_attr("IFA_ADDRESS")
            if addr_val is not None:
                addr_map.setdefault(idx, []).append(
                    (IPv4Address(addr_val), a["prefixlen"])
                )

        for link in links:
            idx = link["index"]
            name = link.get_attr("IFLA_IFNAME") or ""
            mac = link.get_attr("IFLA_ADDRESS") or ""
            mtu = link.get_attr("IFLA_MTU") or 1500
            operstate = link.get_attr("IFLA_OPERSTATE")
            state = operstate.lower() if isinstance(operstate, str) else "down"

            if state != "up" or idx not in addr_map:
                continue

            interfaces.append(InterfaceInfo(
                name=name,
                index=idx,
                mtu=mtu,
                addresses=addr_map[idx],
                state=state,
                mac=mac,
            ))

        logger.info("Discovered %d OSPF-eligible interfaces", len(interfaces))
        return interfaces

    def get_interface_index(self, name: str) -> Optional[int]:
        """Get the kernel interface index for a given interface name."""
        try:
            links = self._ipr.link_lookup(ifname=name)
            return links[0] if links else None
        except Exception:
            return None

    def install_route(
        self,
        destination: IPv4Network,
        nexthops: list[Nexthop],
        metric: int = 0,
    ) -> None:
        """Install an OSPF route into the kernel routing table.

        Uses 'replace' semantics for idempotent updates.
        Supports ECMP with multiple nexthops.

        Args:
            destination: The destination network (e.g., 10.1.0.0/24).
            nexthops: List of nexthops (gateway + interface).
            metric: Route metric/priority (0 = kernel default).
        """
        dst_str = str(destination)
        try:
            if len(nexthops) == 1:
                kwargs = {
                    "dst": dst_str,
                    "gateway": str(nexthops[0].gateway),
                    "oif": nexthops[0].interface_index,
                    "proto": RTPROT_OSPF,
                }
                if metric:
                    kwargs["priority"] = metric
                self._ipr.route("replace", **kwargs)
            else:
                # ECMP multipath
                mp = [
                    {"gateway": str(nh.gateway), "oif": nh.interface_index}
                    for nh in nexthops
                ]
                kwargs = {
                    "dst": dst_str,
                    "multipath": mp,
                    "proto": RTPROT_OSPF,
                }
                if metric:
                    kwargs["priority"] = metric
                self._ipr.route("replace", **kwargs)

            logger.debug("Installed route %s via %s", dst_str,
                        ", ".join(str(nh.gateway) for nh in nexthops))
        except Exception as e:
            logger.error("Failed to install route %s: %s", dst_str, e)

    def remove_route(self, destination: IPv4Network) -> None:
        """Remove an OSPF route from the kernel routing table."""
        try:
            self._ipr.route("del", dst=str(destination), proto=RTPROT_OSPF)
            logger.debug("Removed route %s", destination)
        except Exception as e:
            logger.warning("Failed to remove route %s: %s", destination, e)

    def flush_ospf_routes(self) -> None:
        """Remove all OSPF-installed routes. Called on daemon shutdown."""
        try:
            routes = self._ipr.get_routes(proto=RTPROT_OSPF)
            count = 0
            for route in routes:
                try:
                    dst = route.get_attr("RTA_DST")
                    if dst:
                        prefix_len = route.get("dst_len", 32)
                        self._ipr.route(
                            "del",
                            dst=f"{dst}/{prefix_len}",
                            proto=RTPROT_OSPF,
                        )
                        count += 1
                except Exception:
                    pass
            logger.info("Flushed %d OSPF routes", count)
        except Exception as e:
            logger.error("Failed to flush OSPF routes: %s", e)

    def install_sr_routes(self, sr_routes) -> None:
        """Install SR/MPLS routes via Netlink."""
        from ospfd.const import MPLS_LABEL_IMPLICIT_NULL
        for route in sr_routes:
            try:
                if route.outgoing_label == MPLS_LABEL_IMPLICIT_NULL:
                    # PHP: forward without label (plain IP)
                    self._ipr.route(
                        "replace",
                        dst=str(route.destination),
                        gateway=str(route.nexthop_ip),
                        proto=88,  # proto=88 for SR routes
                    )
                else:
                    # Push label
                    self._ipr.route(
                        "replace",
                        dst=str(route.destination),
                        gateway=str(route.nexthop_ip),
                        encap={"type": "mpls", "labels": route.outgoing_label},
                        proto=88,
                    )
            except Exception as e:
                logger.debug("Failed to install SR route %s: %s", route.destination, e)

    def close(self) -> None:
        """Close the Netlink socket."""
        try:
            self._ipr.close()
        except Exception:
            pass
        logger.info("Netlink manager closed")
