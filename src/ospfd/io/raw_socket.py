"""Raw IP socket for OSPF protocol 89.

Manages per-interface raw sockets with multicast group membership,
integrated with the asyncio event loop via loop.add_reader().
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Callable, Optional

from ospfd.const import ALL_D_ROUTERS, ALL_SPF_ROUTERS, IP_TOS_OSPF, OSPF_IP_PROTOCOL

logger = logging.getLogger(__name__)


class OspfSocket:
    """Raw OSPF socket bound to a single interface.

    Creates a raw IP socket for protocol 89, bound to a specific interface
    via SO_BINDTODEVICE. Handles multicast group join/leave and integrates
    with asyncio for non-blocking receive.
    """

    def __init__(
        self,
        interface_name: str,
        interface_addr: str,
        mtu: int = 1500,
    ):
        self._interface_name = interface_name
        self._interface_addr = interface_addr
        self._mtu = mtu
        self._multicast_groups: set[str] = set()
        self._callback: Optional[Callable] = None

        self._sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, OSPF_IP_PROTOCOL
        )
        # Set IP options
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, IP_TOS_OSPF)

        # Bind to specific interface
        self._sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface_name.encode() + b"\x00",
        )

        # Set outgoing multicast interface
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_addr),
        )

        # Don't receive our own multicast
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        self._sock.setblocking(False)

        logger.info("Created OSPF socket on %s (%s)", interface_name, interface_addr)

    def join_allspf(self) -> None:
        """Join the AllSPFRouters multicast group (224.0.0.5)."""
        self._join_multicast(ALL_SPF_ROUTERS)

    def join_alld(self) -> None:
        """Join the AllDRouters multicast group (224.0.0.6)."""
        self._join_multicast(ALL_D_ROUTERS)

    def leave_alld(self) -> None:
        """Leave the AllDRouters multicast group (224.0.0.6)."""
        self._leave_multicast(ALL_D_ROUTERS)

    def _join_multicast(self, group: str) -> None:
        if group in self._multicast_groups:
            return
        mreq = struct.pack(
            "4s4s",
            socket.inet_aton(group),
            socket.inet_aton(self._interface_addr),
        )
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self._multicast_groups.add(group)
        logger.debug("Joined multicast %s on %s", group, self._interface_name)

    def _leave_multicast(self, group: str) -> None:
        if group not in self._multicast_groups:
            return
        mreq = struct.pack(
            "4s4s",
            socket.inet_aton(group),
            socket.inet_aton(self._interface_addr),
        )
        try:
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except OSError:
            pass
        self._multicast_groups.discard(group)

    def register_reader(self, callback: Callable[[], None]) -> None:
        """Register a callback with the asyncio event loop for read events."""
        self._callback = callback
        asyncio.get_running_loop().add_reader(self._sock.fileno(), callback)

    def send(self, data: bytes, dest: str) -> None:
        """Send an OSPF packet to a destination address (unicast or multicast)."""
        try:
            self._sock.sendto(data, (dest, 0))
        except OSError as e:
            logger.error("Send failed on %s to %s: %s", self._interface_name, dest, e)

    def recv(self) -> tuple[bytes, str]:
        """Receive a raw IP packet. Strips IP header, returns (ospf_payload, src_addr).

        Raises BlockingIOError if no data available (non-blocking socket).
        """
        data, (addr, _) = self._sock.recvfrom(self._mtu + 64)
        # IP header length is in the IHL field (lower 4 bits of first byte)
        ip_hdr_len = (data[0] & 0x0F) * 4
        return data[ip_hdr_len:], addr

    def close(self) -> None:
        """Clean up: remove reader, leave multicast groups, close socket."""
        if self._callback is not None:
            try:
                asyncio.get_running_loop().remove_reader(self._sock.fileno())
            except Exception:
                pass
        for group in list(self._multicast_groups):
            self._leave_multicast(group)
        try:
            self._sock.close()
        except OSError:
            pass
        logger.info("Closed OSPF socket on %s", self._interface_name)

    @property
    def fileno(self) -> int:
        return self._sock.fileno()
