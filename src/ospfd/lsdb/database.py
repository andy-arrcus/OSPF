"""OSPF Link State Database per RFC 2328 Section 12.

Stores all LSAs organized by area. Provides lookup, installation,
comparison, and retrieval operations.
"""

from __future__ import annotations

import logging
import time
from ipaddress import IPv4Address
from typing import Optional

from ospfd.const import (
    LSA_TYPE_EXTERNAL,
    MAX_AGE,
    MAX_AGE_DIFF,
    MIN_LS_ARRIVAL,
)
from ospfd.packet.lsa import Lsa, LsaHeader

logger = logging.getLogger(__name__)

# LSA key type: (ls_type, link_state_id, advertising_router)
LsaKey = tuple[int, IPv4Address, IPv4Address]


class LinkStateDatabase:
    """OSPF LSDB storing LSAs per area and AS-wide externals.

    Structure:
      - _areas[area_id][key] = Lsa   (for types 1-4)
      - _external[key] = Lsa          (for type 5)

    LSA comparison per Section 13.1:
      1. Higher sequence number wins.
      2. If equal, higher checksum wins.
      3. If equal, MaxAge wins over non-MaxAge.
      4. If ages differ by > MaxAgeDiff (15 min), younger wins.
    """

    def __init__(self, router_id: IPv4Address):
        self.router_id = router_id
        self._areas: dict[IPv4Address, dict[LsaKey, Lsa]] = {}
        self._external: dict[LsaKey, Lsa] = {}
        self._last_arrival: dict[LsaKey, float] = {}  # for MinLSArrival

    def ensure_area(self, area_id: IPv4Address) -> None:
        """Ensure area partition exists."""
        if area_id not in self._areas:
            self._areas[area_id] = {}

    def lookup(self, area_id: IPv4Address, key: LsaKey) -> Optional[Lsa]:
        """Look up an LSA by key in the specified area (or external DB)."""
        ls_type = key[0]
        if ls_type == LSA_TYPE_EXTERNAL:
            return self._external.get(key)
        area_db = self._areas.get(area_id, {})
        return area_db.get(key)

    def install(self, area_id: IPv4Address, lsa: Lsa) -> tuple[bool, Optional[Lsa]]:
        """Install an LSA into the database.

        Returns (is_new_or_newer, old_lsa).
        - is_new_or_newer: True if this LSA was installed (new or more recent).
        - old_lsa: The previous LSA instance if replaced, None if new.

        Respects MinLSArrival: rejects LSAs arriving too quickly.
        """
        key = lsa.key
        now = time.monotonic()

        # Get the right database partition
        if lsa.header.ls_type == LSA_TYPE_EXTERNAL:
            db = self._external
        else:
            self.ensure_area(area_id)
            db = self._areas[area_id]

        old = db.get(key)

        if old is not None:
            cmp = self.compare_lsa(lsa.header, old.header)
            if cmp <= 0:
                # Old is same or newer
                return False, old
            # MinLSArrival: reject rapid updates for same LSA
            last = self._last_arrival.get(key, 0.0)
            if now - last < MIN_LS_ARRIVAL:
                return False, old

        # Install
        lsa.mark_installed()
        db[key] = lsa
        self._last_arrival[key] = now

        logger.debug(
            "LSDB install: type=%d id=%s adv=%s seq=0x%08x age=%d",
            lsa.header.ls_type, lsa.header.link_state_id,
            lsa.header.advertising_router, lsa.header.ls_sequence_number,
            lsa.header.ls_age,
        )

        return True, old

    def remove(self, area_id: IPv4Address, key: LsaKey) -> Optional[Lsa]:
        """Remove an LSA from the database."""
        if key[0] == LSA_TYPE_EXTERNAL:
            return self._external.pop(key, None)
        area_db = self._areas.get(area_id)
        if area_db:
            return area_db.pop(key, None)
        return None

    def get_all(self, area_id: IPv4Address, ls_type: Optional[int] = None) -> list[Lsa]:
        """Get all LSAs in an area, optionally filtered by type."""
        area_db = self._areas.get(area_id, {})
        lsas = list(area_db.values())
        if ls_type is not None:
            lsas = [l for l in lsas if l.header.ls_type == ls_type]
        return lsas

    def get_all_external(self) -> list[Lsa]:
        """Get all AS External LSAs."""
        return list(self._external.values())

    def get_all_headers(self, area_id: IPv4Address) -> list[LsaHeader]:
        """Get all LSA headers for an area (for DD exchange).

        Includes both area-scoped LSAs and external LSAs.
        """
        headers = []
        area_db = self._areas.get(area_id, {})
        for lsa in area_db.values():
            headers.append(lsa.header)
        for lsa in self._external.values():
            headers.append(lsa.header)
        return headers

    def get_maxage_lsas(self, area_id: IPv4Address) -> list[Lsa]:
        """Get all MaxAge LSAs in an area."""
        result = []
        area_db = self._areas.get(area_id, {})
        for lsa in area_db.values():
            if lsa.current_age >= MAX_AGE:
                result.append(lsa)
        return result

    def is_self_originated(self, lsa: Lsa) -> bool:
        """Check if an LSA was originated by this router."""
        return lsa.header.advertising_router == self.router_id

    def compare_lsa(self, a: LsaHeader, b: LsaHeader) -> int:
        """Compare two LSA instances per Section 13.1.

        Returns:
            > 0 if a is more recent
            < 0 if b is more recent
            0 if they are considered the same instance
        """
        # 1. Higher sequence number wins (stored unsigned, compared signed)
        if a.ls_sequence_number != b.ls_sequence_number:
            # Convert to signed 32-bit for comparison
            a_signed = a.ls_sequence_number if a.ls_sequence_number < 0x80000000 else a.ls_sequence_number - 0x100000000
            b_signed = b.ls_sequence_number if b.ls_sequence_number < 0x80000000 else b.ls_sequence_number - 0x100000000
            return 1 if a_signed > b_signed else -1

        # 2. Higher checksum wins
        if a.ls_checksum != b.ls_checksum:
            return a.ls_checksum - b.ls_checksum

        # 3. MaxAge wins
        a_maxage = a.ls_age >= MAX_AGE
        b_maxage = b.ls_age >= MAX_AGE
        if a_maxage and not b_maxage:
            return 1
        if b_maxage and not a_maxage:
            return -1

        # 4. If ages differ by > MaxAgeDiff, younger wins
        age_diff = abs(a.ls_age - b.ls_age)
        if age_diff > MAX_AGE_DIFF:
            if a.ls_age < b.ls_age:
                return 1  # a is younger
            else:
                return -1  # b is younger

        # Same instance
        return 0

    @property
    def area_ids(self) -> list[IPv4Address]:
        """Return all area IDs in the LSDB."""
        return list(self._areas.keys())
