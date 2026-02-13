"""LSA age management per RFC 2328 Section 14.

Handles:
  - Periodic age checking
  - MaxAge LSA detection and flushing
  - LSA refresh scheduling
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ospfd.const import LS_REFRESH_TIME, MAX_AGE

if TYPE_CHECKING:
    from ospfd.protocol.instance import OspfInstance

logger = logging.getLogger(__name__)

AGE_CHECK_INTERVAL = 60  # Check every 60 seconds


class LsaAgingManager:
    """Manages LSA aging and MaxAge processing.

    LSA ages are not actively incremented; instead, each LSA records
    its age at installation time and the installation timestamp.
    The current age is computed on demand as:
        current_age = min(installed_age + elapsed, MAX_AGE)

    This class periodically scans for:
    1. LSAs reaching MaxAge -> initiate flushing
    2. Self-originated LSAs nearing LS_REFRESH_TIME -> re-originate
    """

    def __init__(self, instance: OspfInstance):
        self._instance = instance
        from ospfd.util.timer import PeriodicTimer
        self._timer = PeriodicTimer(
            instance.loop, AGE_CHECK_INTERVAL, self._check_ages,
            name="lsa-aging",
        )

    def start(self) -> None:
        """Start the periodic age check timer."""
        self._timer.start()

    def stop(self) -> None:
        """Stop the age check timer."""
        self._timer.stop()

    def _check_ages(self) -> None:
        """Periodic check for MaxAge and refresh-needed LSAs."""
        instance = self._instance
        lsdb = instance.lsdb

        for area_id in lsdb.area_ids:
            # Check for MaxAge LSAs
            maxage_lsas = lsdb.get_maxage_lsas(area_id)
            for lsa in maxage_lsas:
                if lsdb.is_self_originated(lsa):
                    # Re-originate before it expires
                    logger.info("Refreshing MaxAge self-originated LSA: %s", lsa.key)
                    instance.originator.refresh_lsa(area_id, lsa)
                else:
                    # Flush foreign MaxAge LSA
                    self._flush_maxage_lsa(lsa, area_id)

            # Check for LSAs needing refresh (self-originated, age approaching refresh time)
            for lsa in lsdb.get_all(area_id):
                if not lsdb.is_self_originated(lsa):
                    continue
                age = lsa.current_age
                if age >= LS_REFRESH_TIME and age < MAX_AGE:
                    logger.debug("LSA refresh needed: %s (age=%d)", lsa.key, age)
                    instance.originator.refresh_lsa(area_id, lsa)

    def _flush_maxage_lsa(self, lsa, area_id) -> None:
        """Flush a MaxAge LSA: flood and remove when acked by all neighbors."""
        instance = self._instance
        lsdb = instance.lsdb

        # Flood with MaxAge
        instance.flooding.flood_lsa(lsa, area_id, None, None)

        # Check if all adjacent neighbors have acknowledged
        area = instance.areas.get(area_id)
        if area is None:
            lsdb.remove(area_id, lsa.key)
            return

        all_acked = True
        for intf in area.interfaces:
            for nbr in intf.adjacent_neighbors:
                if any(l.key == lsa.key for l in nbr.ls_retransmission_list):
                    all_acked = False
                    break
            if not all_acked:
                break

        if all_acked:
            lsdb.remove(area_id, lsa.key)
            logger.debug("Flushed MaxAge LSA: %s", lsa.key)
