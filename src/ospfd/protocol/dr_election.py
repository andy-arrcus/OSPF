"""DR/BDR election algorithm per RFC 2328 Section 9.4.

The election is run on broadcast and NBMA networks when:
  - The WaitTimer fires
  - A neighbor in state >= 2-Way changes its DR/BDR claim
  - A neighbor transitions to/from state >= 2-Way
  - The interface receives BackupSeen event

The algorithm runs in two passes to ensure stability when
this router's own role changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ospfd.protocol.interface import OspfInterface

logger = logging.getLogger(__name__)

ZERO_ADDR = IPv4Address("0.0.0.0")


@dataclass
class _Candidate:
    """A candidate for DR/BDR election."""
    router_id: IPv4Address
    ip_addr: IPv4Address
    priority: int
    declared_dr: IPv4Address
    declared_bdr: IPv4Address


def elect_dr_bdr(interface: OspfInterface) -> tuple[IPv4Address, IPv4Address]:
    """Run the DR/BDR election algorithm per Section 9.4.

    Returns (new_dr, new_bdr) as IP addresses of the interface
    (not router IDs). The caller must translate to router IDs
    and update the interface state accordingly.
    """
    from ospfd.const import NBR_STATE_2WAY

    # Build candidate list: self + all neighbors in state >= 2-Way with priority > 0
    candidates: list[_Candidate] = []

    # Add self
    if interface.priority > 0:
        candidates.append(_Candidate(
            router_id=interface.instance.router_id,
            ip_addr=interface.ip_addr,
            priority=interface.priority,
            declared_dr=interface.dr,
            declared_bdr=interface.bdr,
        ))

    # Add eligible neighbors
    for nbr in interface.neighbors.values():
        if nbr.state >= NBR_STATE_2WAY and nbr.priority > 0:
            candidates.append(_Candidate(
                router_id=nbr.router_id,
                ip_addr=nbr.ip_addr,
                priority=nbr.priority,
                declared_dr=nbr.dr,
                declared_bdr=nbr.bdr,
            ))

    if not candidates:
        return ZERO_ADDR, ZERO_ADDR

    # Save our old role
    old_dr = interface.dr
    old_bdr = interface.bdr
    my_addr = interface.ip_addr

    # Run election (potentially twice per Section 9.4)
    new_dr, new_bdr = _run_election(candidates)

    # Check if our role changed — if so, run again for stability
    was_dr = (old_dr == my_addr)
    was_bdr = (old_bdr == my_addr)
    is_dr = (new_dr == my_addr)
    is_bdr = (new_bdr == my_addr)

    if (was_dr != is_dr) or (was_bdr != is_bdr):
        # Update our own declaration for the second pass
        for c in candidates:
            if c.ip_addr == my_addr:
                c.declared_dr = new_dr
                c.declared_bdr = new_bdr
                break
        new_dr, new_bdr = _run_election(candidates)

    logger.debug(
        "DR election on %s: DR=%s BDR=%s",
        interface.name, new_dr, new_bdr,
    )
    return new_dr, new_bdr


def _run_election(candidates: list[_Candidate]) -> tuple[IPv4Address, IPv4Address]:
    """Single pass of the DR/BDR election.

    Step 1: Elect BDR
      - Consider candidates NOT declaring themselves DR.
      - Among those declaring themselves BDR, pick highest priority (tie: highest RID).
      - If none declare BDR, pick highest priority among non-DR-declarers.

    Step 2: Elect DR
      - Among candidates declaring themselves DR, pick highest priority (tie: highest RID).
      - If none declare DR, promote BDR.
    """
    # ── Step 1: Elect BDR ──
    # Candidates not declaring themselves as DR
    non_dr_declarers = [c for c in candidates if c.declared_dr != c.ip_addr]

    # Among non-DR-declarers, those declaring themselves BDR
    bdr_declarers = [c for c in non_dr_declarers if c.declared_bdr == c.ip_addr]

    if bdr_declarers:
        new_bdr_candidate = max(bdr_declarers, key=lambda c: (c.priority, c.router_id))
    elif non_dr_declarers:
        new_bdr_candidate = max(non_dr_declarers, key=lambda c: (c.priority, c.router_id))
    else:
        new_bdr_candidate = None

    new_bdr = new_bdr_candidate.ip_addr if new_bdr_candidate else ZERO_ADDR

    # ── Step 2: Elect DR ──
    dr_declarers = [c for c in candidates if c.declared_dr == c.ip_addr]

    if dr_declarers:
        new_dr_candidate = max(dr_declarers, key=lambda c: (c.priority, c.router_id))
        new_dr = new_dr_candidate.ip_addr
    else:
        # Promote BDR to DR
        new_dr = new_bdr
        # BDR becomes whoever would be BDR if current BDR is now DR
        # In practice, the second pass handles this
        if new_bdr_candidate:
            remaining = [c for c in non_dr_declarers if c.ip_addr != new_bdr]
            bdr_remaining = [c for c in remaining if c.declared_bdr == c.ip_addr]
            if bdr_remaining:
                alt = max(bdr_remaining, key=lambda c: (c.priority, c.router_id))
                new_bdr = alt.ip_addr
            elif remaining:
                alt = max(remaining, key=lambda c: (c.priority, c.router_id))
                new_bdr = alt.ip_addr
            else:
                new_bdr = ZERO_ADDR

    return new_dr, new_bdr
