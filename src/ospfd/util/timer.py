"""Asyncio timer abstractions for OSPF protocol timers.

PeriodicTimer: Repeating timer (Hello, delayed ACK flush, LSA age scan).
OneShotTimer: Single-fire restartable timer (inactivity, wait, rxmt).
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class PeriodicTimer:
    """Repeating timer using asyncio.call_later.

    Fires `callback` every `interval` seconds. Optional jitter adds
    random 0-jitter fraction to each interval to prevent synchronization.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        interval: float,
        callback: Callable[[], None],
        jitter: float = 0.0,
        name: str = "",
    ):
        self._loop = loop
        self._interval = interval
        self._callback = callback
        self._jitter = jitter
        self._name = name
        self._handle: Optional[asyncio.TimerHandle] = None
        self._running = False

    def start(self) -> None:
        """Start the periodic timer."""
        if self._running:
            return
        self._running = True
        self._schedule()

    def stop(self) -> None:
        """Stop the periodic timer."""
        self._running = False
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None

    def reset(self) -> None:
        """Restart the timer from now."""
        self.stop()
        self.start()

    def _schedule(self) -> None:
        if not self._running:
            return
        delay = self._interval
        if self._jitter > 0:
            delay += random.uniform(0, self._interval * self._jitter)
        self._handle = self._loop.call_later(delay, self._fire)

    def _fire(self) -> None:
        if not self._running:
            return
        try:
            self._callback()
        except Exception:
            logger.exception("PeriodicTimer %s callback error", self._name)
        self._schedule()

    @property
    def running(self) -> bool:
        return self._running


class OneShotTimer:
    """Single-fire timer that can be restarted.

    Used for inactivity timers (reset on each Hello received),
    wait timers, and retransmission timers.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        timeout: float,
        callback: Callable[[], None],
        name: str = "",
    ):
        self._loop = loop
        self._timeout = timeout
        self._callback = callback
        self._name = name
        self._handle: Optional[asyncio.TimerHandle] = None

    def start(self) -> None:
        """Start (or restart) the timer."""
        self.cancel()
        self._handle = self._loop.call_later(self._timeout, self._fire)

    def cancel(self) -> None:
        """Cancel the timer if running."""
        if self._handle is not None:
            self._handle.cancel()
            self._handle = None

    def reset(self) -> None:
        """Restart the timer from now (alias for start)."""
        self.start()

    def _fire(self) -> None:
        self._handle = None
        try:
            self._callback()
        except Exception:
            logger.exception("OneShotTimer %s callback error", self._name)

    @property
    def is_running(self) -> bool:
        return self._handle is not None
