"""OSPF daemon lifecycle management.

Handles daemonization, PID file, signal handling,
and the main event loop.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from ospfd.config import OspfConfig
from ospfd.protocol.instance import OspfInstance
from ospfd.util.logging import setup_logging

logger = logging.getLogger(__name__)


class OspfDaemon:
    """OSPF daemon process manager."""

    def __init__(self) -> None:
        self._config: Optional[OspfConfig] = None
        self._instance: Optional[OspfInstance] = None
        self._foreground: bool = False
        self._config_path: str = "/etc/ospfd/ospfd.yaml"
        self._pid_file: Optional[str] = None

    def run(self) -> None:
        """Main entry point for the daemon."""
        self._parse_args()
        self._load_config()
        self._setup_logging()

        if not self._foreground:
            self._daemonize()

        self._write_pid()
        self._run_event_loop()
        self._remove_pid()

    def _parse_args(self) -> None:
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(
            description="OSPF v2 routing daemon (RFC 2328)",
            prog="ospfd",
        )
        parser.add_argument(
            "-c", "--config",
            default="/etc/ospfd/ospfd.yaml",
            help="Path to configuration file (default: /etc/ospfd/ospfd.yaml)",
        )
        parser.add_argument(
            "-f", "--foreground",
            action="store_true",
            help="Run in foreground (don't daemonize)",
        )
        parser.add_argument(
            "-d", "--debug",
            action="store_true",
            help="Enable debug logging",
        )

        args = parser.parse_args()
        self._config_path = args.config
        self._foreground = args.foreground
        if args.debug:
            self._debug = True
        else:
            self._debug = False

    def _load_config(self) -> None:
        """Load and validate the configuration file."""
        try:
            self._config = OspfConfig.from_yaml(self._config_path)
        except FileNotFoundError:
            print(f"Error: Config file not found: {self._config_path}", file=sys.stderr)
            sys.exit(1)
        except (ValueError, Exception) as e:
            print(f"Error: Invalid config: {e}", file=sys.stderr)
            sys.exit(1)

        self._pid_file = self._config.pid_file

    def _setup_logging(self) -> None:
        """Configure logging."""
        level = "debug" if self._debug else self._config.log_level
        log_file = self._config.log_file if not self._foreground else None
        setup_logging(level=level, log_file=log_file, name="ospfd")

    def _daemonize(self) -> None:
        """Fork into the background (classic double-fork)."""
        # First fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Decouple from parent
        os.setsid()
        os.umask(0o022)

        # Second fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Redirect std file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        devnull = open(os.devnull, "r+b")
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        if self._config.log_file:
            # Keep stderr for crash output
            pass
        else:
            os.dup2(devnull.fileno(), sys.stdout.fileno())
            os.dup2(devnull.fileno(), sys.stderr.fileno())

    def _write_pid(self) -> None:
        """Write PID file."""
        if not self._pid_file:
            return
        try:
            pid_path = Path(self._pid_file)
            pid_path.parent.mkdir(parents=True, exist_ok=True)
            pid_path.write_text(str(os.getpid()) + "\n")
            logger.info("PID %d written to %s", os.getpid(), self._pid_file)
        except OSError as e:
            logger.warning("Failed to write PID file %s: %s", self._pid_file, e)

    def _remove_pid(self) -> None:
        """Remove PID file on exit."""
        if not self._pid_file:
            return
        try:
            Path(self._pid_file).unlink(missing_ok=True)
        except OSError:
            pass

    def _run_event_loop(self) -> None:
        """Create and run the asyncio event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        self._instance = OspfInstance(self._config, loop)

        # Signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown, loop)
        loop.add_signal_handler(signal.SIGHUP, self._handle_reload)
        loop.add_signal_handler(signal.SIGUSR1, self._handle_dump)

        try:
            self._instance.init_netlink()
            loop.run_until_complete(self._instance.start())
            logger.info("OSPF daemon running (PID %d)", os.getpid())
            loop.run_forever()
        except Exception as e:
            logger.error("Fatal error: %s", e, exc_info=True)
        finally:
            if self._instance:
                loop.run_until_complete(self._instance.shutdown())
            loop.close()
            logger.info("OSPF daemon stopped")

    def _handle_shutdown(self, loop: asyncio.AbstractEventLoop) -> None:
        """Handle SIGTERM/SIGINT: initiate graceful shutdown."""
        logger.info("Received shutdown signal")
        loop.stop()

    def _handle_reload(self) -> None:
        """Handle SIGHUP: reload configuration."""
        logger.info("SIGHUP received — config reload not yet implemented")
        # TODO: Reload config, re-evaluate interfaces

    def _handle_dump(self) -> None:
        """Handle SIGUSR1: dump LSDB to log."""
        if self._instance is None:
            return
        logger.info("=== LSDB Dump (SIGUSR1) ===")
        lsdb = self._instance.lsdb
        for area_id in lsdb.area_ids:
            logger.info("Area %s:", area_id)
            for lsa in lsdb.get_all(area_id):
                h = lsa.header
                logger.info(
                    "  Type=%d ID=%s Adv=%s Seq=0x%08x Age=%d Len=%d",
                    h.ls_type, h.link_state_id, h.advertising_router,
                    h.ls_sequence_number, lsa.current_age, h.length,
                )
        for lsa in lsdb.get_all_external():
            h = lsa.header
            logger.info(
                "  [External] Type=%d ID=%s Adv=%s Seq=0x%08x Age=%d",
                h.ls_type, h.link_state_id, h.advertising_router,
                h.ls_sequence_number, lsa.current_age,
            )
        logger.info("=== End LSDB Dump ===")
