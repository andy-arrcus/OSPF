"""Entry point for `python -m ospfd`."""

from ospfd.daemon import OspfDaemon


def main() -> None:
    """Run the OSPF daemon."""
    daemon = OspfDaemon()
    daemon.run()


if __name__ == "__main__":
    main()
