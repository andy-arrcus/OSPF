# ospfd — RFC 2328 OSPF v2 Routing Daemon

A complete OSPF version 2 routing daemon written in Python, implementing RFC 2328. Runs as a Linux daemon and programs the kernel routing table via Netlink. Tested with Cisco IOS.

## Features

- **Full RFC 2328 implementation**: Hello, DD exchange, flooding, SPF, route calculation
- **All 5 LSA types**: Router, Network, Summary (Network/ASBR), AS External
- **Neighbor FSM**: 8 states, 13 events, master/slave DD negotiation
- **Interface FSM**: Broadcast, point-to-point, NBMA, point-to-multipoint
- **DR/BDR election**: Two-pass algorithm per Section 9.4
- **Dijkstra SPF**: Intra-area, inter-area, and external route calculation with ECMP
- **Kernel route programming**: Via Netlink (pyroute2), tagged as proto 89
- **Multi-area**: ABR support with Summary LSA origination
- **Authentication**: Null, simple password, and MD5
- **systemd integration**: Service file with security hardening (capabilities, ProtectSystem)

## Requirements

- Linux (kernel 3.x+)
- Python 3.9+
- pyroute2
- PyYAML

## Installation

```bash
tar xzf ospfd-0.1.0.tar.gz
cd ospfd-0.1.0
sudo ./install.sh
```

The install script creates a virtualenv at `/opt/ospfd`, installs the wheel and dependencies, symlinks the binary to `/usr/local/sbin/ospfd`, deploys the config and systemd service.

### Build from source

```bash
pip install build
python3 -m build --wheel
# wheel is in dist/
```

## Configuration

Edit `/etc/ospfd/ospfd.yaml`:

```yaml
router_id: 10.0.0.1

log_level: info

timers:
  spf_delay: 1
  spf_hold: 5

areas:
  0.0.0.0:
    interfaces:
      eth0:
        type: broadcast
        cost: 10
        priority: 1
        hello_interval: 10
        dead_interval: 40
```

See `etc/ospfd.yaml` for all options including authentication, multi-area, and redistribution.

## Usage

```bash
# Start the service
sudo systemctl enable --now ospfd

# Check status
sudo systemctl status ospfd

# View logs
journalctl -u ospfd -f

# Dump LSDB to log
sudo kill -USR1 $(pidof ospfd)

# Run in foreground with debug
sudo ospfd -f -d -c /etc/ospfd/ospfd.yaml
```

## Project Structure

```
src/ospfd/
  packet/     Serialization for all OSPF packet and LSA types
  protocol/   Neighbor FSM, interface FSM, DR election, area, instance
  lsdb/       Link state database, flooding, origination, aging
  spf/        Dijkstra, intra/inter/external route calculation, routing table
  io/         Raw sockets (protocol 89), Netlink route programming
  util/       Timers, IP helpers, logging, router ID selection
  daemon.py   Daemonization, PID file, signal handling
  config.py   YAML configuration parsing
  const.py    RFC 2328 constants
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

75 unit tests covering checksums, packet serialization, FSM transitions, DR election, Dijkstra, LSDB operations, config parsing, and routing table logic.

## License

MIT
