# ospfd — RFC 2328 OSPF v2 Routing Daemon

A complete OSPF version 2 routing daemon written in Python, implementing RFC 2328 with Segment Routing extensions (RFC 8665). Runs as a Linux daemon and programs the kernel routing table via Netlink. Tested with Cisco IOS achieving full adjacency (FULL state).

## Features

- **Full RFC 2328 implementation**: Hello, DD exchange, flooding, SPF, route calculation
- **All 5 standard LSA types**: Router, Network, Summary (Network/ASBR), AS External
- **Segment Routing (RFC 8665)**: Opaque LSA types 9–11, RI LSA, Extended Prefix/Link LSAs, SRGB advertisement, Prefix-SID, Adj-SID, MPLS label stack programming
- **Neighbor FSM**: 8 states, 13 events, master/slave DD negotiation
- **Interface FSM**: Broadcast, point-to-point, NBMA, point-to-multipoint
- **DR/BDR election**: Two-pass algorithm per Section 9.4
- **Dijkstra SPF**: Intra-area, inter-area, and external route calculation with ECMP
- **Kernel route programming**: IP routes and MPLS encap routes via Netlink (pyroute2), proto 89
- **Multi-area**: ABR support with Summary LSA origination
- **Authentication**: Null, simple password, and MD5 (HMAC with monotonic crypto sequence)
- **Security hardening**: Bounded LSDB/neighbor sizes, constant-time auth comparison, on-link source validation, atomic PID file, O_CLOEXEC everywhere
- **systemd integration**: Service file with capability restriction and filesystem protection

## Requirements

- Linux (kernel 3.x+, MPLS enabled for SR)
- Python 3.9+
- pyroute2 >= 0.7
- PyYAML >= 6.0

## Installation

```bash
tar xzf ospfd-0.1.0.tar.gz
cd ospfd-0.1.0
sudo ./install.sh
```

The install script creates a virtualenv at `/opt/ospfd`, installs the wheel and dependencies, symlinks the binary to `/usr/local/sbin/ospfd`, deploys the config and systemd service file.

### Build from source

```bash
pip install build
python3 -m build --wheel
sudo ./install.sh
```

## Quick start

```bash
# Enable and start
sudo systemctl enable --now ospfd

# Follow logs
journalctl -u ospfd -f

# Run in foreground with debug logging
sudo ospfd -f -d -c /etc/ospfd/ospfd.yaml

# Dump LSDB to log at runtime
sudo kill -USR1 $(pidof ospfd)
```

## Configuration

Minimal `ospfd.yaml`:

```yaml
router_id: 10.0.0.1

areas:
  0.0.0.0:
    interfaces:
      eth0:
        cost: 10
```

With Segment Routing:

```yaml
router_id: 10.0.0.1

sr:
  enabled: true
  srgb_start: 16000    # label block start
  srgb_size: 8000      # block size
  node_sid_index: 100  # this router's Node-SID (label = 16100 at peers)

areas:
  0.0.0.0:
    interfaces:
      eth0:
        cost: 10
        auth:
          type: md5
          md5:
            key_id: 1
            key: "strongkey"
```

See [docs/configuration.md](docs/configuration.md) for the full reference.

## Segment Routing

ospfd implements RFC 8665 as an optional subsystem. When enabled it:

1. Floods a **Router Information LSA** (opaque type 4) advertising the SRGB
2. Floods an **Extended Prefix LSA** (opaque type 7) advertising this router's Node-SID
3. Receives and parses peer RI/Extended-Prefix/Extended-Link LSAs
4. After each SPF run, computes MPLS label stacks and programs them into the kernel

Label computation: `outgoing_label = nexthop_srgb.start + sid_index`. PHP (implicit-null) is applied when the destination is one hop away and the No-PHP flag is not set.

See [docs/segment-routing.md](docs/segment-routing.md) for full details.

## Project structure

```
src/ospfd/
  packet/       Serialization for all OSPF packet and LSA types
  protocol/     Neighbor FSM, interface FSM, DR election, area, instance
  lsdb/         Link-state database, flooding, origination, aging
  spf/          Dijkstra, intra/inter/external route calculation, routing table
  io/           Raw sockets (protocol 89), Netlink route programming
  sr/           Segment Routing subsystem (RFC 8665)
  util/         Timers, IP helpers, logging, router ID selection
  daemon.py     Daemonization, PID file, signal handling
  config.py     YAML configuration parsing
  const.py      Protocol constants (RFC 2328 + RFC 8665)
etc/
  ospfd.yaml    Reference configuration
  ospfd.service systemd unit file
install.sh      venv-based installer (Ubuntu 24.04+)
tests/unit/     108 unit tests
docs/           Architecture, configuration, SR, and operations guides
```

## Testing

```bash
pip install -e ".[dev]"
pytest                              # 108 tests
pytest --cov=ospfd --cov-report=term-missing
ruff check src/ tests/
```

Tests cover: checksums, packet serialization/deserialization, neighbor FSM, interface FSM, DR election, Dijkstra SPF, LSDB operations, config parsing, routing table diffing, SR TLV codec, Opaque LSA parsing, label computation.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/architecture.md](docs/architecture.md) | Module map, startup sequence, packet/SPF flow, key invariants |
| [docs/segment-routing.md](docs/segment-routing.md) | SR concepts, LSA types, label computation, Cisco IOS interop |
| [docs/configuration.md](docs/configuration.md) | Full YAML reference with every option |
| [docs/operations.md](docs/operations.md) | Deploy, monitor, troubleshoot, upgrade |

## License

MIT
