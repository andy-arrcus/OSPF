# CLAUDE.md — ospfd developer guide

## Build & test

```bash
# Install in editable mode with dev deps
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=ospfd --cov-report=term-missing

# Lint / format check
ruff check src/ tests/
```

## Deploy to ub01 (192.168.86.224)

```bash
# Build wheel
python3 -m build --wheel

# Copy and install
scp dist/ospfd-*.whl install.sh etc/ospfd.yaml etc/ospfd.service asmith@192.168.86.224:~/
ssh asmith@192.168.86.224 'sudo bash install.sh'

# Restart service
ssh asmith@192.168.86.224 'sudo systemctl restart ospfd'

# Tail logs
ssh asmith@192.168.86.224 'journalctl -u ospfd -f'
```

## Run in foreground for debugging

```bash
sudo ospfd -f -d -c /etc/ospfd/ospfd.yaml
```

## Dump LSDB at runtime

```bash
sudo kill -USR1 $(pidof ospfd)
# then check journalctl -u ospfd
```

## Project layout

```
src/ospfd/
  packet/       Serialization for all OSPF packet and LSA types
  protocol/     Neighbor FSM, interface FSM, DR election, area, instance
  lsdb/         Link-state database, flooding, origination, aging
  spf/          Dijkstra, intra/inter/external routes, routing table
  io/           Raw socket (proto 89), Netlink via pyroute2
  util/         Timers, IP helpers, logging, router ID
  daemon.py     Daemonize, PID file, signal handling (SIGTERM/SIGHUP/SIGUSR1)
  config.py     YAML config parsing
  const.py      RFC 2328 constants
  sr/           Segment Routing subsystem (RFC 8665)
tests/unit/     108 unit tests (75 original + 33 SR)
docs/           architecture.md, segment-routing.md, configuration.md, operations.md
etc/            ospfd.yaml (config), ospfd.service (systemd)
install.sh      venv-based installer for Ubuntu 24.04+
```

## Key implementation notes

**pyroute2 IPRoute must be created before the event loop starts.**
pyroute2 0.9.x uses asyncio internally; creating IPRoute after
`loop.run_until_complete()` causes a deadlock. See `instance.py` —
`init_netlink()` is called before `loop.run_forever()`.

**LSA sequence numbers are unsigned 32-bit (`struct` format `'I'`).**
RFC 2328 uses a signed integer range (0x80000001–0x7FFFFFFF) but the
wire format is 4 bytes and values like 0x80000001 overflow a signed int.
The seq field is stored as `uint32`, then converted to signed only for
the wrap-around comparison in `lsdb/database.py`.

**DD exchange: master increments seq after NegotiationDone.**
The master must send its first Exchange DD with a seq number one higher
than the final negotiation seq. Slave echoes the master's seq unchanged.

**MinLSArrival check ordering.**
The check must come *after* the newer/older LSA comparison, not before.
Placing it before blocks legitimate re-installs of the same LSA from a
different router.

**systemd service type is `simple`, not `forking`.**
The daemon is started with `-f` (foreground). Double-fork daemonization
is available but not used under systemd.

**Test environment.**
- Target host: ub01 (192.168.86.224), Ubuntu 24.04, Python 3.12
- OSPF interface: 172.16.1.224, area 0.0.0.0
- Peer: Cisco IOS R1 (router-id 1.1.1.1) on FastEthernet0/0
- Full adjacency (FULL state) confirmed in production testing

## Segment Routing (RFC 8665)

SR support is implemented as an optional subsystem in `src/ospfd/sr/`. Enable it in `ospfd.yaml`:

```yaml
sr:
  enabled: true
  srgb_start: 16000    # first label in SRGB
  srgb_size: 8000      # number of labels
  node_sid_index: 100  # this router's Node-SID index (optional)
```

**Architecture:**

| Module | Purpose |
|--------|---------|
| `sr/tlv.py` | TLV codec: `parse_tlvs`, `encode_tlv`, `SidLabelRange`, `PrefixSid`, `AdjSid`, `ExtendedPrefixEntry`, `ExtendedLinkEntry` |
| `sr/lsa.py` | Opaque LSA body parsers: `RouterInfoLsa` (type 10/4), `ExtendedPrefixLsa` (type 10/7), `ExtendedLinkLsa` (type 10/8) |
| `sr/database.py` | `SrDatabase` — scans LSDB for opaque LSAs, builds per-router SR topology |
| `sr/origination.py` | `SrOriginator` — originates RI LSA (SRGB advertisement) and Extended Prefix LSA (Prefix-SID) |
| `sr/spf.py` | `compute_sr_routes` — post-SPF MPLS label stack computation with PHP support |

**LSA types added** (const.py):
- Type 9: Link-scoped Opaque (flooding/database now accept types 9–11)
- Type 10: Area-scoped Opaque (RI LSA, Extended Prefix, Extended Link)
- Type 11: AS-scoped Opaque (treated like Type 5 in LSDB)

**Opaque LSA flow:**
1. On startup (if SR enabled): `SrOriginator` floods RI LSA with SRGB TLV and Extended Prefix LSA with Prefix-SID sub-TLV.
2. Peer Opaque LSAs arrive via LSU, pass the type-9/10/11 gate in `flooding.py`, and are installed in the LSDB as `_RawBody` objects.
3. After each SPF run, `SrDatabase.rebuild()` scans the LSDB, parses all Opaque LSAs, and builds `NodeSrInfo` per router-ID (SRGB + Node-SIDs + Adj-SIDs).
4. `compute_sr_routes()` walks the SPF tree and emits `SrRoute` objects with outgoing MPLS labels.
5. `NetlinkManager.install_sr_routes()` programs the kernel via pyroute2 MPLS encap routes.

**Label computation:**
- Global SID (index form): `outgoing_label = nexthop_srgb.start + sid_index`
- Absolute label (V-flag set): `outgoing_label = sid` directly
- PHP (penultimate hop popping): when No-PHP flag is NOT set and destination is one hop away, `outgoing_label = IMPLICIT_NULL (3)`

**Adj-SID:** advertised in Extended Link LSA (opaque type 8). Parsed and stored per link in `NodeSrInfo.adj_sids`. Not yet programmed into kernel (label swap path is future work).

**Interop note:** This router advertises `OPT_O` (0x40) in the Options field of Hello packets to signal Opaque LSA support per RFC 5250. Cisco IOS routers will send their own RI/SR LSAs in response.
