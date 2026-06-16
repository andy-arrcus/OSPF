# ospfd Architecture

## Overview

ospfd is a single-process, event-driven OSPF v2 daemon built on Python's asyncio. It opens a raw IP socket (protocol 89) per interface, drives all protocol state machines from asyncio callbacks, and programs the Linux kernel routing table via Netlink (pyroute2).

```
┌─────────────────────────────────────────────────────────┐
│                     ospfd process                        │
│                                                         │
│  OspfInstance                                           │
│  ├── OspfArea (per area)                                │
│  │   └── OspfInterface (per interface)                  │
│  │       └── OspfNeighbor (per peer)                    │
│  ├── LinkStateDatabase                                  │
│  │   ├── area DBs (types 1–4, 9–10)                    │
│  │   └── external DB (types 5, 11)                     │
│  ├── FloodingEngine                                     │
│  ├── LsaOriginator                                      │
│  ├── LsaAgingManager                                    │
│  ├── DijkstraEngine → OspfRoutingTable                  │
│  ├── SrDatabase + SrOriginator (optional)               │
│  └── NetlinkManager                                     │
│                                                         │
│  asyncio event loop                                     │
│  ├── raw socket readers (one per interface)             │
│  ├── periodic timers (Hello, aging, retransmit)         │
│  └── one-shot timers (SPF delay, LSA scheduling)        │
└─────────────────────────────────────────────────────────┘
         │ Netlink (pyroute2)            │ raw IP (proto 89)
         ▼                               ▼
   kernel routing table            network interfaces
```

## Module map

### `packet/`

Wire format serialization and deserialization. Each module owns one packet or LSA type. All use `struct.pack`/`unpack` — no external parsing libraries.

| Module | Owns |
|--------|------|
| `header.py` | OSPF common header (24 bytes) |
| `hello.py` | Hello packet |
| `dd.py` | Database Description |
| `lsr.py` | Link State Request |
| `lsu.py` | Link State Update |
| `lsack.py` | Link State Acknowledgment |
| `lsa.py` | LSA header + all 5 body types + `_RawBody` for opaque |
| `auth.py` | Null / simple / MD5 authentication |
| `checksum.py` | Fletcher-16 (LSA) and IP checksum |

### `protocol/`

State machines and protocol logic.

| Module | Owns |
|--------|------|
| `neighbor.py` | Neighbor FSM (8 states, 13 events), DD exchange, LSR/LSU/LSAck handling |
| `interface.py` | Interface FSM (7 states, 7 events), Hello origination, DR/BDR election trigger |
| `dr_election.py` | DR/BDR two-pass election (RFC 2328 §9.4) |
| `area.py` | Area object — owns its interface list |
| `instance.py` | Top-level orchestrator: startup, packet dispatch, SPF scheduling |

### `lsdb/`

| Module | Owns |
|--------|------|
| `database.py` | LSDB storage, lookup, install (with MinLSArrival, size limits), LSA comparison |
| `flooding.py` | LSU receive processing, retransmission lists, flooding to interfaces |
| `origination.py` | Router LSA, Network LSA, Summary LSA, AS External LSA origination |
| `aging.py` | Periodic aging tick (every 5s), MaxAge flushing, LS Refresh |

### `spf/`

| Module | Owns |
|--------|------|
| `dijkstra.py` | Dijkstra SPF using a min-heap candidate list |
| `intra_area.py` | Intra-area route extraction from SPF tree |
| `inter_area.py` | Inter-area route calculation from Summary LSAs |
| `external.py` | AS External route calculation (Type 1 and Type 2 metrics) |
| `routing_table.py` | Route table with add/change/remove diffing, Netlink sync |

### `sr/`

Optional Segment Routing subsystem (RFC 8665). Only loaded when `sr.enabled: true`.

| Module | Owns |
|--------|------|
| `tlv.py` | TLV codec for all SR TLV/sub-TLV types |
| `lsa.py` | Opaque LSA body parsers (RI, Extended Prefix, Extended Link) |
| `database.py` | SR topology view built by scanning LSDB after each SPF |
| `origination.py` | Originate RI LSA (SRGB) and Extended Prefix LSA (Prefix-SID) |
| `spf.py` | Post-SPF MPLS label stack computation |

### `io/`

| Module | Owns |
|--------|------|
| `raw_socket.py` | AF_INET/SOCK_RAW socket, multicast join, asyncio reader registration |
| `netlink.py` | Interface discovery, route add/change/remove, SR MPLS route programming |

### `util/`

| Module | Owns |
|--------|------|
| `timer.py` | `PeriodicTimer` and `OneShotTimer` backed by `asyncio.get_running_loop()` |
| `ip.py` | Mask/prefix-len conversion, network/broadcast helpers |
| `identifier.py` | Router ID selection (configured > highest loopback > highest interface) |
| `logging.py` | Log setup (file + stderr, configurable level) |

## Startup sequence

```
daemon.py main()
  │
  ├── parse args / load config
  ├── open raw sockets (root required)
  ├── OspfInstance(config)
  │     └── init_netlink()           ← pyroute2 IPRoute() created here, before loop
  │
  └── asyncio.run(instance.start())
        ├── select_router_id()
        ├── create OspfInterface objects
        ├── register raw socket readers
        ├── aging_manager.start()
        ├── bring up interfaces (INTF_EVT_IF_UP)
        ├── originate_router_lsa() per area
        └── if sr.enabled: SrOriginator.originate_ri_lsa()
              loop.run_forever()
```

## Packet receive path

```
raw socket readable
  └── _receive_packet(interface, sock)
        ├── recv() → data, src_addr
        ├── OspfHeader.deserialize()
        ├── validate: version, router_id (not self), length, checksum, auth, area, on-link
        └── dispatch by header.type
              Hello  → interface.process_hello()
              DD     → neighbor.process_dd()
              LSR    → neighbor.process_ls_request()
              LSU    → flooding.receive_lsu()
              LSAck  → neighbor.process_ls_ack()
```

## SPF trigger path

```
LSDB install() → instance.schedule_spf()  (debounced)
  └── _run_spf()
        ├── dijkstra.calculate() per area → spf_tree
        ├── calculate_intra_area_routes()
        ├── calculate_inter_area_routes()
        ├── calculate_asbr_routes()
        ├── calculate_external_routes()
        ├── routing_table.update() → added/changed/removed
        ├── routing_table.sync_to_kernel()
        └── if SR enabled:
              SrDatabase.rebuild()
              compute_sr_routes()
              NetlinkManager.install_sr_routes()
```

## Key invariants

**pyroute2 before event loop.** `IPRoute()` must be constructed before `asyncio.run()` starts because pyroute2 0.9.x creates its own event loop internally. Creating it inside the running loop causes a deadlock. See `init_netlink()`.

**LSA sequence numbers are unsigned on the wire.** RFC 2328 specifies signed comparison but the wire format is 4 bytes. Values like `0x80000001` (initial) overflow a signed 32-bit int. The `struct` format `'I'` stores the raw unsigned bits; conversion to signed happens only in `lsdb/database.py` for the wrap-around comparison.

**DD master increments seq after NegotiationDone.** The master sends its first Exchange DD with seq = final-negotiation-seq + 1. The slave echoes the master's seq unchanged.

**MinLSArrival ordering.** The 1-second MinLSArrival check must happen *after* the newer/older LSA comparison, not before. Placing it before blocks legitimate re-installs of the same LSA from a different router.
