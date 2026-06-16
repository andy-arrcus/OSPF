# Segment Routing (RFC 8665)

ospfd implements OSPF Extensions for Segment Routing over MPLS as defined in RFC 8665, with the Opaque LSA infrastructure from RFC 5250 (opaque LSA types 9/10/11) and RFC 7684 (Extended Prefix/Link LSAs).

## Concepts

Segment Routing replaces per-flow state in the network core with labels pushed at the ingress router. Each router advertises:

- **SRGB** (Segment Routing Global Block): the contiguous label range this router uses for globally significant SIDs, e.g. labels 16000–23999.
- **Node-SID** (Prefix-SID): an index into the advertising router's SRGB that represents "deliver to this router's loopback". The ingress router pushes `nexthop_srgb.start + index` as the MPLS label.
- **Adj-SID**: a label that steers traffic out a specific interface, bypassing normal SPF. Allocated locally.

## Enabling SR

Add the `sr:` block to `ospfd.yaml`:

```yaml
sr:
  enabled: true
  srgb_start: 16000      # first label in SRGB (must not overlap with dynamic labels)
  srgb_size: 8000        # number of labels in SRGB
  node_sid_index: 100    # this router's Node-SID index within the SRGB (optional)
```

With `node_sid_index: 100` and `srgb_start: 16000`, this router's Node-SID label is **16100**. Neighbors push label 16100 to send traffic to this router.

## What is advertised

When SR is enabled, ospfd originates two new Opaque LSA types into every area on startup:

### Router Information LSA (opaque type 4, area-scoped)

Advertises this router's SRGB and supported SR algorithms. Peers that receive this LSA know how to map Node-SID indices to labels for this router.

```
LSA type: 10 (area-scoped Opaque)
Link State ID: 0x04000000  (opaque type 4, opaque ID 0)
Body TLVs:
  TLV 2  SR-Capabilities: flags=0, range_size=8000, first_label=16000
  TLV 19 SR-Algorithm:    [0]  (0=shortest path)
  TLV 9  SID/Label Range: size=8000, start=16000
```

### Extended Prefix LSA (opaque type 7, area-scoped)

Advertises a Prefix-SID sub-TLV for each interface prefix if `node_sid_index` is configured.

```
LSA type: 10 (area-scoped Opaque)
Link State ID: 0x07<prefix>  (opaque type 7, lower 24 bits from prefix)
Body TLVs:
  TLV 1  Extended Prefix: route_type=1, prefix_len=24, prefix=10.0.1.0
    Sub-TLV 2 Prefix-SID: flags=NP, algorithm=0, index=100
```

The `NP` (No-PHP) flag is set by default, meaning this router expects to receive labeled packets even when it is the penultimate hop.

## What is received

### From Cisco IOS peers

Cisco IOS routers that see `OPT_O` (0x40) in Hello packets respond with their own RI LSA and Extended Prefix/Link LSAs. These arrive via normal LSU flooding, are stored in the LSDB as raw opaque bodies, and are parsed by `SrDatabase.rebuild()` after each SPF run.

### Adj-SIDs

Extended Link LSAs (opaque type 8) carry Adj-SID sub-TLVs. ospfd parses and stores these in `NodeSrInfo.adj_sids` but does not yet program label-swap (transit) MPLS entries for them. This is noted as future work.

## Label computation

After each SPF run, `compute_sr_routes()` in `sr/spf.py` walks the SPF tree:

```python
for each router in spf_tree:
    for each (prefix, prefix_sid) in router.node_sids:
        if prefix_sid.V_flag:
            label = prefix_sid.sid          # absolute label
        else:
            label = nexthop_srgb.start + prefix_sid.sid   # index into SRGB

        if not prefix_sid.NP_flag and destination is one hop away:
            label = IMPLICIT_NULL (3)       # PHP: pop label at penultimate hop
```

The resulting `SrRoute` objects are passed to `NetlinkManager.install_sr_routes()`.

## Kernel programming

ospfd programs MPLS encapsulation routes via Netlink using pyroute2:

```python
# Label push (multi-hop)
ipr.route("replace", dst="10.0.2.0/24", gateway="172.16.1.1",
          encap={"type": "mpls", "labels": 16200}, proto=88)

# PHP (one hop away, NP not set)
ipr.route("replace", dst="10.0.1.0/24", gateway="172.16.1.1", proto=88)
```

Requires kernel `CONFIG_MPLS_IPTUNNEL=y` and:
```bash
sysctl -w net.mpls.platform_labels=65536
sysctl -w net.mpls.conf.eth0.input=1
```

## Architecture

```
startup
  └── SrOriginator.originate_ri_lsa()         flood RI LSA
  └── SrOriginator.originate_prefix_sid_lsa() flood Prefix-SID LSA

LSU received
  └── flooding.receive_lsu()
        └── lsdb.install() with _RawBody for types 9/10/11

SPF trigger
  └── dijkstra.calculate()
  └── SrDatabase.rebuild()      scan LSDB, parse all opaque LSAs
  └── compute_sr_routes()       walk SPF tree, compute labels
  └── netlink.install_sr_routes()
```

## Module reference

| File | Key classes/functions |
|------|-----------------------|
| `sr/tlv.py` | `parse_tlvs`, `encode_tlv`, `SidLabelRange`, `PrefixSid`, `AdjSid`, `ExtendedPrefixEntry`, `ExtendedLinkEntry` |
| `sr/lsa.py` | `RouterInfoLsa`, `ExtendedPrefixLsa`, `ExtendedLinkLsa`, `make_opaque_lsa_id`, `opaque_type_from_lsa_id` |
| `sr/database.py` | `SrDatabase`, `NodeSrInfo` |
| `sr/origination.py` | `SrOriginator`, `OpaqueLsaBody` |
| `sr/spf.py` | `compute_sr_routes`, `SrRoute` |

## Relevant RFCs

| RFC | Title |
|-----|-------|
| RFC 5250 | The OSPF Opaque LSA Option |
| RFC 7770 | Extensions to OSPF for Advertising Optional Router Capabilities (RI LSA) |
| RFC 7684 | OSPFv2 Prefix/Link Attribute Advertisement |
| RFC 8665 | OSPF Extensions for Segment Routing |
| RFC 8660 | Segment Routing with MPLS Data Plane |
