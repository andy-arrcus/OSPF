# Configuration Reference

ospfd is configured via a YAML file, by default `/etc/ospfd/ospfd.yaml`. Pass an alternate path with `-c`.

## Full reference

```yaml
# ── Router identity ────────────────────────────────────────────────────────
router_id: 10.0.0.1          # IPv4 dotted-decimal; auto-selected if omitted
                              # Selection order: configured > highest loopback > highest interface

# ── Logging ───────────────────────────────────────────────────────────────
log_level: info               # debug | info | warning | error
log_file: /var/log/ospfd.log  # optional; must be under /var/log/

# ── PID file ──────────────────────────────────────────────────────────────
pid_file: /var/run/ospfd.pid

# ── Timers ────────────────────────────────────────────────────────────────
timers:
  spf_delay: 1.0              # seconds to wait after a topology change before running SPF
  spf_hold: 5.0               # minimum seconds between SPF runs (dampening)
  lsa_refresh: 1800           # seconds between self-LSA re-originations (default 30 min)

# ── Route redistribution ──────────────────────────────────────────────────
redistribute:
  connected: false            # redistribute directly connected prefixes as Type-5 AS External
  static: false               # redistribute kernel static routes as Type-5 AS External
  metric: 20                  # external metric value
  metric_type: 2              # 1 = Type 1 (additive), 2 = Type 2 (flat)

# ── Segment Routing (RFC 8665) ────────────────────────────────────────────
sr:
  enabled: false              # set true to enable SR subsystem
  srgb_start: 16000           # first label in Segment Routing Global Block
  srgb_size: 8000             # number of labels in SRGB
  node_sid_index: ~           # integer SID index for this router's Node-SID (optional)
                              # outgoing label at peers = srgb_start + node_sid_index

# ── Areas ─────────────────────────────────────────────────────────────────
areas:
  0.0.0.0:                    # area ID in dotted-decimal
    stub: false               # true = stub area (no Type-5 LSAs flooded in)
    default_cost: 1           # cost of default route injected into stub area

    interfaces:
      eth0:                   # interface name as shown by `ip link`

        # Interface type
        type: broadcast       # broadcast | point-to-point | nbma | point-to-multipoint

        # Metrics
        cost: 10              # interface output cost (1–65535)

        # Timers (seconds)
        hello_interval: 10    # how often to send Hellos
        dead_interval: 40     # declare neighbor dead after this many seconds without a Hello
                              # default: hello_interval * 4
        retransmit_interval: 5   # retransmit unacknowledged LSUs after this many seconds
        transmit_delay: 1        # estimated transit delay added to LSA age on transmit

        # DR election
        priority: 1           # DR election priority; 0 = never become DR/BDR

        # Passive — send no packets, accept no neighbors; just announce the prefix
        passive: false

        # Authentication
        auth:
          type: none          # none | simple | md5

          # For type: simple
          key: "mysecret"

          # For type: md5
          md5:
            key_id: 1
            key: "mysecret"

  1.0.0.0:
    stub: true
    default_cost: 5
    interfaces:
      eth1:
        type: point-to-point
        cost: 100
        hello_interval: 10
        dead_interval: 40
```

## Minimal configuration

```yaml
router_id: 192.168.1.1
areas:
  0.0.0.0:
    interfaces:
      eth0:
        cost: 10
```

## Authentication

### Simple password

```yaml
auth:
  type: simple
  key: "opensesame"
```

The key is sent in cleartext in every packet. Use only on trusted networks.

### MD5 (recommended)

```yaml
auth:
  type: md5
  md5:
    key_id: 1
    key: "strongpassword"
```

Uses HMAC-MD5 with a monotonically increasing cryptographic sequence number. Key ID must match on both ends of the adjacency.

## Multi-area

```yaml
areas:
  0.0.0.0:                    # backbone
    interfaces:
      eth0:
        cost: 10
  10.0.1.0:                   # non-backbone area
    interfaces:
      eth1:
        cost: 10
```

A router with interfaces in both areas automatically becomes an ABR and originates Summary LSAs between them.

## Segment Routing with Node-SID

```yaml
sr:
  enabled: true
  srgb_start: 16000
  srgb_size: 8000
  node_sid_index: 1     # neighbors push label 16001 to reach this router

areas:
  0.0.0.0:
    interfaces:
      eth0:
        cost: 10
```

Kernel setup required:
```bash
sysctl -w net.mpls.platform_labels=65536
sysctl -w net.mpls.conf.eth0.input=1
```
