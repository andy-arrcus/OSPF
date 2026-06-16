# Operations Guide

## Installation

### From wheel (Ubuntu 24.04+)

```bash
# Build
python3 -m build --wheel

# Deploy to remote host
scp dist/ospfd-*.whl install.sh etc/ospfd.yaml etc/ospfd.service user@host:~/
ssh user@host 'sudo bash install.sh'
```

The install script:
- Creates a virtualenv at `/opt/ospfd`
- Installs the wheel and all dependencies
- Symlinks `ospfd` binary to `/usr/local/sbin/ospfd`
- Copies config to `/etc/ospfd/ospfd.yaml`
- Installs and enables the systemd service

### From source

```bash
pip install -e ".[dev]"
```

## Running

### Under systemd (production)

```bash
sudo systemctl enable ospfd   # enable at boot
sudo systemctl start ospfd    # start now
sudo systemctl status ospfd   # check status
sudo systemctl restart ospfd  # restart (e.g. after config change)
sudo systemctl stop ospfd     # stop
```

### In foreground (debugging)

```bash
sudo ospfd -f -d -c /etc/ospfd/ospfd.yaml
```

Flags:
- `-f` — foreground (do not daemonize)
- `-d` — debug log level
- `-c PATH` — config file path

## Monitoring

### Follow logs

```bash
journalctl -u ospfd -f
journalctl -u ospfd --since "1 hour ago"
```

Key log lines to watch:

| Message | Meaning |
|---------|---------|
| `Router ID: 10.0.0.1` | Daemon started, router ID selected |
| `Interface eth0: state → Waiting` | Interface brought up |
| `Interface eth0: new DR 10.0.0.2` | DR election completed |
| `Neighbor 10.0.0.2 → Full` | Full adjacency formed |
| `Running SPF calculation...` | Topology change detected |
| `SPF done: 5 intra, 2 inter, 0 external routes` | SPF result summary |
| `Originated Router LSA for area 0.0.0.0` | Self-LSA generated |
| `SR database rebuilt: 3 SR nodes` | SR topology updated |

### Dump LSDB

Send `SIGUSR1` to dump the full LSDB to the log:

```bash
sudo kill -USR1 $(pidof ospfd)
journalctl -u ospfd -n 200
```

### Reload config

`SIGHUP` triggers a config reload (re-reads YAML, re-evaluates interfaces):

```bash
sudo kill -HUP $(pidof ospfd)
```

## Troubleshooting

### No adjacency forming

1. **Check interface state**: look for `state → Waiting` or `state → P2P` in logs. If still `Down`, the interface may not have come up.
2. **Hello mismatch**: Hello and Dead intervals must match on both sides. Check peer config.
3. **Area ID mismatch**: packets with the wrong area ID are silently dropped.
4. **Authentication mismatch**: auth type and key must match. Check for `Auth failed` in logs.
5. **MTU mismatch**: DD packets with a mismatched MTU are rejected during ExStart.
6. **On-link check**: broadcast interfaces reject packets from off-subnet sources. Verify IP addressing.

### Stuck in ExStart/Exchange

- **Master/slave flip**: if both sides think they are master, DD exchange loops. Verify neither side has a stale neighbor entry.
- **DD seq mismatch**: look for `SeqNumberMismatch` events in logs — this resets the adjacency and retries.

### Routes not in kernel

1. Run `ip route show proto 89` to see ospfd-installed routes.
2. Check `SPF done` log line — zero routes means SPF found nothing, which usually means no router/network LSAs are installed.
3. Verify Netlink is functional: ospfd logs any pyroute2 errors at WARNING level.

### SR labels not programmed

1. Verify `sr.enabled: true` in config and check for `SR database rebuilt` log line.
2. Check kernel MPLS is enabled:
   ```bash
   sysctl net.mpls.platform_labels   # should be > 0
   sysctl net.mpls.conf.eth0.input   # should be 1
   ```
3. Run `ip -f mpls route` to see installed MPLS routes.

## Security notes

ospfd drops privileges minimally — it needs `CAP_NET_RAW` (raw socket) and `CAP_NET_ADMIN` (Netlink). The systemd unit grants only these capabilities:

```ini
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
```

Additional hardening in the unit file: `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `PrivateTmp=yes`.

Authentication with MD5 is strongly recommended on any interface that connects to untrusted segments. Simple password authentication is sent in cleartext.

LSDB and neighbor table sizes are bounded to prevent memory exhaustion from malformed or malicious LSUs:
- Max LSAs per area: 10,000
- Max AS External LSAs: 10,000
- Max neighbors per interface: 128
- Max retransmission list per neighbor: 1,000
- Max LSAs per LSU: 1,000

## Upgrading

```bash
# On the build machine
python3 -m build --wheel
scp dist/ospfd-*.whl asmith@ub01:~/

# On ub01
sudo systemctl stop ospfd
sudo /opt/ospfd/bin/pip install --force-reinstall ~/ospfd-*.whl
sudo systemctl start ospfd
```

## Test environment

- Target host: ub01 (192.168.86.224), Ubuntu 24.04, Python 3.12
- OSPF interface: 172.16.1.224, area 0.0.0.0
- Peer: Cisco IOS R1 (router-id 1.1.1.1) on FastEthernet0/0
- Full adjacency (FULL state) confirmed in production
