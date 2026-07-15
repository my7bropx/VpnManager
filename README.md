# vpn-manager

A clean Rust rewrite of the Python VPN manager — OpenVPN wrapper with an
iptables kill switch, automatic interface teardown, and a live two-tab TUI.

---

## What was wrong with the Python version

### Root bug — `persist-tun` orphans kernel routes

The Python config template always emitted `persist-tun`.  When OpenVPN is
killed (SIGKILL or an unexpected crash) this directive keeps the `tun0`
interface alive as a kernel object.  OpenVPN had already pushed routes like:

```
0.0.0.0/1 via 10.x.x.1 dev tun0
```

Those routes remain in the routing table after the process dies.  All traffic
is now forwarded to a dead interface.  iptables never sees the packets, so:

- Restarting iptables rules → no effect (problem is in the routing layer, not netfilter)
- `vpn-manager recover` → no effect (it only reset iptables, never touched routes/interfaces)
- Reboot → fixes it (kernel removes the stale interface and its routes)

`persist-tun` is absent from the Rust config template.

### Secondary bug — explicit interface teardown was missing

Neither `disconnect()` nor `force_disconnect()` in the Python code called
`ip route flush dev tun0` or `ip link delete tun0`.  This Rust implementation
calls `teardown_vpn_interfaces()` in every disconnect path, including the
Drop impl (panic safety) and standalone recovery.

### Kill-switch `restored` flag bug

The Python `_restore_rules()` set `restored = True` on the first table that
succeeded (`nat` often succeeds when `filter` fails), then skipped
`_emergency_recovery()` even when the `filter` table — the one with the DROP
default policies — had not been restored.

The Rust implementation tracks per-table success independently and falls
through to emergency recovery if any table fails.

---

## Installation

Requires Rust 1.75+ and `openvpn` installed.

```bash
git clone … && cd vpn-manager
chmod +x install.sh && ./install.sh
```

Or manually:

```bash
cargo build --release
sudo install -m755 target/release/vpn-manager /usr/local/bin/
```

---

## Usage

```bash
# List all VPN configs (.ovpn / WireGuard .conf) in a folder
vpn-manager list ~/vpn-configs
# (passing a directory to --config also lists what's inside)

# Connect using a .ovpn profile
sudo vpn-manager connect --config ~/myvpn.ovpn

# Connect by host/port (auto-generates config)
sudo vpn-manager connect --host vpn.example.com --port 1194 --proto udp

# With custom DNS and credential file
sudo vpn-manager connect --config ~/myvpn.ovpn \
    --dns 1.1.1.1 1.0.0.1 \
    --auth-file ~/creds.txt

# Headless (no TUI) — stays connected until Ctrl-C or `vpn-manager disconnect`
sudo vpn-manager connect --config ~/myvpn.ovpn --no-tui

# Graceful disconnect
sudo vpn-manager disconnect

# Emergency recovery (network stuck after a crash)
sudo vpn-manager recover

# Status
vpn-manager status
```

---

## TUI

```
╭─ vpn-manager ───────────────────────────────────────────────╮
│  1 Dashboard    2 Log    3 Configs                           │
╰──────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────╮
│ ● CONNECTED  ·  WireGuard  ·  203.0.113.7  ·  Berlin, DE  ·  up 00:12:47
╰──────────────────────────────────────────────────────────────╯
 Connection                    Traffic
 ─────────────────────────      ────────────────────
 State         ● CONNECTED     ↑ Sent      42 MB
 Server        vpn.example     ↑ Rate      1.2 MB/s
 Location      Berlin, DE      ↓ Received  180 MB
 Public IP     203.0.113.7     ↓ Rate      8.4 MB/s
 Interface     wgvpnm
 Uptime        00:12:47
 Kill Switch   ● ACTIVE
 DNS           10.2.0.1
╭ ↑ 1.2 MB/s  peak 3 MB/s ─╮  ╭ ↓ 8.4 MB/s  peak 12 MB/s ╮
│      ▂▄▆█▅▃▁▂▄           │  │  ▁▃▅▇█▆▄▂▁▂▃▅            │
╰──────────────────────────╯  ╰──────────────────────────╯
```

The **Dashboard** is colour-coded by connection state (green connected,
yellow connecting, red error — banner, borders, and tab frame all follow it)
and shows live upload/download sparklines built from 1-second rate samples
(last ~5 minutes).

**Log tab** shows live verbose output from openvpn and the manager itself,
colour-coded by severity.  Scroll with `↑ ↓ PgUp PgDn`, jump to the bottom
with `End`.

**Configs tab** lists every .ovpn / WireGuard .conf sitting next to the
config you connected with (● marks the active one).  Select with `↑ ↓` and
press `Enter` to disconnect and reconnect using the selected config — the
kill switch is re-armed with the new server's endpoints.

**Keys:** `Tab` / `1` / `2` / `3` switch tabs.  `q` or `Esc` disconnects and quits.

---

## Kill switch behaviour

When the kill switch is active:

- IPv6 is disabled at sysctl level **and** blocked at ip6tables level
- IPv4 default policy: `INPUT DROP`, `FORWARD DROP`, `OUTPUT DROP`
- Allowed outbound: VPN server endpoints, LAN subnets, DHCP, rate-limited ICMP
- Allowed inbound:  VPN server, established/related, LAN
- DNS is locked to the servers you specify via `resolvectl` (systemd-resolved)
  or direct `/etc/resolv.conf` rewrite with a backup
- Original iptables state is saved per-table before activation and restored
  on disconnect — including on panic (Drop impl)
- On partial restore failure, emergency recovery resets to full ACCEPT **and**
  tears down any remaining tun/wg interfaces

---

## Recovery without rebooting (manual)

If you're stuck right now:

```bash
sudo vpn-manager recover
```

If the binary isn't available:

```bash
sudo pkill -9 openvpn

# Remove stale tun interfaces
for iface in $(ip link show | grep ': tun' | awk -F': ' '{print $2}' | cut -d@ -f1); do
    sudo ip route flush dev "$iface"
    sudo ip link set "$iface" down
    sudo ip link delete "$iface"
done

# Reset iptables
sudo iptables  -P INPUT ACCEPT && sudo iptables  -P FORWARD ACCEPT && sudo iptables  -P OUTPUT ACCEPT
sudo iptables  -F && sudo iptables  -X
sudo iptables  -t nat -F && sudo iptables  -t nat -X
sudo iptables  -t mangle -F && sudo iptables  -t mangle -X
sudo ip6tables -P INPUT ACCEPT && sudo ip6tables -P FORWARD ACCEPT && sudo ip6tables -P OUTPUT ACCEPT
sudo ip6tables -F && sudo ip6tables -X

# Restore IPv6
echo 0 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 0 | sudo tee /proc/sys/net/ipv6/conf/default/disable_ipv6
```
