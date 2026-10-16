#!/bin/sh
# Host firewall for the icloud-mcp containers on CT104 (DOCKER-USER chain, idempotent).
#  - icloud-mcp (172.30.104.2) may only reach DNS and Apple (17.0.0.0/8) on 443/993/587. Anything else is logged and dropped,
#    so a compromised dependency or a tool that fetches a sender-chosen URL cannot send data anywhere but iCloud.
#  - cloudflared (172.30.104.3) may only reach DNS and Cloudflare's tunnel ports (7844 tcp/udp, 443), never the LAN.
#  - From outside, the app port 8000 is open only to the MCP gateway CT103.
# Addresses live here and in docker-compose.yml (ipv4_address). Pattern after Michel's CT219 egress.sh, written anew.
set -eu
APP=172.30.104.2
TUN=172.30.104.3
NET=172.30.104.0/24
GATEWAY=192.168.1.234          # CT103 mcp-gateway
DNS="192.168.1.12 1.1.1.1"     # what Docker's embedded resolver forwards to (CT104 /etc/resolv.conf)
APPLE=17.0.0.0/8
PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"

ipt() { iptables "$@"; }
ipt -N DOCKER-USER 2>/dev/null || true
ipt -F DOCKER-USER

ipt -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
ipt -A DOCKER-USER -s "$NET" -d "$NET" -j RETURN                       # tunnel -> app inside the compose network

# inbound to the app from outside the host: only the gateway
ipt -A DOCKER-USER -d "$APP" -p tcp --dport 8000 -s "$GATEWAY" -j RETURN
ipt -A DOCKER-USER -d "$APP" -j LOG --log-prefix "icloud-mcp-in-drop " -m limit --limit 6/min
ipt -A DOCKER-USER -d "$APP" -j DROP

for src in "$APP" "$TUN"; do
  for d in $DNS; do
    ipt -A DOCKER-USER -s "$src" -d "$d" -p udp --dport 53 -j RETURN
    ipt -A DOCKER-USER -s "$src" -d "$d" -p tcp --dport 53 -j RETURN
  done
done

# app: Apple only
ipt -A DOCKER-USER -s "$APP" -d "$APPLE" -p tcp -m multiport --dports 443,993,587 -j RETURN
ipt -A DOCKER-USER -s "$APP" -j LOG --log-prefix "icloud-mcp-egress-drop " -m limit --limit 6/min
ipt -A DOCKER-USER -s "$APP" -j DROP

# tunnel: no private networks, then Cloudflare tunnel ports only
for p in $PRIVATE; do ipt -A DOCKER-USER -s "$TUN" -d "$p" -j DROP; done
ipt -A DOCKER-USER -s "$TUN" -p tcp -m multiport --dports 7844,443 -j RETURN
ipt -A DOCKER-USER -s "$TUN" -p udp --dport 7844 -j RETURN
ipt -A DOCKER-USER -s "$TUN" -j LOG --log-prefix "icloud-mcp-tunnel-drop " -m limit --limit 6/min
ipt -A DOCKER-USER -s "$TUN" -j DROP

ipt -A DOCKER-USER -j RETURN
