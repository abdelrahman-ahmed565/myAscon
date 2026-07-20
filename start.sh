#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Universal LEACH Launcher — works on ANY Pi automatically
#  Just run ./start.sh on every Pi. No per-Pi editing needed.
# ══════════════════════════════════════════════════════════════════

# ── Configure your network here ONCE ──────────────────────────────
# List every Pi's IP in the cluster, comma-separated:
ALL_IPS="10.25.96.150,10.25.96.151"
# LEACH probability: 0.5 for 2 Pis, 0.2 for 5 Pis
P_VALUE="0.5"
ROUND_TIME="60"
# ──────────────────────────────────────────────────────────────────

# Auto-detect THIS Pi's IP address (first non-loopback IPv4)
MY_IP=$(hostname -I | awk '{print $1}')

# Build the peers list = all IPs except mine
PEERS=$(echo "$ALL_IPS" | tr ',' '\n' | grep -v "^${MY_IP}$" | paste -sd ',')

# Derive a node ID from the last octet of the IP (e.g. .150 -> Pi150_Node)
LAST_OCTET=$(echo "$MY_IP" | awk -F. '{print $4}')
NODE_ID="Pi${LAST_OCTET}_Node"

echo "══════════════════════════════════════════════════"
echo "  Detected this Pi:"
echo "    My IP   : $MY_IP"
echo "    Node ID : $NODE_ID"
echo "    Peers   : $PEERS"
echo "    P value : $P_VALUE"
echo "══════════════════════════════════════════════════"

# Fix line endings just in case
sed -i 's/\r$//' leach_launcher.py 2>/dev/null

# Launch
python3 leach_launcher.py \
    --node-id "$NODE_ID" \
    --my-ip "$MY_IP" \
    --peers "$PEERS" \
    --P "$P_VALUE" \
    --round-time "$ROUND_TIME"
