#!/bin/bash
# Pi 1 — LEACH launcher. Elects gateway/node role each round automatically.
sed -i 's/\r$//' leach_launcher.py 2>/dev/null
python3 leach_launcher.py \
    --node-id Pi1_Node \
    --my-ip 10.25.96.150 \
    --peers 10.25.96.151 \
    --P 0.5 \
    --round-time 60
