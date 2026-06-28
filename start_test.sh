#!/bin/bash

# ══════════════════════════════════════════════════════════
#  IoT Security System — Single Pi Test Script
#  Runs Gateway + Node on the same device using loopback
#  Each epoch = 60 seconds, then roles switch
# ══════════════════════════════════════════════════════════

EPOCH_TIME=60
EPOCH=1

cleanup() {
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  Shutting down — killing all Python processes..."
    echo "══════════════════════════════════════════════════════"
    kill $GATEWAY_PID $NODE_PID 2>/dev/null
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    echo "  Done."
    exit 0
}

trap cleanup SIGINT SIGTERM

while true; do

    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  EPOCH $EPOCH — Duration: ${EPOCH_TIME}s"
    echo "  Node ID : TestNode${EPOCH}"
    echo "  Gateway : 127.0.0.1:9999  │  Profile: 127.0.0.1:9998"
    echo "══════════════════════════════════════════════════════"
    echo ""

    # Kill anything still holding the ports from last epoch
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    sleep 1

    # Start gateway in background
    timeout $EPOCH_TIME python3 gateway_sink.py \
        --bind-host 0.0.0.0 \
        --bind-port 9999 \
        --profile-port 9998 \
        --decrypt &
    GATEWAY_PID=$!

    # Give gateway 2 seconds to fully start before node connects
    sleep 2

    # Start node in background pointing to loopback
    timeout $EPOCH_TIME python3 node_ascon_sender.py \
        --node-id "TestNode${EPOCH}" \
        --gateway-host 127.0.0.1 \
        --gateway-port 9999 \
        --profile-port 9998 \
        --length-mode auto \
        --urgent-prob 0.20 &
    NODE_PID=$!

    # Wait for the gateway epoch to finish (60 seconds)
    wait $GATEWAY_PID

    # Gateway done — kill node cleanly
    kill $NODE_PID 2>/dev/null
    wait $NODE_PID 2>/dev/null

    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  EPOCH $EPOCH COMPLETE — switching in 2 seconds..."
    echo "══════════════════════════════════════════════════════"
    sleep 2

    # Increment epoch counter (cycles 1 → 2 → 3 → 1 → ...)
    EPOCH=$(( (EPOCH % 3) + 1 ))

done
