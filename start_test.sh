#!/bin/bash
EPOCH_TIME=60

while true; do
    echo "======================================"
    echo " EPOCH 1: GATEWAY MODE"
    echo "======================================"
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    sleep 1
    timeout $EPOCH_TIME python3 gateway_sink.py --bind-host 0.0.0.0 --bind-port 9999 --profile-port 9998 --decrypt &
    GATEWAY_PID=$!
    sleep 2
    timeout $EPOCH_TIME python3 node_ascon_sender.py --node-id TestNode --gateway-host 127.0.0.1 --gateway-port 9999 --profile-port 9998 --length-mode auto &
    NODE_PID=$!
    wait $GATEWAY_PID
    kill $NODE_PID 2>/dev/null

    echo "======================================"
    echo " EPOCH 2: SWITCHING ROLES"
    echo "======================================"
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    sleep 1
    timeout $EPOCH_TIME python3 gateway_sink.py --bind-host 0.0.0.0 --bind-port 9999 --profile-port 9998 --decrypt &
    GATEWAY_PID=$!
    sleep 2
    timeout $EPOCH_TIME python3 node_ascon_sender.py --node-id TestNode2 --gateway-host 127.0.0.1 --gateway-port 9999 --profile-port 9998 --length-mode auto &
    NODE_PID=$!
    wait $GATEWAY_PID
    kill $NODE_PID 2>/dev/null
done
