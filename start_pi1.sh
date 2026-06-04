#!/bin/bash
EPOCH_TIME=60

while true; do
    echo "======================================"
    echo " EPOCH 1: I AM THE GATEWAY (Pi 1)"
    echo "======================================"
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    sleep 1
    timeout $EPOCH_TIME python3 gateway_sink.py --bind-host 0.0.0.0 --bind-port 9999 --profile-port 9998 --decrypt

    echo "======================================"
    echo " EPOCH 2: I AM A NODE (Sending to Pi 2)"
    echo "======================================"
    sudo fuser -k 9999/udp 9998/udp 2>/dev/null
    sleep 1
    timeout $EPOCH_TIME python3 node_ascon_sender.py --node-id Pi1_Node --gateway-host 10.25.96.151 --gateway-port 9999 --profile-port 9998 --length-mode auto
done
