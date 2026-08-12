#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Attack Test Menu — run the 3 threat scenarios from the paper
# ══════════════════════════════════════════════════════════════════

# Set the cluster head IP (the Pi currently acting as gateway)
read -p "Enter the CLUSTER HEAD IP (the gateway Pi): " TARGET

echo ""
echo "Which attack do you want to run?"
echo "  1) SYN Flood DoS        (raises CTS threat score)"
echo "  2) Injection Attack     (forged/oversized fragments → WFSS)"
echo "  3) Packet Replay        (duplicate + stale → Replay Count)"
echo ""
read -p "Choice [1-3]: " CHOICE

case $CHOICE in
  1)
    echo "Running SYN Flood against $TARGET:22 for 30s..."
    python3 attack_syn_flood.py --target "$TARGET" --port 22 --duration 30
    ;;
  2)
    echo "Injection mode?"
    echo "  a) forged     (bad ciphertext → decrypt fail)"
    echo "  b) oversized  (wrong fragment size → size mismatch)"
    echo "  c) announce   (missing fragments → integrity shortfall)"
    read -p "Choice [a/b/c]: " M
    case $M in
      a) MODE="forged" ;;
      b) MODE="oversized" ;;
      c) MODE="announce" ;;
      *) MODE="forged" ;;
    esac
    python3 attack_injection.py --target "$TARGET" --port 9999 --node-id Pi2_Node --mode "$MODE"
    ;;
  3)
    python3 attack_replay.py --target "$TARGET" --port 9999 --node-id Pi2_Node --replays 5
    ;;
  *)
    echo "Invalid choice."
    ;;
esac
