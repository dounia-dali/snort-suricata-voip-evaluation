#!/usr/bin/env bash
set -euo pipefail

IDS="snort"
SCENARIO="benign"
RUN_ID="01"
DURATION="300"
IFACE="vboxnet0"
TARGET_IP="192.168.56.1"

if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi

BASE_DIR="$USER_HOME/ids_voip_experiment"

SNORT_CONF="/etc/snort/snort.conf"
SURICATA_CONF="/etc/suricata/suricata.yaml"

usage() {
    echo "Usage:"
    echo "  sudo $0 --ids snort|suricata|baseline --scenario benign|sip_scan|sip_brute|sip_flood|sip_spoof|rtp_flood --run 01 --duration 300 --iface vboxnet0"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ids) IDS="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --run) RUN_ID="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --target-ip) TARGET_IP="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [[ "$IDS" != "snort" && "$IDS" != "suricata" && "$IDS" != "baseline" ]]; then
    usage
fi

RUN_DIR="$BASE_DIR/results/${IDS}/${SCENARIO}/run_${RUN_ID}"
LOG_DIR="$RUN_DIR/ids_logs"
PCAP_FILE="$RUN_DIR/capture.pcapng"
RESOURCE_FILE="$RUN_DIR/resources.csv"
META_FILE="$RUN_DIR/metadata.json"

mkdir -p "$LOG_DIR"

echo "=================================================="
echo "[INFO] Vérification d'Asterisk"
echo "=================================================="

if systemctl is-active --quiet asterisk; then
    echo "[OK] Asterisk est actif."
else
    echo "[INFO] Asterisk n'est pas actif. Démarrage..."
    systemctl start asterisk
    sleep 2
fi

if systemctl is-active --quiet asterisk; then
    echo "[OK] Asterisk fonctionne."
else
    echo "[ERREUR] Asterisk n'a pas pu démarrer."
    exit 1
fi

echo "=================================================="
echo "[INFO] Run expérimental"
echo "=================================================="
echo "[INFO] IDS       : $IDS"
echo "[INFO] Scénario  : $SCENARIO"
echo "[INFO] Run       : $RUN_ID"
echo "[INFO] Durée     : $DURATION secondes"
echo "[INFO] Interface : $IFACE"
echo "[INFO] IP cible  : $TARGET_IP"
echo "[INFO] Dossier   : $RUN_DIR"
echo "=================================================="

IDS_PID=""
MONITOR_PID=""
TSHARK_PID=""

cleanup() {
    echo ""
    echo "[INFO] Arrêt de la collecte..."

    if [[ -n "$TSHARK_PID" ]]; then
        kill "$TSHARK_PID" 2>/dev/null || true
        wait "$TSHARK_PID" 2>/dev/null || true
    fi

    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi

    if [[ -n "$IDS_PID" ]]; then
        kill "$IDS_PID" 2>/dev/null || true
        wait "$IDS_PID" 2>/dev/null || true
    fi

    echo "[INFO] Collecte terminée."
}
trap cleanup EXIT

START_EPOCH=$(date +%s)
START_ISO=$(date --iso-8601=seconds)

cat > "$META_FILE" <<EOF
{
  "ids": "$IDS",
  "scenario": "$SCENARIO",
  "run_id": "$RUN_ID",
  "duration_seconds": $DURATION,
  "interface": "$IFACE",
  "target_ip": "$TARGET_IP",
  "start_epoch": $START_EPOCH,
  "start_iso": "$START_ISO",
  "attack_trigger_mode": "manual_from_kali",
  "asterisk_checked": true,
  "benign_generator": "SIPp with RTP received from Asterisk, without rtp_echo",
  "snort_rules": "/etc/snort/rules/local.rules",
  "suricata_rules": "/var/lib/suricata/rules/local.rules",
  "end_epoch": null,
  "end_iso": null
}
EOF

echo "[INFO] Démarrage de la capture TShark..."
tshark -i "$IFACE" -f "host $TARGET_IP" -w "$PCAP_FILE" >/dev/null 2>&1 &
TSHARK_PID=$!

sleep 2

if [[ "$IDS" == "snort" ]]; then
    echo "[INFO] Démarrage de Snort..."
    snort -q -A fast -i "$IFACE" -c "$SNORT_CONF" -l "$LOG_DIR" &
    IDS_PID=$!

elif [[ "$IDS" == "suricata" ]]; then
    echo "[INFO] Démarrage de Suricata..."
    suricata -c "$SURICATA_CONF" -i "$IFACE" -l "$LOG_DIR" -k none >/dev/null 2>&1 &
    IDS_PID=$!

else
    echo "[INFO] Mode baseline : aucun IDS lancé."
fi

sleep 3

if [[ "$IDS" != "baseline" ]]; then
    echo "[INFO] Monitoring CPU/RAM du PID $IDS_PID..."
    "$BASE_DIR/scripts/monitor_pid.py" --pid "$IDS_PID" --out "$RESOURCE_FILE" --interval 1 &
    MONITOR_PID=$!
fi

echo ""
echo "=================================================="
echo "[ACTION REQUISE]"
echo "=================================================="

if [[ "$SCENARIO" == "benign" ]]; then
    echo "Depuis Kali :"
    echo "  - Lance SIPp avec RTP reçu depuis Asterisk."
    echo "  - Ne lance aucune attaque."
else
    echo "Depuis Kali :"
    echo "  - Lance manuellement l'attaque : $SCENARIO."
    echo "  - Ne lance qu'une seule attaque pendant ce run."
fi

echo ""
if [[ "$IDS" == "snort" ]]; then
    echo "Alertes temps réel : sudo tail -F $LOG_DIR/alert"
elif [[ "$IDS" == "suricata" ]]; then
    echo "Alertes temps réel : sudo tail -F $LOG_DIR/fast.log"
fi
echo ""
echo "La collecte dure $DURATION secondes."
echo "=================================================="
echo ""

sleep "$DURATION"

END_EPOCH=$(date +%s)
END_ISO=$(date --iso-8601=seconds)

python3 - <<PY
import json
path = "$META_FILE"
with open(path) as f:
    data = json.load(f)
data["end_epoch"] = $END_EPOCH
data["end_iso"] = "$END_ISO"
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PY

echo "[INFO] Run terminé : $RUN_DIR"
