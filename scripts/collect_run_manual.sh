#!/usr/bin/env bash
# collect_run_manual.sh (v2)
# Nouveautes par rapport a la v1 :
#  --results-dir   dossier de sortie (results, results_load_5000, ...)
#  --runmode       Suricata : default | workers | single (test multithreading)
#  --snort-conf / --suricata-conf   configurations alternatives (jeux de regles)
#  --rules-set     etiquette libre enregistree dans metadata.json
#  --remote-cmd    commande lancee automatiquement (ex. ssh vers Kali) apres --start-delay s
#  --capture-filter / --no-pcap     filtre ou desactivation de la capture TShark
#  Attente reelle de la fin du chargement des regles (indispensable avec 10k+ regles)
#  Sorties IDS conservees (snort_stdout.log / suricata_stdout.log) -> paquets perdus
#  Arret propre des IDS (SIGINT Snort / SIGTERM Suricata) pour obtenir les statistiques finales
#  Refus d'ecraser un run existant (sauf --force)
#  start_epoch = debut de la fenetre de mesure (IDS pret), en secondes decimales
set -euo pipefail

IDS="snort"; SCENARIO="benign"; RUN_ID="01"; DURATION="300"
IFACE="vboxnet0"; TARGET_IP="192.168.56.1"
RESULTS_NAME="results"; RUNMODE="default"; RULES_SET="local"
NO_PCAP=0; CAPTURE_FILTER=""; REMOTE_CMD=""; START_DELAY=5
READY_TIMEOUT=240; FORCE=0
SNORT_CONF="/etc/snort/snort.conf"
SURICATA_CONF="/etc/suricata/suricata.yaml"

if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi
BASE_DIR="$USER_HOME/ids_voip_v2"

usage() {
    cat <<USAGE
Usage:
  sudo $0 --ids snort|suricata|baseline --scenario benign|sip_scan|sip_brute|sip_flood|sip_spoof|rtp_flood \\
          --run 01 --duration 70 --iface vboxnet0 --target-ip 192.168.56.1 \\
          [--results-dir results] [--runmode default|workers|single] [--rules-set local] \\
          [--snort-conf FILE] [--suricata-conf FILE] [--remote-cmd "CMD"] [--start-delay 5] \\
          [--capture-filter "BPF"] [--no-pcap] [--ready-timeout 240] [--force]
USAGE
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
        --results-dir) RESULTS_NAME="$2"; shift 2 ;;
        --runmode) RUNMODE="$2"; shift 2 ;;
        --rules-set) RULES_SET="$2"; shift 2 ;;
        --snort-conf) SNORT_CONF="$2"; shift 2 ;;
        --suricata-conf) SURICATA_CONF="$2"; shift 2 ;;
        --remote-cmd) REMOTE_CMD="$2"; shift 2 ;;
        --start-delay) START_DELAY="$2"; shift 2 ;;
        --capture-filter) CAPTURE_FILTER="$2"; shift 2 ;;
        --ready-timeout) READY_TIMEOUT="$2"; shift 2 ;;
        --no-pcap) NO_PCAP=1; shift ;;
        --force) FORCE=1; shift ;;
        *) usage ;;
    esac
done

if [[ "$IDS" != "snort" && "$IDS" != "suricata" && "$IDS" != "baseline" ]]; then usage; fi
[[ -z "$CAPTURE_FILTER" ]] && CAPTURE_FILTER="host $TARGET_IP"

RUN_DIR="$BASE_DIR/$RESULTS_NAME/${IDS}/${SCENARIO}/run_${RUN_ID}"
LOG_DIR="$RUN_DIR/ids_logs"
PCAP_FILE="$RUN_DIR/capture.pcapng"
RESOURCE_FILE="$RUN_DIR/resources.csv"
META_FILE="$RUN_DIR/metadata.json"

if [[ -e "$META_FILE" && "$FORCE" -eq 0 ]]; then
    echo "[ERREUR] $RUN_DIR existe deja (utilise --force pour ecraser)."
    exit 1
fi
rm -rf "$RUN_DIR"
mkdir -p "$LOG_DIR"

echo "=================================================="
echo "[INFO] Verification d'Asterisk"
if ! systemctl is-active --quiet asterisk; then
    echo "[INFO] Asterisk inactif, demarrage..."
    systemctl start asterisk
    sleep 2
fi
systemctl is-active --quiet asterisk || { echo "[ERREUR] Asterisk n'a pas pu demarrer."; exit 1; }
echo "[OK] Asterisk fonctionne."
echo "=================================================="
echo "[INFO] IDS=$IDS scenario=$SCENARIO run=$RUN_ID duree=${DURATION}s iface=$IFACE"
echo "[INFO] results=$RESULTS_NAME runmode=$RUNMODE rules-set=$RULES_SET"
echo "[INFO] dossier: $RUN_DIR"
echo "=================================================="

IDS_PID=""; MONITOR_PID=""; TSHARK_PID=""; REMOTE_PID=""

poke_interface() {
    # emet un paquet de diffusion sur l'interface pour debloquer Snort (libpcap en attente de trafic)
    ping -b -c 1 -W 1 -I "$IFACE" "${TARGET_IP%.*}.255" >/dev/null 2>&1 || true
}

stop_ids() {
    [[ -z "$IDS_PID" ]] && return 0
    if kill -0 "$IDS_PID" 2>/dev/null; then
        # Snort : SIGINT (affiche les statistiques finales) ; Suricata : SIGTERM (ecrit stats.log)
        if [[ "$IDS" == "snort" ]]; then kill -INT "$IDS_PID" 2>/dev/null || true
        else kill -TERM "$IDS_PID" 2>/dev/null || true; fi
        for _ in $(seq 1 15); do
            kill -0 "$IDS_PID" 2>/dev/null || break
            if [[ "$IDS" == "snort" ]]; then poke_interface; fi
            sleep 1
        done
        if kill -0 "$IDS_PID" 2>/dev/null; then kill -TERM "$IDS_PID" 2>/dev/null || true; fi
        for _ in $(seq 1 15); do
            kill -0 "$IDS_PID" 2>/dev/null || break
            if [[ "$IDS" == "snort" ]]; then poke_interface; fi
            sleep 1
        done
        kill -9 "$IDS_PID" 2>/dev/null || true
    fi
    wait "$IDS_PID" 2>/dev/null || true
}

cleanup() {
    echo ""
    echo "[INFO] Arret de la collecte..."
    [[ -n "$REMOTE_PID" ]] && { kill "$REMOTE_PID" 2>/dev/null || true; wait "$REMOTE_PID" 2>/dev/null || true; }
    [[ -n "$MONITOR_PID" ]] && { kill "$MONITOR_PID" 2>/dev/null || true; wait "$MONITOR_PID" 2>/dev/null || true; }
    stop_ids
    [[ -n "$TSHARK_PID" ]] && { kill "$TSHARK_PID" 2>/dev/null || true; wait "$TSHARK_PID" 2>/dev/null || true; }
    # sous forte charge, eve.json peut atteindre plusieurs centaines de Mo (un evenement par message SIP) :
    # au-dela du seuil, on ne conserve que les evenements d'alerte, seuls utilises par l'analyse
    # (la mesure CPU/RAM de la configuration par defaut n'est pas modifiee : le filtrage a lieu apres l'arret)
    EVE_FILE="$LOG_DIR/eve.json"
    if [[ -f "$EVE_FILE" ]] && (( $(stat -c %s "$EVE_FILE") > ${EVE_KEEP_ALERTS_OVER:-52428800} )); then
        grep -E '"event_type": ?"alert"' "$EVE_FILE" > "$EVE_FILE.alerts" || true
        mv "$EVE_FILE.alerts" "$EVE_FILE"
    fi
    # les fichiers crees par sudo appartiennent a root : on les rend a l'utilisateur (analyse sans sudo)
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$BASE_DIR/$RESULTS_NAME" 2>/dev/null || true
    fi
    echo "[INFO] Collecte terminee."
}
trap cleanup EXIT

write_meta() {  # $1 = end_epoch ou "null"
    META_FILE="$META_FILE" IDS="$IDS" SCENARIO="$SCENARIO" RUN_ID="$RUN_ID" DURATION="$DURATION" \
    IFACE="$IFACE" TARGET_IP="$TARGET_IP" START_EPOCH="$START_EPOCH" START_ISO="$START_ISO" \
    READY_EPOCH="$READY_EPOCH" END_EPOCH="$1" RESULTS_NAME="$RESULTS_NAME" RUNMODE="$RUNMODE" \
    RULES_SET="$RULES_SET" REMOTE_CMD="$REMOTE_CMD" SNORT_CONF="$SNORT_CONF" \
    SURICATA_CONF="$SURICATA_CONF" CAPTURE_FILTER="$CAPTURE_FILTER" NO_PCAP="$NO_PCAP" \
    python3 - <<'PY'
import json, os
from datetime import datetime
e = os.environ
end = None if e["END_EPOCH"] == "null" else float(e["END_EPOCH"])
meta = {
    "ids": e["IDS"], "scenario": e["SCENARIO"], "run_id": e["RUN_ID"],
    "duration_seconds": int(e["DURATION"]), "interface": e["IFACE"], "target_ip": e["TARGET_IP"],
    "start_epoch": float(e["START_EPOCH"]), "start_iso": e["START_ISO"],
    "ids_ready_epoch": float(e["READY_EPOCH"]),
    "end_epoch": end,
    "end_iso": datetime.fromtimestamp(end).isoformat() if end else None,
    "results_dir": e["RESULTS_NAME"], "suricata_runmode": e["RUNMODE"], "rules_set": e["RULES_SET"],
    "remote_cmd": e["REMOTE_CMD"], "snort_conf": e["SNORT_CONF"], "suricata_conf": e["SURICATA_CONF"],
    "capture_filter": e["CAPTURE_FILTER"], "pcap_disabled": e["NO_PCAP"] == "1",
    "attack_trigger_mode": "remote_cmd" if e["REMOTE_CMD"] else "manual_from_kali",
}
with open(e["META_FILE"], "w") as f:
    json.dump(meta, f, indent=2)
PY
}

if [[ "$NO_PCAP" -eq 0 ]]; then
    echo "[INFO] Demarrage de la capture TShark..."
    tshark -i "$IFACE" -f "$CAPTURE_FILTER" -w "$PCAP_FILE" >/dev/null 2>&1 &
    TSHARK_PID=$!
    sleep 2
fi

ids_ready() {
    # pret si le texte attendu apparait dans la sortie standard, dans suricata.log, ou si Suricata a
    # ecrit sa premiere statistique (stats.log contient "uptime") : la sortie standard peut etre
    # tamponnee (non ecrite en direct) quand elle est redirigee vers un fichier
    grep -q -E "$READY_PATTERN" "$READY_LOG" 2>/dev/null && return 0
    if [[ "$IDS" == "suricata" ]]; then
        grep -q -i -E "engine started" "$LOG_DIR/suricata.log" 2>/dev/null && return 0
        grep -q "uptime" "$LOG_DIR/stats.log" 2>/dev/null && return 0
    fi
    return 1
}

READY_PATTERN=""
if [[ "$IDS" == "snort" ]]; then
    echo "[INFO] Demarrage de Snort ($SNORT_CONF)..."
    snort -A fast -i "$IFACE" -c "$SNORT_CONF" -l "$LOG_DIR" > "$LOG_DIR/snort_stdout.log" 2>&1 &
    IDS_PID=$!
    READY_LOG="$LOG_DIR/snort_stdout.log"; READY_PATTERN="Commencing packet processing"
elif [[ "$IDS" == "suricata" ]]; then
    echo "[INFO] Demarrage de Suricata ($SURICATA_CONF, runmode=$RUNMODE)..."
    SURI_ARGS=(-c "$SURICATA_CONF" -i "$IFACE" -l "$LOG_DIR" -k none)
    if [[ "$RUNMODE" != "default" ]]; then SURI_ARGS+=(--runmode "$RUNMODE"); fi
    SURI_CMD=(suricata)
    if command -v stdbuf >/dev/null 2>&1; then SURI_CMD=(stdbuf -oL -eL suricata); fi
    "${SURI_CMD[@]}" "${SURI_ARGS[@]}" > "$LOG_DIR/suricata_stdout.log" 2>&1 &
    IDS_PID=$!
    READY_LOG="$LOG_DIR/suricata_stdout.log"; READY_PATTERN="[Ee]ngine started"
else
    echo "[INFO] Mode baseline : aucun IDS lance."
fi

if [[ -n "$READY_PATTERN" ]]; then
    echo "[INFO] Attente de la fin du chargement des regles (max ${READY_TIMEOUT}s)..."
    waited=0; ready=0
    while (( waited < READY_TIMEOUT )); do
        if ids_ready; then ready=1; break; fi
        if ! kill -0 "$IDS_PID" 2>/dev/null; then
            echo "[ERREUR] L'IDS s'est arrete pendant le demarrage :"; tail -n 20 "$READY_LOG"; exit 1
        fi
        sleep 1; waited=$((waited+1))
    done
    if [[ "$ready" -ne 1 ]]; then echo "[ERREUR] IDS non pret apres ${READY_TIMEOUT}s."; exit 1; fi
    echo "[OK] IDS pret apres ${waited}s."
    sleep 2
fi

START_EPOCH=$(date +%s.%N); START_ISO=$(date --iso-8601=seconds); READY_EPOCH="$START_EPOCH"
write_meta null

if [[ "$IDS" != "baseline" ]]; then
    echo "[INFO] Monitoring CPU/RAM du PID $IDS_PID..."
    python3 "$BASE_DIR/scripts/monitor_pid.py" --pid "$IDS_PID" --out "$RESOURCE_FILE" --interval 1 &
    MONITOR_PID=$!
fi

echo ""
echo "=================================================="
if [[ -n "$REMOTE_CMD" ]]; then
    echo "[AUTO] Commande distante dans ${START_DELAY}s : $REMOTE_CMD"
    ( sleep "$START_DELAY"; bash -c "$REMOTE_CMD" ) > "$RUN_DIR/remote_cmd.log" 2>&1 &
    REMOTE_PID=$!
else
    printf '\a'; sleep 0.3; printf '\a'; sleep 0.3; printf '\a'
    echo ""
    echo "################################################################"
    echo "#  GO !  Lance MAINTENANT sur Kali : $SCENARIO  (une seule attaque)"
    echo "#  Fais-le dans les 8 premieres secondes (l'attaque dure 60 s)."
    echo "################################################################"
fi
if [[ "$IDS" == "snort" ]]; then echo "Alertes : sudo tail -F $LOG_DIR/alert"
elif [[ "$IDS" == "suricata" ]]; then echo "Alertes : sudo tail -F $LOG_DIR/fast.log"; fi
echo "La collecte dure $DURATION secondes."
echo "=================================================="

sleep "$DURATION"

END_EPOCH=$(date +%s.%N)
write_meta "$END_EPOCH"
echo "[INFO] Run termine : $RUN_DIR"
