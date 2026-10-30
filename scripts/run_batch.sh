#!/usr/bin/env bash
# run_batch.sh - enchaine automatiquement les runs (IDS alternes pour eviter un biais d'ordre).
# L'attaque est declenchee sur Kali par SSH (cle sans mot de passe obligatoire).
#
# Exemple A (attaques, 10 repetitions) :
#   sudo ./scripts/run_batch.sh --runs 1-10 --results-dir results_v2
# Exemple F (Suricata en un seul thread) :
#   sudo ./scripts/run_batch.sh --runs 1-10 --scenarios "sip_scan sip_flood" --ids suricata \
#        --runmode single --results-dir results_suri_single
# Exemple C (charge de fond 5000 paquets/s depuis une adresse source dediee) :
#   sudo ./scripts/run_batch.sh --runs 1-10 --scenarios "sip_scan sip_flood" --bg-pps 5000 \
#        --bg-src 192.168.56.103 --duration 80 --results-dir results_load_5000
set -euo pipefail

RUNS="1-3"; SCENARIOS="sip_scan sip_brute sip_flood sip_spoof rtp_flood"
RESULTS="results"; DURATION=70; ATTACK_DURATION=60; MULT=1; BG_PPS=0; PPS=""
RULES_SET="local"; RUNMODE="default"; SNORT_CONF="/etc/snort/snort.conf"
SURICATA_CONF="/etc/suricata/suricata.yaml"; IFACE="vboxnet0"; TARGET="192.168.56.1"
KALI="USER@192.168.56.102"; KALI_SCRIPT='~/attack_gen.py'; PAUSE=10; ONLY_IDS="snort suricata"
BENIGN_CMD='cd ~ && sipp 192.168.56.1:5060 -sf ~/uac_auth_rtp.xml -s 2000 -i 192.168.56.102 -p 5062 -au 1000 -ap CHANGE_ME -m 30 -r 0.08 -rp 1000 -l 3 -mp 10000 -nostdin'
CAPTURE_FILTER=""; NO_PCAP=""; BG_SRC=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --scenarios) SCENARIOS="$2"; shift 2 ;;
        --results-dir) RESULTS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --attack-duration) ATTACK_DURATION="$2"; shift 2 ;;
        --mult) MULT="$2"; shift 2 ;;
        --pps) PPS="$2"; shift 2 ;;
        --bg-pps) BG_PPS="$2"; shift 2 ;;
        --bg-src) BG_SRC="$2"; shift 2 ;;
        --rules-set) RULES_SET="$2"; shift 2 ;;
        --runmode) RUNMODE="$2"; shift 2 ;;
        --snort-conf) SNORT_CONF="$2"; shift 2 ;;
        --suricata-conf) SURICATA_CONF="$2"; shift 2 ;;
        --iface) IFACE="$2"; shift 2 ;;
        --target-ip) TARGET="$2"; shift 2 ;;
        --kali) KALI="$2"; shift 2 ;;
        --ids) ONLY_IDS="$2"; shift 2 ;;
        --benign-cmd) BENIGN_CMD="$2"; shift 2 ;;
        --capture-filter) CAPTURE_FILTER="$2"; shift 2 ;;
        --no-pcap) NO_PCAP="--no-pcap"; shift ;;
        --pause) PAUSE="$2"; shift 2 ;;
        *) echo "option inconnue : $1"; sed -n '2,13p' "$0"; exit 1 ;;
    esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${SUDO_USER:-}" ]]; then USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6); else USER_HOME="$HOME"; fi
BASE_DIR="$USER_HOME/ids_voip_v2"
SSH_USER="${SUDO_USER:-$USER}"
SSH="sudo -u $SSH_USER ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new $KALI"
FIRST="${RUNS%-*}"; LAST="${RUNS#*-}"
if [[ -n "$BG_SRC" && -z "$CAPTURE_FILTER" ]]; then CAPTURE_FILTER="host $TARGET and not host $BG_SRC"; fi

echo "[INFO] Test SSH vers $KALI ..."
$SSH "echo ssh-ok" >/dev/null || { echo "[ERREUR] SSH vers $KALI impossible (ssh-copy-id ?)"; exit 1; }

for r in $(seq "$FIRST" "$LAST"); do
    RUN_ID=$(printf "%02d" "$r")
    # alternance de l'ordre des IDS : run impair -> ordre normal, run pair -> ordre inverse
    if (( r % 2 == 1 )); then ORDER="$ONLY_IDS"; else ORDER=$(echo "$ONLY_IDS" | awk '{for(i=NF;i>=1;i--) printf "%s ", $i}'); fi
    for scen in $SCENARIOS; do
        for ids in $ORDER; do
            RUN_PATH="$BASE_DIR/$RESULTS/$ids/$scen/run_$RUN_ID"
            if [[ -f "$RUN_PATH/metadata.json" ]]; then
                if grep -q '"end_epoch": null' "$RUN_PATH/metadata.json"; then
                    echo "[INFO] run partiel $ids/$scen/run_$RUN_ID : supprime puis refait"; rm -rf "$RUN_PATH"
                else
                    echo "[SKIP] $ids/$scen/run_$RUN_ID deja termine"; continue
                fi
            fi
            pkill -x snort 2>/dev/null || true; pkill -x suricata 2>/dev/null || true
            sleep 2
            if [[ "$scen" == "benign" ]]; then
                REMOTE="$SSH '$BENIGN_CMD'"
            else
                PPS_ARG=""; [[ -n "$PPS" ]] && PPS_ARG="--pps $PPS"
                [[ -n "$BG_SRC" ]] && PPS_ARG="$PPS_ARG --bg-src $BG_SRC"
                REMOTE="$SSH 'python3 $KALI_SCRIPT --target $TARGET --mode $scen --duration $ATTACK_DURATION --mult $MULT $PPS_ARG --bg-pps $BG_PPS'"
            fi
            echo; echo "########## run $RUN_ID | $ids | $scen | results=$RESULTS ##########"
            "$HERE/collect_run_manual.sh" --ids "$ids" --scenario "$scen" --run "$RUN_ID" \
                --duration "$DURATION" --iface "$IFACE" --target-ip "$TARGET" --results-dir "$RESULTS" \
                --runmode "$RUNMODE" --rules-set "$RULES_SET" --snort-conf "$SNORT_CONF" \
                --suricata-conf "$SURICATA_CONF" --remote-cmd "$REMOTE" --start-delay 5 \
                ${CAPTURE_FILTER:+--capture-filter "$CAPTURE_FILTER"} $NO_PCAP
            sleep "$PAUSE"
        done
    done
done
echo "[OK] Batch termine."
