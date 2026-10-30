#!/usr/bin/env python3
"""analyze_attacks_detection_time.py (v2)

Calcule taux de detection, temps de detection (TTD), ressources, paquets perdus.
Nouveautes : --results-dir, ressources limitees a la fenetre d'attaque (cpu_avg_attack,
mem_avg_attack_mb), nb de threads, paquets recus/perdus (Suricata stats.log, Snort stdout).
Les colonnes de la v1 sont conservees a l'identique.
"""
import argparse
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import pandas as pd

EXPECTED_SID = {
    "sip_scan": 1000003, "sip_brute": 1000005, "sip_flood": 1000006,
    "rtp_flood": 1000007, "sip_spoof": 1000008,
}

ATTACK_FILTERS = {
    "sip_scan": 'ip.src == {attacker} && ip.dst == {target} && sip.Method == "OPTIONS"',
    "sip_brute": 'ip.src == {attacker} && ip.dst == {target} && sip.Method == "REGISTER"',
    "sip_flood": 'ip.src == {attacker} && ip.dst == {target} && sip.Method == "INVITE"',
    "sip_spoof": 'ip.src == {attacker} && ip.dst == {target} && sip.Method == "INVITE"',
    "rtp_flood": "ip.src == {attacker} && ip.dst == {target} && udp.dstport >= 10000 && udp.dstport <= 20000",
}


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def get_year_from_metadata(meta_path):
    with open(meta_path) as f:
        meta = json.load(f)
    start_iso = meta.get("start_iso", "")
    if start_iso:
        return datetime.fromisoformat(start_iso.replace("Z", "+00:00")).year
    return datetime.now().year


def get_tz_from_metadata(meta_path):
    """Fuseau horaire du run (decalage ecrit dans start_iso) : l'analyse ne depend plus du fuseau actuel de la machine."""
    with open(meta_path) as f:
        meta = json.load(f)
    try:
        return datetime.fromisoformat(meta.get("start_iso", "").replace("Z", "+00:00")).tzinfo
    except ValueError:
        return None


def parse_alert_time_line(line, year, tz=None):
    # Snort : "MM/DD-HH:MM:SS.ffffff" ; Suricata (fast.log) : "MM/DD/YYYY-HH:MM:SS.ffffff"
    # Ces heures sont locales, sans fuseau : tz (fuseau du run) permet de les convertir correctement.
    m = re.search(r"^(\d{2})/(\d{2})(?:/(\d{4}))?-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", line)
    if not m:
        return None
    month, day = int(m.group(1)), int(m.group(2))
    if m.group(3):
        year = int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    micro = m.group(7)
    microsecond = int((micro + "000000")[:6]) if micro else 0
    try:
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz).timestamp()
    except ValueError:
        return None


def parse_alerts(log_dir, expected_sid, year, tz=None):
    log_dir = Path(log_dir)
    text_times, eve_times = [], []
    sid_regex = re.compile(r"\[1:(\d+):\d+\]")
    for name in ["alert", "fast.log", "alert.fast"]:
        path = log_dir / name
        if not path.exists():
            continue
        with open(path, errors="ignore") as f:
            for line in f:
                m_sid = sid_regex.search(line)
                if not m_sid or int(m_sid.group(1)) != expected_sid:
                    continue
                ts = parse_alert_time_line(line, year, tz)
                if ts is not None:
                    text_times.append(ts)
    eve_path = log_dir / "eve.json"
    if eve_path.exists():
        with open(eve_path, errors="ignore") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("event_type") != "alert":
                    continue
                alert = obj.get("alert", {})
                if int(alert.get("signature_id", -1)) != expected_sid:
                    continue
                ts_str = obj.get("timestamp")
                if not ts_str:
                    continue
                try:
                    eve_times.append(datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp())
                except ValueError:
                    continue
    # eve.json (horodatage avec fuseau) est utilise quand il existe ; sinon fast.log / alert (evite de compter deux fois)
    return sorted(eve_times if eve_times else text_times)


def malicious_packet_times(pcap_file, scenario, attacker_ip, target_ip):
    if not Path(pcap_file).exists():
        return []
    display_filter = ATTACK_FILTERS[scenario].format(attacker=attacker_ip, target=target_ip)
    out = run_cmd(["tshark", "-r", str(pcap_file), "-Y", display_filter, "-T", "fields", "-e", "frame.time_epoch"])
    times = []
    for line in out.splitlines():
        try:
            times.append(float(line.strip()))
        except ValueError:
            pass
    return times


def first_malicious_packet_time(pcap_file, scenario, attacker_ip, target_ip):  # compat v1
    t = malicious_packet_times(pcap_file, scenario, attacker_ip, target_ip)
    return min(t) if t else None


def compute_resource_stats(resource_csv, win=None):
    empty = {"cpu_avg": None, "cpu_max": None, "mem_avg_mb": None, "mem_max_mb": None,
             "cpu_avg_attack": None, "mem_avg_attack_mb": None, "threads_max": None}
    if not os.path.exists(resource_csv):
        return empty
    df = pd.read_csv(resource_csv)
    if df.empty:
        return empty
    res = {
        "cpu_avg": df["cpu_percent"].mean(), "cpu_max": df["cpu_percent"].max(),
        "mem_avg_mb": df["memory_rss_mb"].mean(), "mem_max_mb": df["memory_rss_mb"].max(),
        "cpu_avg_attack": None, "mem_avg_attack_mb": None,
        "threads_max": df["num_threads"].max() if "num_threads" in df.columns else None,
    }
    if win and win[0] is not None and win[1] is not None:
        sub = df[(df["timestamp_epoch"] >= win[0]) & (df["timestamp_epoch"] <= win[1] + 1.0)]
        if not sub.empty:
            res["cpu_avg_attack"] = sub["cpu_percent"].mean()
            res["mem_avg_attack_mb"] = sub["memory_rss_mb"].mean()
    return res


def parse_drops(log_dir, ids):
    """Retourne (paquets_recus, paquets_perdus) ou (None, None)."""
    log_dir = Path(log_dir)
    recv = drop = None
    if ids == "suricata":
        # 1) ligne ecrite a l'arret dans la sortie standard : "device: vboxnet0: packets: N, drops: M (x%)"
        p_out = log_dir / "suricata_stdout.log"
        if p_out.exists():
            rx_dev = re.compile(r"packets:\s*(\d+),\s*drops:\s*(\d+)")
            with open(p_out, errors="ignore") as f:
                for line in f:
                    if "device:" in line:
                        m = rx_dev.search(line)
                        if m:
                            recv, drop = int(m.group(1)), int(m.group(2))
        # 2) a defaut, stats.log (les compteurs a zero y sont omis : kernel_drops absent = 0 perte)
        if recv is None:
            p = log_dir / "stats.log"
            if p.exists():
                rx = re.compile(r"^(capture\.kernel_packets|capture\.kernel_drops)\s*\|\s*Total\s*\|\s*(\d+)")
                with open(p, errors="ignore") as f:
                    for line in f:
                        m = rx.match(line.strip())
                        if m:
                            if m.group(1).endswith("packets"):
                                recv = int(m.group(2))
                            else:
                                drop = int(m.group(2))
                if recv is not None and drop is None:
                    drop = 0
    elif ids == "snort":
        p = log_dir / "snort_stdout.log"
        if p.exists():
            with open(p, errors="ignore") as f:
                for line in f:
                    m = re.match(r"^\s*Received:\s+(\d+)", line)
                    if m:
                        recv = int(m.group(1))
                    m = re.match(r"^\s*Dropped:\s+(\d+)", line)
                    if m:
                        drop = int(m.group(1))
    return recv, drop


def analyze(base_dir, attacker_ip, results_dir="results"):
    base = Path(base_dir)
    rows = []
    for meta_path in base.glob(f"{results_dir}/*/*/run_*/metadata.json"):
        run_dir = meta_path.parent
        with open(meta_path) as f:
            meta = json.load(f)
        ids, scenario, run_id = meta["ids"], meta["scenario"], meta["run_id"]
        target_ip = meta.get("target_ip", "192.168.56.1")
        if scenario not in EXPECTED_SID:
            continue
        expected_sid = EXPECTED_SID[scenario]
        year = get_year_from_metadata(meta_path)
        tz = get_tz_from_metadata(meta_path)
        log_dir = run_dir / "ids_logs"
        pkt_times = malicious_packet_times(run_dir / "capture.pcapng", scenario, attacker_ip, target_ip)
        first_pkt_ts = min(pkt_times) if pkt_times else None
        last_pkt_ts = max(pkt_times) if pkt_times else None
        alert_times = parse_alerts(log_dir, expected_sid, year, tz)
        first_alert_ts = alert_times[0] if alert_times else None
        detected = 1 if first_alert_ts is not None else 0
        detection_time_s = None
        if first_pkt_ts is not None and first_alert_ts is not None:
            detection_time_s = first_alert_ts - first_pkt_ts
        res = compute_resource_stats(run_dir / "resources.csv", (first_pkt_ts, last_pkt_ts))
        recv, drop = parse_drops(log_dir, ids)
        drop_pct = (100.0 * drop / recv) if (recv and drop is not None) else None
        rows.append({
            "ids": ids, "scenario": scenario, "run_id": run_id, "expected_sid": expected_sid,
            "first_malicious_packet_epoch": first_pkt_ts, "first_alert_epoch": first_alert_ts,
            "detection_time_s": detection_time_s, "detected": detected,
            "false_negative": 0 if detected else 1,
            "alert_count_expected_sid": len(alert_times),
            "cpu_avg": res["cpu_avg"], "cpu_max": res["cpu_max"],
            "mem_avg_mb": res["mem_avg_mb"], "mem_max_mb": res["mem_max_mb"],
            "cpu_avg_attack": res["cpu_avg_attack"], "mem_avg_attack_mb": res["mem_avg_attack_mb"],
            "threads_max": res["threads_max"],
            "pkts_received": recv, "pkts_dropped": drop, "drop_pct": drop_pct,
            "rules_set": meta.get("rules_set"), "suricata_runmode": meta.get("suricata_runmode"),
            "run_dir": str(run_dir),
        })

    out_dir = base / ("analysis" if results_dir == "results" else f"analysis_{results_dir}")
    out_dir.mkdir(exist_ok=True)
    df = pd.DataFrame(rows)
    by_run_csv = out_dir / "attacks_detection_by_run.csv"
    summary_csv = out_dir / "attacks_detection_summary.csv"
    df.to_csv(by_run_csv, index=False)

    summary_rows = []
    if not df.empty:
        for (ids, scenario), g in df.groupby(["ids", "scenario"]):
            tp, fn = g["detected"].sum(), g["false_negative"].sum()
            valid_dt = g["detection_time_s"].dropna()
            summary_rows.append({
                "ids": ids, "scenario": scenario, "runs": len(g),
                "true_positives": tp, "false_negatives": fn,
                "detection_rate_percent": tp / (tp + fn) * 100 if (tp + fn) > 0 else None,
                "detection_time_avg_s": valid_dt.mean() if not valid_dt.empty else None,
                "detection_time_min_s": valid_dt.min() if not valid_dt.empty else None,
                "detection_time_max_s": valid_dt.max() if not valid_dt.empty else None,
                "alerts_expected_sid_total": g["alert_count_expected_sid"].sum(),
                "cpu_avg": g["cpu_avg"].mean(), "cpu_max": g["cpu_max"].max(),
                "mem_avg_mb": g["mem_avg_mb"].mean(), "mem_max_mb": g["mem_max_mb"].max(),
                "cpu_avg_attack": g["cpu_avg_attack"].mean(),
                "mem_avg_attack_mb": g["mem_avg_attack_mb"].mean(),
                "drop_pct_mean": g["drop_pct"].mean(),
            })
    df_summary = pd.DataFrame(summary_rows)
    df_summary.to_csv(summary_csv, index=False)
    print(f"[OK] Resultats par run : {by_run_csv}")
    print(f"[OK] Resume attaques   : {summary_csv}")
    if summary_rows:
        print(df_summary.to_string(index=False))
    else:
        print("[ATTENTION] Aucun run d'attaque trouve.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze IDS detection rate and detection time.")
    parser.add_argument("--base-dir", default=os.path.expanduser("~/ids_voip_v2"))
    parser.add_argument("--attacker-ip", default="192.168.56.102")
    parser.add_argument("--results-dir", default="results", help="results (defaut), results_load_5000, ...")
    args = parser.parse_args()
    analyze(args.base_dir, args.attacker_ip, args.results_dir)
