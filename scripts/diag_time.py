#!/usr/bin/env python3
"""diag_time.py - compare les horodatages des alertes (fast.log / alert / eve.json) a la capture reseau.

  python3 scripts/diag_time.py results_suri_single/suricata/sip_flood/run_01 results_suri_min/suricata/sip_flood/run_01

Pour chaque run : premiere alerte lue dans le fichier texte et dans eve.json (texte brut), puis temps de
detection calcule depuis chacun, par rapport au 1er paquet malveillant de la capture (reference absolue).
Un temps de detection proche de la valeur attendue (0,40 s scan, 0,79 s flood) = horodatage coherent ;
un ecart de +/- 3600 s = decalage de fuseau horaire.
"""
import importlib.util
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("an", str(here / "analyze_attacks_detection_time.py"))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)

for arg in sys.argv[1:]:
    run = Path(os.path.expanduser(arg))
    meta = json.load(open(run / "metadata.json"))
    scen, ids = meta["scenario"], meta["ids"]
    sid = an.EXPECTED_SID[scen]
    year = int(meta["start_iso"][:4])
    pk = an.malicious_packet_times(run / "capture.pcapng", scen, "192.168.56.102", meta.get("target_ip", "192.168.56.1"))
    t0 = min(pk) if pk else None
    print(f"\n=== {run}  ({ids}, {scen}, sid {sid})")
    print(f"  1er paquet malveillant : epoch {t0:.6f} = {datetime.fromtimestamp(t0).isoformat()} (heure locale de cet ordinateur)")
    logs = run / "ids_logs"
    txt = None
    for name in ["alert", "fast.log", "alert.fast"]:
        p = logs / name
        if p.exists():
            for line in open(p, errors="ignore"):
                if re.search(rf"\[1:{sid}:\d+\]", line):
                    txt = (name, line[:30].strip(), an.parse_alert_time_line(line, year, an.get_tz_from_metadata(run / "metadata.json")))
                    break
        if txt:
            break
    if txt:
        print(f"  {txt[0]:9s}: horodatage brut [{txt[1]}]  -> TTD = {txt[2] - t0:+.3f} s")
    else:
        print("  fichier texte : aucune alerte lue")
    ev = None
    p = logs / "eve.json"
    if p.exists():
        for line in open(p, errors="ignore"):
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("event_type") == "alert" and o.get("alert", {}).get("signature_id") == sid:
                ev = (o["timestamp"], datetime.fromisoformat(o["timestamp"].replace("Z", "+00:00")).timestamp())
                break
    if ev:
        print(f"  eve.json : horodatage brut [{ev[0]}]  -> TTD = {ev[1] - t0:+.3f} s")
    else:
        print("  eve.json : absent ou sans alerte")
