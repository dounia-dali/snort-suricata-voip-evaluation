#!/usr/bin/env python3
"""load_rates.py - debit reel du trafic de fond envoye par attack_gen.py pendant chaque run.

  python3 scripts/load_rates.py --results-dir results_load_5000
Lit les remote_cmd.log (resume JSON d'attack_gen.py) et affiche, par IDS et scenario,
le debit moyen reellement atteint (paquets/s) face au debit demande.
"""
import argparse
import json
import os
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--base-dir", default=os.path.expanduser("~/ids_voip_v2"))
ap.add_argument("--results-dir", required=True)
a = ap.parse_args()

rows = {}
for log in Path(a.base_dir).glob(f"{a.results_dir}/*/*/run_*/remote_cmd.log"):
    ids, scen = log.parts[-4], log.parts[-3]
    for line in log.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        sent = j.get("packets_sent", {}).get("background")
        dur = j["end_epoch"] - j["launch_epoch"]
        if sent and dur > 0:
            rows.setdefault((ids, scen), []).append((sent / dur, j.get("bg_pps_requested", 0)))
if not rows:
    print("Aucun resume trouve (verifie --results-dir et remote_cmd.log).")
for (ids, scen), v in sorted(rows.items()):
    got = sum(x[0] for x in v) / len(v)
    req = v[0][1]
    print(f"{ids:9s} {scen:10s} runs={len(v):2d}  demande={req:8.0f} pps  reel moyen={got:8.0f} pps  ({100*got/req:5.1f} %)")
