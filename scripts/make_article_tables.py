#!/usr/bin/env python3
"""make_article_tables.py - tableau de detection (LaTeX) et chiffres cles pour le texte de l'article.

  python3 scripts/make_article_tables.py \
      --by-run analysis_results_v2/attacks_detection_by_run.csv \
      --tests final_base/tests_snort_vs_suricata.csv --outdir final_base

Ecrit dans --outdir :
  table_detection.tex   TP, FN, taux de detection par IDS et scenario (tableau I)
  key_numbers.txt       chiffres a reprendre dans le texte (aussi affiches a l'ecran)
"""
import argparse
import os
from pathlib import Path

import pandas as pd

SCEN_ORDER = ["sip_scan", "sip_brute", "sip_flood", "sip_spoof", "rtp_flood"]
SCEN_NAME = {"sip_scan": "SIP Scan", "sip_brute": "SIP Brute Force", "sip_flood": "SIP Flood",
             "sip_spoof": "SIP Spoofing", "rtp_flood": "RTP Flood"}
LABEL = {"snort": "Snort", "suricata": "Suricata"}
# (seuil de paquets de la regle, debit d'attaque en paquets/s) -> TTD attendu = (seuil - 1) / debit
MODEL = {"sip_scan": (5, 10), "sip_brute": (10, 20), "sip_flood": (80, 100), "sip_spoof": (10, 20), "rtp_flood": (80, 200)}

ap = argparse.ArgumentParser()
ap.add_argument("--by-run", required=True)
ap.add_argument("--tests", default=None)
ap.add_argument("--outdir", default="final_base")
a = ap.parse_args()
out = Path(a.outdir)
out.mkdir(parents=True, exist_ok=True)

d = pd.read_csv(a.by_run)
lines = []


def p(s=""):
    lines.append(s)
    print(s)


# ---------- tableau de detection ----------
rows = []
for ids in ["snort", "suricata"]:
    for scen in SCEN_ORDER:
        g = d[(d.ids == ids) & (d.scenario == scen)]
        if g.empty:
            continue
        tp, n = int(g["detected"].sum()), len(g)
        rows.append((LABEL[ids], SCEN_NAME[scen], n, tp, n - tp, 100.0 * tp / n))
tex = ["\\begin{table}[t]", "\\centering", "\\caption{VoIP attack detection results.}", "\\label{tab:detection}",
       "\\begin{tabular}{llcccc}", "\\hline", "IDS & Attack scenario & Runs & TP & FN & TPR (\\%) \\\\", "\\hline"]
prev = None
for r in rows:
    if prev is not None and r[0] != prev:
        tex.append("\\hline")
    tex.append(f"{r[0]} & {r[1]} & {r[2]} & {r[3]} & {r[4]} & {r[5]:.0f} \\\\")
    prev = r[0]
tex += ["\\hline", "\\end{tabular}", "\\end{table}"]
(out / "table_detection.tex").write_text("\n".join(tex) + "\n")

# ---------- chiffres cles ----------
p("=== Detection ===")
for ids in ["snort", "suricata"]:
    g = d[d.ids == ids]
    p(f"{LABEL[ids]:9s}: {int(g['detected'].sum())} runs detectes sur {len(g)}  (faux negatifs : {int(g['false_negative'].sum())})")

p("\n=== Temps de detection : observe vs modele (seuil - 1) / debit ===")
p(f"{'scenario':16s}{'attendu (s)':>12s}{'Snort (s)':>16s}{'Suricata (s)':>16s}{'ecart max (ms)':>16s}")
maxdiff = 0.0
for scen in SCEN_ORDER:
    s = d[(d.ids == "snort") & (d.scenario == scen)]["detection_time_s"].dropna()
    u = d[(d.ids == "suricata") & (d.scenario == scen)]["detection_time_s"].dropna()
    if s.empty or u.empty:
        continue
    thr, rate = MODEL[scen]
    diff = abs(s.mean() - u.mean()) * 1000
    maxdiff = max(maxdiff, diff)
    p(f"{SCEN_NAME[scen]:16s}{(thr - 1) / rate:12.3f}{s.mean():9.3f} +/- {s.std(ddof=1):.3f}{u.mean():9.3f} +/- {u.std(ddof=1):.3f}{diff:16.1f}")
p(f"Ecart maximal entre les deux IDS sur le TTD moyen : {maxdiff:.1f} ms")
p(f"TTD maximal observe (tous runs) : {d['detection_time_s'].max():.3f} s")

p("\n=== Ressources (moyennes sur les runs, par scenario) ===")
for ids in ["snort", "suricata"]:
    g = d[d.ids == ids]
    by = g.groupby("scenario").agg(cpu=("cpu_avg", "mean"), cpu_sd=("cpu_avg", "std"), cpu_max=("cpu_max", "max"),
                                   mem=("mem_avg_mb", "mean"), mem_sd=("mem_avg_mb", "std"))
    p(f"{LABEL[ids]:9s}: CPU moyen de {by['cpu'].min():.3f} a {by['cpu'].max():.3f} % "
      f"(ecart-type max {by['cpu_sd'].max():.3f}), CPU de pointe max {by['cpu_max'].max():.1f} %, "
      f"RAM {by['mem'].min():.1f} a {by['mem'].max():.1f} Mo (ecart-type max {by['mem_sd'].max():.2f})")
sn = d[d.ids == "snort"]["mem_avg_mb"].mean()
su = d[d.ids == "suricata"]["mem_avg_mb"].mean()
p(f"RAM de Suricata par rapport a Snort : +{100 * (su / sn - 1):.0f} %")
if d["threads_max"].notna().any():
    p("Threads max : " + ", ".join(f"{LABEL[i]} {int(d[d.ids == i]['threads_max'].max())}" for i in ["snort", "suricata"]))
if d["drop_pct"].notna().any():
    p("Paquets perdus (moyenne) : " + ", ".join(f"{LABEL[i]} {d[d.ids == i]['drop_pct'].mean():.3f} %" for i in ["snort", "suricata"]))

if a.tests and os.path.exists(a.tests):
    t = pd.read_csv(a.tests)
    p("\n=== Tests Snort contre Suricata (Welch, correction de Holm) ===")
    for m, name in [("detection_time_s", "temps de detection"), ("cpu_avg", "CPU moyen"), ("mem_avg_mb", "RAM moyenne")]:
        s = t[t.metric == m]
        if s.empty:
            continue
        sig = int(s["significant_holm_0.05"].sum())
        p(f"{name:20s}: {sig} scenarios significatifs sur {len(s)} ; p corrige max = {s['welch_p_holm'].max():.3g} ; |d de Cohen| min = {s['cohen_d'].abs().min():.1f}")
(out / "key_numbers.txt").write_text("\n".join(lines) + "\n")
p(f"\n[OK] {out/'table_detection.tex'} et {out/'key_numbers.txt'}")
