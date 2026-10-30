#!/usr/bin/env python3
"""make_load_figure.py - CPU de Snort et de Suricata en fonction du trafic de fond (experience C), style epure.

  python3 scripts/make_load_figure.py --table final_load_table.csv --outdir final_load --scenario sip_flood

Produit fig_load_cpu_<scenario>.pdf et .png : deux courbes (Snort, Suricata), valeurs sur les points,
sans titre, sans barres d'erreur, sans cadre (comme les autres figures). Options : --titles, --errorbars, --frame.
Le tableau est final_load_table.csv, ecrit par la commande de synthese de l'experience C.
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

COL = {"snort": "#1f4e9c", "suricata": "#7f8796"}
LAB = {"snort": "Snort", "suricata": "Suricata"}
MARK = {"snort": "o", "suricata": "s"}
SCEN_NAME = {"sip_scan": "SIP Scan", "sip_flood": "SIP Flood"}

plt.rcParams.update({"font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
                     "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8})

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--table", default="final_load_table.csv")
ap.add_argument("--outdir", default="final_load")
ap.add_argument("--scenario", default="sip_flood", choices=["sip_scan", "sip_flood"])
ap.add_argument("--titles", action="store_true")
ap.add_argument("--errorbars", action="store_true")
ap.add_argument("--frame", action="store_true")
a = ap.parse_args()

t = pd.read_csv(a.table)
t = t[t.scenario == a.scenario]
fig, ax = plt.subplots(figsize=(5.4, 3.4))
top = 0.0
for ids in ["snort", "suricata"]:
    s = t[t.ids == ids].sort_values("load")
    x, y, e = s["load"].to_numpy(float), s["cpu"].to_numpy(float), s["cpu_sd"].fillna(0).to_numpy(float)
    ax.plot(x, y, marker=MARK[ids], color=COL[ids], linewidth=1.6, markersize=5, label=LAB[ids])
    if a.errorbars:
        ax.errorbar(x, y, yerr=e, fmt="none", ecolor=COL[ids], capsize=2, elinewidth=0.8)
    for xi, yi in zip(x, y):
        ax.annotate(f"{yi:.2f}" if yi < 10 else f"{yi:.1f}", (xi, yi), textcoords="offset points",
                    xytext=(0, 7), ha="center", fontsize=7, color=COL[ids])
    top = max(top, float(np.nanmax(y + e)))
loads = sorted(t["load"].unique())
ax.set_xticks(loads)
ax.set_xticklabels(["0" if v == 0 else f"{int(v) // 1000}k" for v in loads])
ax.set_ylim(0, top * 1.2)
ax.set_xlim(-600, max(loads) * 1.04)
ax.set_xlabel("Background traffic rate (packets/s)")
ax.set_ylabel("Mean CPU usage (%)")
ax.grid(alpha=0.3)
ax.set_axisbelow(True)
if a.titles:
    ax.set_title(f"CPU Consumption under Increasing Load ({SCEN_NAME[a.scenario]})", fontweight="bold")
if not a.frame:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="none", framealpha=0.9)
fig.tight_layout()
out = Path(a.outdir)
out.mkdir(parents=True, exist_ok=True)
for ext in ("pdf", "png"):
    fig.savefig(out / f"fig_load_cpu_{a.scenario}.{ext}", dpi=200)
print(f"[OK] {out / ('fig_load_cpu_' + a.scenario + '.pdf')} (et .png)")
