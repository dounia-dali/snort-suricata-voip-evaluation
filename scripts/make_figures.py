#!/usr/bin/env python3
"""make_figures.py - figures de l'article, textes en anglais, style epure.

  python3 scripts/make_figures.py --summary final_base/summary_stats.csv --outdir final_base

Produit (PDF et PNG) :
  fig_ttd   histogramme du temps de detection moyen, valeurs au-dessus des barres
  fig_cpu   COURBE de la consommation CPU moyenne (marqueurs, valeurs, zone grisee sous la courbe)
  fig_mem   COURBE de la consommation memoire moyenne (meme style que fig_cpu)
Par defaut : pas de titre dans l'image (il est dans la legende LaTeX), pas de barres d'erreur,
pas de cadre (seuls les axes gauche et bas sont traces).
Options : --titles (ajoute le titre), --errorbars (ajoute l'ecart-type), --frame (cadre complet).
Les fichiers existants de meme nom (crees par aggregate_stats.py) sont remplaces : relancer ce script
apres chaque execution d'aggregate_stats.py.
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

SCEN_ORDER = ["sip_scan", "sip_brute", "sip_flood", "sip_spoof", "rtp_flood"]
SCEN_NAME = {"sip_scan": "SIP Scan", "sip_brute": "SIP Brute Force", "sip_flood": "SIP Flood",
             "sip_spoof": "SIP Spoofing", "rtp_flood": "RTP Flood"}
COL = {"snort": "#1f4e9c", "suricata": "#7f8796"}
LAB = {"snort": "Snort", "suricata": "Suricata"}
MARK = {"snort": "o", "suricata": "s"}

plt.rcParams.update({"font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
                     "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8})


def series(s, metric, ids, scens):
    m, e = [], []
    for sc in scens:
        r = s[(s.ids == ids) & (s.scenario == sc)]
        m.append(r[f"{metric}_mean"].iloc[0] if not r.empty else np.nan)
        e.append(r[f"{metric}_std"].iloc[0] if not r.empty else np.nan)
    return np.array(m, float), np.nan_to_num(np.array(e, float))


def finish(fig, ax, base, title, titles, frame, legend_loc):
    if titles:
        ax.set_title(title, fontweight="bold")
    if not frame:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    ax.set_xlabel("Attack scenario")
    ax.set_axisbelow(True)
    ax.legend(loc=legend_loc, frameon=True, facecolor="white", edgecolor="none", framealpha=0.9)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(f"{base}.{ext}", dpi=200)
    plt.close(fig)


def bar_ttd(s, scens, base, errorbars, titles, frame):
    x = np.arange(len(scens))
    w = 0.38
    fig, ax = plt.subplots(figsize=(5.4, 3.4))
    top = 0.0
    for k, ids in enumerate(["snort", "suricata"]):
        m, e = series(s, "detection_time_s", ids, scens)
        pos = x + (k - 0.5) * w
        ax.bar(pos, m, w, yerr=e if errorbars else None, capsize=2, color=COL[ids], label=LAB[ids],
               error_kw={"elinewidth": 0.8})
        for xi, mi in zip(pos, m):
            ax.text(xi, mi * 1.01, f"{mi:.3f}", ha="center", va="bottom", fontsize=6.5)
        top = max(top, np.nanmax(m + e))
    ax.set_ylim(0, top * 1.18)
    ax.set_ylabel("Mean detection time (s)")
    ax.set_xticks(x)
    ax.set_xticklabels([SCEN_NAME[c] for c in scens], rotation=15)
    ax.grid(axis="y", alpha=0.3)
    finish(fig, ax, base, "Comparison of Mean Detection Time", titles, frame, "upper right")


def line_fig(s, scens, metric, title, ylabel, fmt, base, errorbars, titles, frame):
    x = np.arange(len(scens))
    fig, ax = plt.subplots(figsize=(5.4, 3.4))
    top = 0.0
    for ids in ["snort", "suricata"]:
        m, e = series(s, metric, ids, scens)
        ax.plot(x, m, marker=MARK[ids], color=COL[ids], linewidth=1.6, markersize=5, label=LAB[ids])
        ax.fill_between(x, 0, m, color=COL[ids], alpha=0.10)
        if errorbars:
            ax.errorbar(x, m, yerr=e, fmt="none", ecolor=COL[ids], capsize=2, elinewidth=0.8)
        for xi, mi in zip(x, m):
            ax.annotate(fmt.format(mi), (xi, mi), textcoords="offset points", xytext=(0, 7),
                        ha="center", fontsize=7, color=COL[ids])
        top = max(top, np.nanmax(m + e))
    ax.set_ylim(0, top * 1.32)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels([SCEN_NAME[c] for c in scens], rotation=15)
    ax.grid(alpha=0.3)
    finish(fig, ax, base, title, titles, frame, "upper left")


ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--summary", required=True, help="summary_stats.csv produit par aggregate_stats.py")
ap.add_argument("--outdir", default="final_base")
ap.add_argument("--titles", action="store_true", help="ajoute un titre en haut des figures")
ap.add_argument("--errorbars", action="store_true", help="ajoute les barres d'erreur (ecart-type)")
ap.add_argument("--frame", action="store_true", help="conserve le cadre complet autour du graphique")
ap.add_argument("--no-errorbars", action="store_true", help=argparse.SUPPRESS)  # ancienne option, sans effet
a = ap.parse_args()

s = pd.read_csv(a.summary)
scens = [c for c in SCEN_ORDER if c in s.scenario.unique()]
out = Path(a.outdir)
out.mkdir(parents=True, exist_ok=True)

bar_ttd(s, scens, str(out / "fig_ttd"), a.errorbars, a.titles, a.frame)
line_fig(s, scens, "cpu_avg", "Comparison of Mean CPU Consumption", "Mean CPU usage (%)", "{:.2f}",
         str(out / "fig_cpu"), a.errorbars, a.titles, a.frame)
line_fig(s, scens, "mem_avg_mb", "Comparison of Mean Memory Consumption", "Mean memory usage (MB)", "{:.1f}",
         str(out / "fig_mem"), a.errorbars, a.titles, a.frame)
print(f"[OK] fig_ttd, fig_cpu, fig_mem (.pdf et .png) dans {out}")
