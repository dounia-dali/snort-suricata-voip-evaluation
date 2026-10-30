#!/usr/bin/env python3
"""aggregate_stats.py - statistiques pour l'article (reponse a l'evaluateur 2).

Entree : attacks_detection_by_run.csv produit par analyze_attacks_detection_time.py.
Sorties (dans --outdir) :
  summary_stats.csv   n, moyenne, ecart-type (ddof=1), IC 95 % (loi t de Student) par IDS/scenario/metrique
  tests_snort_vs_suricata.csv   Welch t, Mann-Whitney U, d de Cohen, correction de Holm
  table_ttd.tex, table_resources.tex   tableaux "moyenne +/- ecart-type" prets pour LaTeX
  fig_ttd / fig_cpu / fig_mem (.pdf et .png)  barres d'erreur = ecart-type, textes en anglais
Courbes de charge (optionnel) : --load 1000=analysis_results_load_1000/attacks_detection_by_run.csv ...
  -> load_summary.csv et fig_load_<scenario>_<metrique>.pdf/png

Exemples :
  python3 aggregate_stats.py --csv ~/ids_voip_v2/analysis/attacks_detection_by_run.csv
  python3 aggregate_stats.py --csv base.csv --load 0=base.csv --load 5000=l5000.csv --load 10000=l10000.csv
"""
import argparse
import math
import os
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore", category=RuntimeWarning)

SCEN_ORDER = ["sip_scan", "sip_brute", "sip_flood", "sip_spoof", "rtp_flood"]
SCEN_NAME = {"sip_scan": "SIP Scan", "sip_brute": "SIP Brute Force", "sip_flood": "SIP Flood",
             "sip_spoof": "SIP Spoofing", "rtp_flood": "RTP Flood"}
METRICS = {
    "detection_time_s": "TTD (s)", "cpu_avg": "Mean CPU (%)", "cpu_max": "Peak CPU (%)",
    "mem_avg_mb": "Mean RSS (MB)", "mem_max_mb": "Peak RSS (MB)",
    "cpu_avg_attack": "Mean CPU during attack (%)", "mem_avg_attack_mb": "Mean RSS during attack (MB)",
    "drop_pct": "Packet drops (%)",
}
COLORS = {"snort": "#1f4e9c", "suricata": "#7f8796"}
LABEL = {"snort": "Snort", "suricata": "Suricata"}


def ci95(x):
    x = np.asarray(x, float)
    n = len(x)
    if n < 2:
        return float("nan")
    return stats.t.ppf(0.975, n - 1) * x.std(ddof=1) / math.sqrt(n)


def summarize(df, metrics):
    rows = []
    for (ids, scen), g in df.groupby(["ids", "scenario"]):
        row = {"ids": ids, "scenario": scen, "runs": len(g),
               "tpr_percent": 100.0 * g["detected"].mean() if "detected" in g else float("nan")}
        for m in metrics:
            v = g[m].dropna().astype(float)
            row[f"{m}_n"] = len(v)
            row[f"{m}_mean"] = v.mean() if len(v) else float("nan")
            row[f"{m}_std"] = v.std(ddof=1) if len(v) > 1 else float("nan")
            row[f"{m}_ci95"] = ci95(v) if len(v) > 1 else float("nan")
        rows.append(row)
    return pd.DataFrame(rows)


def cohen_d(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return float("nan")
    sp = math.sqrt(((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2))
    return float("nan") if sp == 0 else (b.mean() - a.mean()) / sp


def holm(pvals):
    p = np.array([1.0 if (x is None or np.isnan(x)) else x for x in pvals], float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    running = 0.0
    m = len(p)
    for rank, idx in enumerate(order):
        running = max(running, (m - rank) * p[idx])
        adj[idx] = min(1.0, running)
    return adj


def compare(df, metrics):
    rows = []
    for scen in [s for s in SCEN_ORDER if s in df["scenario"].unique()]:
        for m in metrics:
            a = df[(df.ids == "snort") & (df.scenario == scen)][m].dropna().astype(float)
            b = df[(df.ids == "suricata") & (df.scenario == scen)][m].dropna().astype(float)
            if len(a) < 2 or len(b) < 2:
                continue
            if a.std(ddof=1) == 0 and b.std(ddof=1) == 0:
                welch_p = 1.0 if math.isclose(a.mean(), b.mean()) else 0.0
            else:
                welch_p = stats.ttest_ind(a, b, equal_var=False).pvalue
            try:
                mw_p = stats.mannwhitneyu(a, b, alternative="two-sided").pvalue
            except ValueError:
                mw_p = float("nan")
            rows.append({"scenario": scen, "metric": m, "n_snort": len(a), "n_suricata": len(b),
                         "mean_snort": a.mean(), "mean_suricata": b.mean(), "diff_suricata_minus_snort": b.mean() - a.mean(),
                         "cohen_d": cohen_d(a, b), "welch_p": welch_p, "mannwhitney_p": mw_p})
    out = pd.DataFrame(rows)
    if not out.empty:
        out["welch_p_holm"] = holm(out["welch_p"].tolist())
        out["significant_holm_0.05"] = out["welch_p_holm"] < 0.05
    return out


def pm(mean, std, nd=3):
    if pd.isna(mean):
        return "--"
    return f"{mean:.{nd}f}" if pd.isna(std) else f"{mean:.{nd}f} $\\pm$ {std:.{nd}f}"


def write_latex(summ, path, cols, caption, label, headers, nds):
    lines = ["\\begin{table}[t]", "\\centering", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
             "\\begin{tabular}{ll" + "c" * len(cols) + "}", "\\hline",
             "IDS & Scenario & " + " & ".join(headers) + " \\\\", "\\hline"]
    for ids in ["snort", "suricata"]:
        for scen in SCEN_ORDER:
            r = summ[(summ.ids == ids) & (summ.scenario == scen)]
            if r.empty:
                continue
            r = r.iloc[0]
            cells = [pm(r[f"{c}_mean"], r[f"{c}_std"], nd) for c, nd in zip(cols, nds)]
            lines.append(f"{LABEL[ids]} & {SCEN_NAME[scen]} & " + " & ".join(cells) + " \\\\")
        lines.append("\\hline")
    lines += ["\\end{tabular}", "\\end{table}"]
    Path(path).write_text("\n".join(lines) + "\n")


def bar_fig(summ, metric, outbase):
    scens = [s for s in SCEN_ORDER if s in summ.scenario.unique()]
    x = np.arange(len(scens))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7, 3.6))
    for k, ids in enumerate(["snort", "suricata"]):
        means, errs = [], []
        for s in scens:
            r = summ[(summ.ids == ids) & (summ.scenario == s)]
            means.append(r[f"{metric}_mean"].iloc[0] if not r.empty else np.nan)
            e = r[f"{metric}_std"].iloc[0] if not r.empty else np.nan
            errs.append(0 if pd.isna(e) else e)
        ax.bar(x + (k - 0.5) * w, means, w, yerr=errs, capsize=3, label=LABEL[ids], color=COLORS[ids])
    ax.set_xticks(x)
    ax.set_xticklabels([SCEN_NAME[s] for s in scens], rotation=15)
    ax.set_ylabel(METRICS[metric])
    ax.set_xlabel("Attack scenario")
    ax.grid(axis="y", alpha=0.3)
    ax.legend()
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(f"{outbase}.{ext}", dpi=200)
    plt.close(fig)


def load_curves(load_specs, outdir, metrics, xlabel="Background load (packets/s)"):
    frames = []
    for spec in load_specs:
        label, path = spec.split("=", 1)
        d = pd.read_csv(path)
        d["load"] = float(label)
        frames.append(d)
    all_df = pd.concat(frames, ignore_index=True)
    rows = []
    for (ids, scen, load), g in all_df.groupby(["ids", "scenario", "load"]):
        row = {"ids": ids, "scenario": scen, "load_pps": load, "runs": len(g),
               "tpr_percent": 100.0 * g["detected"].mean()}
        for m in metrics:
            v = g[m].dropna().astype(float)
            row[f"{m}_mean"] = v.mean() if len(v) else float("nan")
            row[f"{m}_std"] = v.std(ddof=1) if len(v) > 1 else float("nan")
        rows.append(row)
    summ = pd.DataFrame(rows).sort_values(["scenario", "ids", "load_pps"])
    summ.to_csv(Path(outdir) / "load_summary.csv", index=False)
    for scen in summ.scenario.unique():
        for m in metrics + ["tpr_percent"]:
            col = "tpr_percent" if m == "tpr_percent" else f"{m}_mean"
            if col not in summ or summ[summ.scenario == scen][col].isna().all():
                continue
            fig, ax = plt.subplots(figsize=(5.6, 3.6))
            for ids in ["snort", "suricata"]:
                s = summ[(summ.scenario == scen) & (summ.ids == ids)]
                if s.empty:
                    continue
                err = None if m == "tpr_percent" else s[f"{m}_std"].fillna(0)
                ax.errorbar(s["load_pps"], s[col], yerr=err, marker="o", capsize=3,
                            label=LABEL[ids], color=COLORS[ids])
            ax.set_xlabel(xlabel)
            ax.set_ylabel("Detection rate (%)" if m == "tpr_percent" else METRICS[m])
            ax.set_title(SCEN_NAME.get(scen, scen))
            ax.grid(alpha=0.3)
            ax.legend()
            fig.tight_layout()
            for ext in ("pdf", "png"):
                fig.savefig(Path(outdir) / f"fig_load_{scen}_{m}.{ext}", dpi=200)
            plt.close(fig)
    return summ


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", help="attacks_detection_by_run.csv de l'experience de base")
    ap.add_argument("--load", action="append", default=[], help="CHARGE=chemin/attacks_detection_by_run.csv (repetable)")
    ap.add_argument("--xlabel", default="Background load (packets/s)", help="legende de l'axe x des courbes --load")
    ap.add_argument("--outdir", default="analysis_final")
    a = ap.parse_args()
    out = Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)

    if a.csv:
        df = pd.read_csv(a.csv)
        metrics = [m for m in METRICS if m in df.columns and df[m].notna().any()]
        summ = summarize(df, metrics)
        summ.to_csv(out / "summary_stats.csv", index=False)
        tests = compare(df, metrics)
        tests.to_csv(out / "tests_snort_vs_suricata.csv", index=False)
        write_latex(summ, out / "table_ttd.tex", ["detection_time_s"],
                    "Detection time (s), mean $\\pm$ standard deviation over the repeated runs.",
                    "tab:ttd", ["TTD (s)"], [3])
        res_cols = [c for c in ["cpu_avg", "cpu_max", "mem_avg_mb"] if c in metrics]
        write_latex(summ, out / "table_resources.tex", res_cols,
                    "CPU and memory consumption, mean $\\pm$ standard deviation over the repeated runs.",
                    "tab:resources", [{"cpu_avg": "CPU avg (\\%)", "cpu_max": "CPU max (\\%)", "mem_avg_mb": "RAM avg (MB)"}[c] for c in res_cols],
                    [3 if c == "cpu_avg" else 1 for c in res_cols])
        for m, name in [("detection_time_s", "fig_ttd"), ("cpu_avg", "fig_cpu"), ("mem_avg_mb", "fig_mem")]:
            if m in metrics:
                bar_fig(summ, m, str(out / name))
        n_runs = df.groupby(["ids", "scenario"]).size().min()
        print(f"[OK] {len(df)} runs, minimum {n_runs} runs par IDS/scenario")
        print(f"[OK] Tests : {out/'tests_snort_vs_suricata.csv'}")
        if not tests.empty:
            print(tests[["scenario", "metric", "mean_snort", "mean_suricata", "cohen_d", "welch_p_holm",
                         "mannwhitney_p"]].to_string(index=False, float_format=lambda v: f"{v:.4g}"))
    if a.load:
        metrics = ["detection_time_s", "cpu_avg", "mem_avg_mb", "drop_pct"]
        load_curves(a.load, out, metrics, a.xlabel)
        print(f"[OK] Courbes de charge dans {out}")


if __name__ == "__main__":
    main()
