#!/usr/bin/env python3
"""compare_two.py - compare deux series de runs d'un meme IDS (ex. Suricata par defaut vs un seul thread).

  python3 scripts/compare_two.py --a analysis_results_v2/attacks_detection_by_run.csv \
      --b analysis_results_suri_single/attacks_detection_by_run.csv --ids suricata \
      --label-a "workers (defaut)" --label-b "single" --out final_F/compare_runmode.csv
Pour chaque scenario commun et chaque mesure : moyenne et ecart-type de A et de B, test de Welch,
test de Mann-Whitney. Les valeurs de p ne sont pas corrigees (peu de tests, lecture indicative).
"""
import argparse
import math
import os

import pandas as pd
from scipy import stats

ap = argparse.ArgumentParser()
ap.add_argument("--a", required=True, help="attacks_detection_by_run.csv de reference (A)")
ap.add_argument("--b", required=True, help="attacks_detection_by_run.csv a comparer (B)")
ap.add_argument("--ids", default="suricata")
ap.add_argument("--label-a", default="A")
ap.add_argument("--label-b", default="B")
ap.add_argument("--out", default=None)
a = ap.parse_args()

A, B = pd.read_csv(a.a), pd.read_csv(a.b)
metrics = [m for m in ["detection_time_s", "cpu_avg", "cpu_max", "mem_avg_mb", "threads_max",
                       "cpu_avg_attack", "mem_avg_attack_mb"] if m in A.columns and m in B.columns]
rows = []
for scen in sorted(set(A.scenario) & set(B.scenario)):
    for m in metrics:
        x = A[(A.ids == a.ids) & (A.scenario == scen)][m].dropna().astype(float)
        y = B[(B.ids == a.ids) & (B.scenario == scen)][m].dropna().astype(float)
        if len(x) < 2 or len(y) < 2:
            continue
        if x.std(ddof=1) == 0 and y.std(ddof=1) == 0:
            p = 1.0 if math.isclose(x.mean(), y.mean()) else 0.0
        else:
            p = stats.ttest_ind(x, y, equal_var=False).pvalue
        try:
            mw = stats.mannwhitneyu(x, y, alternative="two-sided").pvalue
        except ValueError:
            mw = float("nan")
        rows.append({"scenario": scen, "metric": m, "n_A": len(x), "n_B": len(y),
                     "mean_A": x.mean(), "std_A": x.std(ddof=1), "mean_B": y.mean(), "std_B": y.std(ddof=1),
                     "B_minus_A": y.mean() - x.mean(), "welch_p": p, "mannwhitney_p": mw})
out = pd.DataFrame(rows)
print(f"IDS : {a.ids}   A = {a.label_a}   B = {a.label_b}")
pd.set_option("display.width", 220)
print(out.round(4).to_string(index=False) if not out.empty else "Aucune comparaison possible (runs insuffisants).")
if a.out and not out.empty:
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    out.to_csv(a.out, index=False)
    print(f"[OK] {a.out}")
