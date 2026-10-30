#!/usr/bin/env python3
import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path

import pandas as pd


def parse_alert_time_line(line, year):
    ts_regex = re.compile(r"^(\d{2})/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")
    m = ts_regex.search(line)
    if not m:
        return None

    month = int(m.group(1))
    day = int(m.group(2))
    hour = int(m.group(3))
    minute = int(m.group(4))
    second = int(m.group(5))
    micro = m.group(6)
    microsecond = int((micro + "000000")[:6]) if micro else 0

    try:
        return datetime(year, month, day, hour, minute, second, microsecond).timestamp()
    except ValueError:
        return None


def get_year_from_metadata(meta_path):
    with open(meta_path) as f:
        meta = json.load(f)

    start_iso = meta.get("start_iso", "")
    if start_iso:
        return datetime.fromisoformat(start_iso.replace("Z", "+00:00")).year

    return datetime.now().year


def parse_alert_times(log_dir, year, excluded_sids=None):
    excluded_sids = set(excluded_sids or [])
    log_dir = Path(log_dir)
    alert_times = []

    sid_regex = re.compile(r"\[1:(\d+):\d+\]")

    for name in ["alert", "fast.log", "alert.fast"]:
        path = log_dir / name
        if not path.exists():
            continue

        with open(path, errors="ignore") as f:
            for line in f:
                sid = None
                m_sid = sid_regex.search(line)
                if m_sid:
                    sid = int(m_sid.group(1))

                if sid in excluded_sids:
                    continue

                ts = parse_alert_time_line(line, year)
                if ts is not None:
                    alert_times.append(ts)

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
                sid = int(alert.get("signature_id", -1))

                if sid in excluded_sids:
                    continue

                ts_str = obj.get("timestamp")
                if not ts_str:
                    continue

                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    alert_times.append(dt.timestamp())
                except ValueError:
                    continue

    return sorted(alert_times)


def analyze_benign_run(run_dir, window_seconds, excluded_sids):
    run_dir = Path(run_dir)
    meta_path = run_dir / "metadata.json"
    log_dir = run_dir / "ids_logs"

    if not meta_path.exists() or not log_dir.exists():
        return None, []

    with open(meta_path) as f:
        meta = json.load(f)

    if meta.get("scenario") != "benign":
        return None, []

    ids = meta.get("ids")
    run_id = meta.get("run_id")
    start_epoch = float(meta.get("start_epoch"))
    end_epoch = meta.get("end_epoch")

    if end_epoch is None:
        duration = int(meta.get("duration_seconds", 0))
        end_epoch = start_epoch + duration
    else:
        end_epoch = float(end_epoch)

    year = get_year_from_metadata(meta_path)
    alert_times = parse_alert_times(log_dir, year, excluded_sids=excluded_sids)

    n_windows = int((end_epoch - start_epoch) // window_seconds)

    window_rows = []
    fp_windows = 0

    for i in range(n_windows):
        w_start = start_epoch + i * window_seconds
        w_end = w_start + window_seconds

        alert_count = sum(1 for ts in alert_times if w_start <= ts < w_end)
        is_fp = 1 if alert_count > 0 else 0

        if is_fp:
            fp_windows += 1

        window_rows.append({
            "ids": ids,
            "run_id": run_id,
            "window_index": i + 1,
            "window_start_epoch": w_start,
            "window_end_epoch": w_end,
            "alert_count": alert_count,
            "is_fp": is_fp,
            "run_dir": str(run_dir),
        })

    fp = fp_windows
    tn = n_windows - fp
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None

    summary = {
        "ids": ids,
        "run_id": run_id,
        "window_seconds": window_seconds,
        "total_windows": n_windows,
        "fp": fp,
        "tn": tn,
        "fpr": fpr,
        "fpr_percent": fpr * 100 if fpr is not None else None,
        "total_alerts": len(alert_times),
        "run_dir": str(run_dir),
    }

    return summary, window_rows


def main():
    parser = argparse.ArgumentParser(description="Compute FP and FPR using time windows for benign runs.")
    parser.add_argument("--base-dir", default=os.path.expanduser("~/ids_voip_experiment"))
    parser.add_argument("--window-seconds", type=int, default=1)
    parser.add_argument(
        "--exclude-sids",
        default="1000001",
        help="Comma-separated SIDs to exclude from FP/FPR, default excludes ICMP SID 1000001."
    )
    args = parser.parse_args()

    excluded_sids = []
    if args.exclude_sids.strip():
        excluded_sids = [int(x.strip()) for x in args.exclude_sids.split(",") if x.strip()]

    base = Path(args.base_dir)
    summaries = []
    all_windows = []

    for run_dir in base.glob("results/*/benign/run_*"):
        summary, windows = analyze_benign_run(
            run_dir,
            window_seconds=args.window_seconds,
            excluded_sids=excluded_sids
        )

        if summary is None:
            continue

        summaries.append(summary)
        all_windows.extend(windows)

    out_dir = base / "analysis"
    out_dir.mkdir(exist_ok=True)

    df_runs = pd.DataFrame(summaries)
    df_windows = pd.DataFrame(all_windows)

    by_run_csv = out_dir / "fp_fpr_windows_by_run.csv"
    by_window_csv = out_dir / "fp_fpr_windows_detail.csv"
    final_csv = out_dir / "fp_fpr_windows_final.csv"

    df_runs.to_csv(by_run_csv, index=False)
    df_windows.to_csv(by_window_csv, index=False)

    final_rows = []

    if not df_runs.empty:
        for ids, group in df_runs.groupby("ids"):
            total_windows = group["total_windows"].sum()
            fp = group["fp"].sum()
            tn = group["tn"].sum()
            total_alerts = group["total_alerts"].sum()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else None

            final_rows.append({
                "ids": ids,
                "runs": len(group),
                "window_seconds": args.window_seconds,
                "total_windows": total_windows,
                "fp": fp,
                "tn": tn,
                "fpr": fpr,
                "fpr_percent": fpr * 100 if fpr is not None else None,
                "total_alerts": total_alerts,
                "excluded_sids": ",".join(str(s) for s in excluded_sids),
            })

    df_final = pd.DataFrame(final_rows)
    df_final.to_csv(final_csv, index=False)

    print(f"[OK] Résultats par run      : {by_run_csv}")
    print(f"[OK] Détail par fenêtre     : {by_window_csv}")
    print(f"[OK] Résultat final FP/FPR  : {final_csv}")

    if final_rows:
        print(df_final.to_string(index=False))
    else:
        print("[ATTENTION] Aucun run benign trouvé.")


if __name__ == "__main__":
    main()
