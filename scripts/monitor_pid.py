#!/usr/bin/env python3
"""monitor_pid.py (v2) - echantillonne CPU / RAM d'un processus IDS.

Compatible avec la v1 : les 7 premieres colonnes sont identiques.
Colonnes ajoutees a la fin : cpu_percent_norm (CPU / nb de coeurs logiques),
num_threads, system_cpu_percent (charge globale de la machine), ncpu.
NB : cpu_percent peut depasser 100 % pour un processus multithread
(100 % = un coeur logique entierement utilise).
"""
import argparse
import csv
import os
import time
from datetime import datetime

import psutil


def main():
    parser = argparse.ArgumentParser(description="Monitor CPU and RAM usage of an IDS process.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()

    try:
        proc = psutil.Process(args.pid)
    except psutil.NoSuchProcess:
        print(f"Process {args.pid} does not exist.")
        return

    ncpu = psutil.cpu_count(logical=True) or 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_iso", "timestamp_epoch", "pid", "process_name",
            "cpu_percent", "memory_rss_mb", "memory_percent",
            "cpu_percent_norm", "num_threads", "system_cpu_percent", "ncpu",
        ])
        proc.cpu_percent(interval=None)
        psutil.cpu_percent(interval=None)

        while True:
            try:
                cpu = proc.cpu_percent(interval=args.interval)
                sys_cpu = psutil.cpu_percent(interval=None)
                mem = proc.memory_info()
                now = time.time()
                writer.writerow([
                    datetime.fromtimestamp(now).isoformat(),
                    now,
                    args.pid,
                    proc.name(),
                    cpu,
                    mem.rss / (1024 * 1024),
                    proc.memory_percent(),
                    cpu / ncpu,
                    proc.num_threads(),
                    sys_cpu,
                    ncpu,
                ])
                f.flush()
            except psutil.NoSuchProcess:
                break
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main()
