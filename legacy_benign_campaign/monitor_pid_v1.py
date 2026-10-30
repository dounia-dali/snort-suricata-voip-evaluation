#!/usr/bin/env python3
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

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_iso",
            "timestamp_epoch",
            "pid",
            "process_name",
            "cpu_percent",
            "memory_rss_mb",
            "memory_percent"
        ])

        proc.cpu_percent(interval=None)

        while True:
            try:
                cpu = proc.cpu_percent(interval=args.interval)
                mem = proc.memory_info()
                now = time.time()

                writer.writerow([
                    datetime.fromtimestamp(now).isoformat(),
                    now,
                    args.pid,
                    proc.name(),
                    cpu,
                    mem.rss / (1024 * 1024),
                    proc.memory_percent()
                ])
                f.flush()

            except psutil.NoSuchProcess:
                break
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main()
