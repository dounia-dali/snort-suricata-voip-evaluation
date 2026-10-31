# Controlled-environment evaluation of Snort and Suricata for VoIP intrusion detection

Rules, scripts, configurations and summary data of the paper *Controlled-Environment Evaluation of Snort and Suricata
for VoIP Intrusion Detection* (CCA 2026).

## Contents
| Folder | Content |
|---|---|
| `scripts/` | Orchestration (`run_batch.sh`, `collect_run_manual.sh`, `monitor_pid.py`), traffic generator (`attack_gen.py`, runs on the attacker VM), analysis (`analyze_attacks_detection_time.py`, `aggregate_stats.py`, `compare_two.py`, `load_rates.py`, `diag_time.py`) and table/figure scripts (`make_*.py`) |
| `rules/` | The five custom detection rules, identical for Snort and Suricata |
| `configs/` | Snort configuration (comments removed), Suricata default and light configurations, sanitized Asterisk configuration |
| `sipp/` | SIPp scenario used for the benign traffic |
| `legacy_benign_campaign/` | Earlier versions of the scripts used for the benign (false-positive) campaign of Table III |
| `data/` | Per-run and summary results (CSV): attacks, single-worker and light-configuration campaigns, load experiment |
| `figures/` | Figures and LaTeX tables of the paper |

## Environment
Host: Ubuntu 24.04.3 LTS, Intel Core i5-10310U (4 cores, 8 threads), 8 GB RAM, VirtualBox 7.2.6 with a host-only network
(192.168.56.0/24). Attacker: Kali Linux VM (2 vCPU, 4 GB RAM). Snort 2.9.20, Suricata 8.0.3, Asterisk 22.8.2,
Tshark 4.2.2, SIPp 3.7.2 (host) and SIPp 3.3-beta1 (attacker VM), Python 3.12.3 (host) and Python 3.13.9 (attacker VM) with psutil, pandas, scipy and matplotlib.

## Reproducing the experiments
1. Create the working directory and copy the scripts: `mkdir -p ~/ids_voip_v2 && cp -r scripts ~/ids_voip_v2/`
   (the scripts use this directory by default).
2. Install `rules/local.rules` for both engines, and use the configurations of `configs/`.
3. Copy `scripts/attack_gen.py` to the attacker VM and set up SSH key authentication from the host to that VM
   (pass the user with `--kali USER@192.168.56.102` or edit `KALI` in `run_batch.sh`).
4. Attack campaign (10 runs): `sudo ./scripts/run_batch.sh --runs 1-10 --results-dir results_v2`
5. Single-worker campaign: `sudo ./scripts/run_batch.sh --runs 1-10 --scenarios "sip_scan sip_flood" --ids suricata --runmode single --results-dir results_suri_single`
6. Light configuration: `python3 scripts/make_min_suricata_conf.py --in configs/suricata.yaml --out configs/suricata_light.yaml`, then
   run as above with `--suricata-conf configs/suricata_light.yaml`.
7. Load experiment: add a second source address on the attacker VM and drop it at the host firewall after capture, then
   `sudo ./scripts/run_batch.sh --runs 1-10 --scenarios "sip_scan sip_flood" --bg-pps 5000 --bg-src 192.168.56.103 --duration 80 --results-dir results_load_5000`
8. Analysis: `python3 scripts/analyze_attacks_detection_time.py --results-dir results_v2`, then
   `python3 scripts/aggregate_stats.py --csv analysis_results_v2/attacks_detection_by_run.csv --outdir final_base`.

## Notes
- Passwords of the laboratory accounts are replaced by `CHANGE_ME`.
- The analysis reads the time zone of each run from `metadata.json`, so results can be re-analyzed on a machine with a different time zone.
- The benign campaign (Table III) was produced earlier with the scripts of `legacy_benign_campaign/`.
- Raw experimental data are archived separately on Zenodo: https://doi.org/10.5281/zenodo.23811199

## License
Code: MIT (see `LICENSE`).
