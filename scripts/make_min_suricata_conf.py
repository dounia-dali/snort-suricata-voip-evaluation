#!/usr/bin/env python3
"""make_min_suricata_conf.py - cree une configuration Suricata allegee a partir de suricata.yaml.

  python3 scripts/make_min_suricata_conf.py --in /etc/suricata/suricata.yaml \
      --out ~/ids_voip_v2/configs/suricata_min.yaml            # eve-log ET analyseurs applicatifs desactives
  ... --eve            seulement eve-log (journal JSON) desactive
  ... --app-layer      seulement les analyseurs de protocoles applicatifs desactives

Le fichier d'origine n'est jamais modifie. Seules les lignes "enabled:" concernees changent
(les commentaires et la mise en forme sont conserves) ; la liste des lignes modifiees est affichee.
Les alertes restent ecrites dans fast.log, et stats.log reste actif (mesure des paquets perdus).
"""
import argparse
import os
import re
import sys

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--in", dest="src", required=True)
ap.add_argument("--out", dest="dst", required=True)
ap.add_argument("--eve", action="store_true")
ap.add_argument("--app-layer", dest="app", action="store_true")
a = ap.parse_args()
do_eve = a.eve or not (a.eve or a.app)
do_app = a.app or not (a.eve or a.app)

lines = open(os.path.expanduser(a.src), encoding="utf-8").read().split("\n")
out = list(lines)
changes = []


def top_key(line):
    """vrai si la ligne est une cle de premier niveau (colonne 0, hors commentaire)."""
    return bool(line) and not line[0].isspace() and not line.startswith("#") and ":" in line


# ---- eve-log (journal JSON) : section "outputs:" ----
if do_eve:
    in_outputs, found = False, False
    for i, ln in enumerate(lines):
        if top_key(ln):
            in_outputs = ln.startswith("outputs:")
        if in_outputs and re.match(r"^\s*-\s*eve-log:\s*$", ln):
            for j in range(i + 1, min(i + 12, len(lines))):
                m = re.match(r"^(\s+)enabled:\s*(\S+)(.*)$", lines[j])
                if m:
                    found = True
                    if m.group(2) != "no":
                        out[j] = f"{m.group(1)}enabled: no{m.group(3)}"
                        changes.append((j + 1, lines[j].strip(), out[j].strip(), "eve-log"))
                    break
            break
    if not found:
        sys.exit("[ERREUR] bloc 'eve-log' (ou sa ligne 'enabled:') introuvable dans le fichier d'entree")

# ---- analyseurs applicatifs : section "app-layer:" ----
if do_app:
    in_app, n_app = False, 0
    for i, ln in enumerate(lines):
        if top_key(ln):
            in_app = ln.startswith("app-layer:")
        if not in_app:
            continue
        m = re.match(r"^(\s+)enabled:\s*(yes|true|1|detection-only)(\s*(#.*)?)$", ln)
        if m:
            out[i] = f"{m.group(1)}enabled: no{m.group(3)}"
            changes.append((i + 1, ln.strip(), out[i].strip(), "app-layer"))
            n_app += 1
            continue
        # protocoles actifs par defaut dont la ligne est en commentaire (ex. sip, rdp, websocket)
        m = re.match(r"^(\s{6})#enabled:\s*yes\s*$", ln)
        if m:
            out[i] = f"{m.group(1)}enabled: no"
            changes.append((i + 1, ln.strip(), out[i].strip(), "app-layer (defaut)"))
            n_app += 1
    if n_app == 0:
        sys.exit("[ERREUR] aucun analyseur applicatif trouve dans la section 'app-layer:'")

os.makedirs(os.path.dirname(os.path.abspath(os.path.expanduser(a.dst))), exist_ok=True)
open(os.path.expanduser(a.dst), "w", encoding="utf-8").write("\n".join(out))
for n, before, after, sect in changes:
    print(f"  ligne {n:5d} [{sect}] {before}  ->  {after}")
print(f"[OK] {len(changes)} ligne(s) modifiee(s) -> {a.dst}")
