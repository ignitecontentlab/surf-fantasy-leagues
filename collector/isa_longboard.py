#!/usr/bin/env python3
"""ISA World Longboard Championship 2026 (El Sunzal, El Salvador): official ISA scoring (SurfScores) results.
Writes data/isa_longboard.json. The event finished on 22 Oct 2026, so this only needs to run when the data is missing."""
import json, os, sys, datetime as dt
import requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_isa import parse_results, norm

BASE = "https://surfscores.com/ESA/2026/isawlsc/"
EVENT = {"name": "ISA World Longboard Championship 2026", "location": "El Sunzal, El Salvador",
         "start": "2026-10-16", "end": "2026-10-22", "official": "https://isasurf.org/", "results": BASE}
HDR = {"User-Agent": "Mozilla/5.0 (compatible; surf-fantasy-leagues collector)"}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "isa_longboard.json")
MED = {1: "gold", 2: "silver", 3: "bronze", 4: "copper"}


def division(page, g):
    r = requests.get(BASE + page, headers=HDR, timeout=30)
    r.raise_for_status()
    heats = parse_results(r.content.decode("utf-8", "replace") if b"\xc3" in r.content else r.content.decode("latin-1"), g)
    people = {}
    for h in heats:
        for s in h["surfers"]:
            k = norm(s["name"])
            p = people.setdefault(k, {"name": s["name"], "country": s["country"], "g": "M" if g == "men" else "W",
                                      "heats": 0, "wins": 0, "best_heat": 0, "sum": 0.0, "last": -1, "log": []})
            if s["total"] is None and not h["complete"]:
                continue
            p["heats"] += 1
            p["sum"] += s["total"] or 0
            p["best_heat"] = max(p["best_heat"], s["total"] or 0)
            if s["place"] == 1:
                p["wins"] += 1
            p["last"] = int(h["round"][1:])  # round block, so surfers knocked out in the same round tie
            p["log"].append({"round": h["round"], "heat": h["heat"], "total": s["total"], "place": s["place"]})
    final = heats[-1] if heats else None
    L = list(people.values())
    for p in L:
        fp = next((s["place"] for s in (final["surfers"] if final else []) if norm(s["name"]) == norm(p["name"])), None)
        # finish: medal from the final, otherwise 1 + everyone who surfed in a later heat
        p["finish"] = fp if fp else 1 + sum(1 for q in L if q is not p and q["last"] > p["last"])
        if fp in MED:
            p["medal"] = MED[fp]
    for p in L:
        p["avg_heat"] = round(p.pop("sum") / p["heats"], 2) if p["heats"] else 0
        p["rounds"] = p.pop("last")
    L.sort(key=lambda p: (p["finish"], -p["best_heat"]))
    return L, len(heats)


def main():
    out = {"updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "event": EVENT, "surfers": [], "heats": {}}
    for page, g in (("men.php", "men"), ("women.php", "women")):
        L, n = division(page, g)
        if not L:
            raise SystemExit(f"no {g} results parsed; keeping the old file")
        out["surfers"] += L
        out["heats"][g] = n
    tmp = OUT + ".tmp"
    json.dump(out, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print(len(out["surfers"]), "longboard surfers", out["heats"])


if __name__ == "__main__":
    main()
