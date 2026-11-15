#!/usr/bin/env python3
"""Contest catalog for Surf Pools drafts (v1).

Builds data/contests.json from data/events.json + data/surfers.json:
- only real contests that are upcoming or running (plus ones that ended in the last 45 days, kept for scoring)
- rosters: WSL Championship Tour lists from worldsurfleague.com, cross-checked against the
  Wikipedia season standings; any name in one list but not the other is reported as a conflict
- manual rosters in collector/rosters_manual.json win over everything (admin can also paste one in the app)
- results: place + fantasy points per surfer once the event has results in the standings table
The Surf Pools worker reads this file every 15 minutes.
"""
import json, os, re, sys, unicodedata, datetime as dt
import requests

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
C = os.path.dirname(os.path.abspath(__file__))
HDR = {"User-Agent": "Mozilla/5.0 (compatible; fantasy-collector)"}
WSL = {"men": "https://www.worldsurfleague.com/athletes/tour/mct?year={y}",
       "women": "https://www.worldsurfleague.com/athletes/tour/wct?year={y}"}
# Fantasy points by finishing place (WSL Championship Tour scale)
PTS = {1: 10000, 2: 7800, 3: 6085, 5: 4745, 9: 3320, 17: 1330, 33: 265}
KEEP_DAYS = 45


def load(p, default):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return default


def key(name):
    s = "".join(c for c in unicodedata.normalize("NFKD", name or "") if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def place_num(s):
    m = re.match(r"\s*(\d+)", s or "")
    return int(m.group(1)) if m else None


def points(place):
    if not place:
        return 0
    best = 0
    for p, v in sorted(PTS.items()):
        if place >= p:
            best = v
    return best


def wsl_list(div, year):
    try:
        r = requests.get(WSL[div].format(y=year), headers=HDR, timeout=30)
        if r.status_code != 200:
            return None
        out = []
        for row in re.findall(r'<tr class="athlete-\d+[^"]*"(.*?)</tr>', r.text, re.S):
            n = re.search(r'class="athlete-name"[^>]*>([^<]+)<', row)
            if not n:
                continue
            c = re.search(r'athlete-country-flag[^>]*title="([^"]+)"', row)
            rk = re.search(r'<td class="athlete-rank[^"]*">\s*(\d+)', row)
            out.append({"name": n.group(1).strip(), "country": c.group(1) if c else "", "rank": int(rk.group(1)) if rk else None})
        return out or None
    except Exception:
        return None


def main():
    today = dt.date.today()
    ev = load(os.path.join(D, "events.json"), {}).get("events", [])
    su = load(os.path.join(D, "surfers.json"), {})
    ct = su.get("ct") or {}
    manual = load(os.path.join(C, "rosters_manual.json"), {})
    old = {c["id"]: c for c in load(os.path.join(D, "contests.json"), {}).get("contests", [])}
    std = ct.get("standings") or {}
    ct_events = [e.get("id") for e in ct.get("events", [])]
    wsl = {}
    out = []
    for e in ev:
        if e.get("kind") != "contest" or not e.get("start") or not e.get("end"):
            continue
        if e.get("status") == "cancelled":
            continue
        try:
            start, end = dt.date.fromisoformat(e["start"]), dt.date.fromisoformat(e["end"])
        except ValueError:
            continue
        if (today - end).days > KEEP_DAYS:
            continue
        c = {"id": e["id"], "name": e.get("name"), "org": e.get("org"), "series": e.get("series"),
             "location": e.get("location"), "start": e["start"], "end": e["end"],
             "status": "finished" if end < today else ("live" if start <= today else "upcoming"),
             "official": e.get("official"), "roster": None, "roster_source": None, "roster_note": "",
             "conflicts": [], "results": None}
        is_ct = e["id"].startswith("wsl-ct-")
        if e["id"] in manual:
            m = manual[e["id"]]
            c["roster"] = {d: [{"key": key(x["name"]), **x} for x in m.get(d, [])] for d in ("men", "women")}
            c["roster_source"] = "manual"
            c["roster_note"] = m.get("note", "Roster entered by the site admin.")
        elif is_ct:
            y = start.year
            if y not in wsl:
                wsl[y] = {d: wsl_list(d, y) for d in ("men", "women")}
            R = {}
            for d, g in (("men", "M"), ("women", "W")):
                site = wsl[y][d]
                wiki = [s for s in std.get(g, []) if s.get("rank")]
                if site:
                    R[d] = [{"key": key(s["name"]), "name": s["name"], "country": s["country"], "rank": s["rank"]} for s in site]
                elif wiki:
                    R[d] = [{"key": key(s["name"]), "name": s["name"], "country": s.get("country", ""), "rank": s["rank"]} for s in wiki]
                if site and wiki:
                    a, b = {key(s["name"]): s["name"] for s in site}, {key(s["name"]): s["name"] for s in wiki}
                    for k in a.keys() - b.keys():
                        c["conflicts"].append(f"{a[k]} ({d}) is on the WSL tour list but not in the Wikipedia standings")
                    for k in b.keys() - a.keys():
                        c["conflicts"].append(f"{b[k]} ({d}) is in the Wikipedia standings but not on the WSL tour list")
            if R.get("men") and R.get("women"):
                c["roster"] = R
                c["roster_source"] = "WSL tour list" + (" + Wikipedia check" if wsl[y]["men"] else " (Wikipedia, WSL site unavailable)")
                c["roster_note"] = "Championship Tour surfers. Event wildcards and injury replacements are added when they are announced."
            elif old.get(e["id"], {}).get("roster"):
                c.update({k: old[e["id"]][k] for k in ("roster", "roster_source", "roster_note")})
                c["conflicts"].append("Roster sources could not be reached this run; kept the last good roster.")
            # results from the standings table, once posted for this event
            if e["id"] in ct_events:
                i = ct_events.index(e["id"])
                res = {}
                for g in ("M", "W"):
                    for s in std.get(g, []):
                        r = (s.get("results") or [])
                        p = place_num(r[i]["place"]) if i < len(r) else None
                        if p:
                            res[key(s["name"])] = {"place": p, "points": points(p)}
                if res:
                    c["results"] = res
        else:
            c["roster_note"] = "Roster not published yet. Drafts open here as soon as the entry list is posted or the admin adds it."
        if c["roster"]:
            # make sure every rostered surfer has a key and a sortable rank
            for d in ("men", "women"):
                for n, s in enumerate(c["roster"][d]):
                    s.setdefault("key", key(s["name"]))
                    if not s.get("rank"):
                        s["rank"] = n + 1
        c["draftable"] = bool(c["roster"] and c["roster"]["men"] and c["roster"]["women"] and c["status"] != "finished")
        out.append(c)
    out.sort(key=lambda c: c["start"])
    doc = {"version": 1, "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "contests": out}
    # email (via the workflow's notify file) when something changes that the admin should know about
    old = {c["id"]: c for c in load(os.path.join(D, "contests.json"), {}).get("contests", [])}
    notes = []
    for c in out:
        o = old.get(c["id"], {})
        if c["draftable"] and not o.get("draftable"):
            notes.append(f"- **{c['name']}** is now open for drafts ({len(c['roster']['men'])} men, {len(c['roster']['women'])} women). Its free public draft was created automatically.")
        new_conf = [x for x in c["conflicts"] if x not in (o.get("conflicts") or [])]
        if new_conf and c["status"] != "finished":
            notes.append(f"- **{c['name']}** roster check: " + "; ".join(new_conf[:6]) + ". Fix it in My pools > Contests and rosters if needed.")
    nf = os.environ.get("NOTIFY_FILE")
    if nf and notes:
        with open(nf, "a", encoding="utf-8") as f:
            f.write("\n### Contests and draft rosters\n" + "\n".join(notes) + "\n")
    tmp = os.path.join(D, "contests.json.tmp")
    json.dump(doc, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, os.path.join(D, "contests.json"))
    for c in out:
        r = c["roster"]
        print(c["id"], c["status"], "draftable" if c["draftable"] else "-", (len(r["men"]), len(r["women"])) if r else "", "conflicts:", len(c["conflicts"]), "results:", len(c["results"] or {}))


if __name__ == "__main__":
    sys.exit(main())
