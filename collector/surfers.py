#!/usr/bin/env python3
"""All surfers in the big contests -> data/surfers.json

  * WSL Championship Tour men and women: rank, points, finish at every stop
    (Wikipedia season page standings, CC BY-SA)
  * ISA World Surfing Games: every heat and wave from data/scores.json (SurfScores)
  * The Eddie: invitees and alternates from collector/events_seed.json (Rip Curl announcement)

Surfers are matched across sources by name (accents and case ignored), so one profile
shows a surfer's CT season, ISA heats and Eddie invite together.
A source that fails keeps its last good data.
"""
import json, os, re, html, unicodedata, datetime as dt
import requests

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
D = os.path.join(ROOT, "data")
OUT = os.path.join(D, "surfers.json")
UA = {"User-Agent": "isa-fantasy-events/1.0 (https://ignitecontentlab.github.io/isa-peru-fantasy-2026/; ignitecontentlab@gmail.com)"}
WIKI = "https://en.wikipedia.org/w/api.php"
NOW = dt.datetime.now(dt.timezone.utc)
ALIASES = {"italo ferreira": "italo ferreira", "caity simmers": "caitlin simmers", "grant baker": "grant twiggy baker"}


def key(name):
    s = unicodedata.normalize("NFKD", re.sub(r"[´’'`]", "", name)).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z ]", "", s.replace("-", " "))
    s = re.sub(r"\s+", " ", s).strip()
    return ALIASES.get(s, s)


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def wiki_sections(page):
    j = requests.get(WIKI, headers=UA, timeout=25, params={"action": "parse", "page": page, "prop": "sections", "format": "json"}).json()
    return {} if "error" in j else {s["line"].strip().lower(): s["index"] for s in j["parse"]["sections"]}


def wiki_text(page, idx):
    j = requests.get(WIKI, headers=UA, timeout=25, params={"action": "parse", "page": page, "prop": "wikitext", "section": idx, "format": "json"}).json()
    return j["parse"]["wikitext"]["*"]


def cell_value(c):
    c = c.strip()
    m = re.match(r'^\s*(?:style|class|rowspan|colspan)="[^"]*"\s*\|(.*)$', c)
    if m:
        c = m.group(1)
    return c.strip()


def plain(s):
    s = re.sub(r"\{\{[^{}]*\}\}", "", s)
    s = re.sub(r"\[\[(?:[^\]|]*\|)?([^\]]*)\]\]", r"\1", s)
    s = re.sub(r"</?s>|'''?|<[^>]+>|&nbsp;", " ", s)
    return html.unescape(re.sub(r"\s+", " ", s)).strip()


def standings(page, section_idx, n_events):
    text = wiki_text(page, section_idx)
    tables = re.findall(r"\{\|(.*?)\n\|\}", text, re.S)
    table = next((t for t in tables if "flagathlete" in t), "")
    out = []
    for chunk in table.split("\n|-")[1:]:
        cells = []
        merged, buf = [], ""
        for ln in chunk.strip().split("\n"):  # join lines where a {{template}} wraps onto the next line
            buf = buf + ln if buf else ln
            if buf.count("{{") <= buf.count("}}"): merged.append(buf); buf = ""
        if buf: merged.append(buf)
        for line in merged:
            line = line.strip()
            if line.startswith(("!", "|")) and not line.startswith(("|+", "|}")):
                cells += re.split(r"\|\||!!", line[1:])
        if len(cells) < 4 or "flagathlete" not in chunk:
            continue
        pos = plain(cell_value(cells[0]))
        who = next(c for c in cells if "flagathlete" in c)
        nm = re.search(r"\[\[(?:[^\]|]*\|)?([^\]]+)\]\]", who)
        if not nm:
            nm = re.search(r"flagathlete\s*\|\s*([^|{}\[\]]+?)\s*\|", who)
        cc = re.search(r"\|\s*([A-Z]{3})\s*\}\}", who)
        i = cells.index(who)
        ev_cells = cells[i + 1:i + 1 + n_events]
        pts = plain(cell_value(cells[-1])).replace(",", "")
        results = []
        for c in ev_cells:
            v = cell_value(c)
            dropped = "<s>" in v
            r = plain(v)
            results.append({"place": r if r not in ("–", "-", "") else "", "dropped": dropped})
        out.append({"name": nm.group(1).strip() if nm else plain(who), "country": cc.group(1) if cc else "",
                    "rank": int(pos) if pos.isdigit() else None, "rank_label": pos,
                    "points": int(pts) if pts.isdigit() else 0, "results": results})
    return out


def ct(year, events):
    page = f"{year} World Surf League"
    secs = wiki_sections(page)
    if not secs:
        return None
    ct_events = [e for e in events if e.get("series") == f"{year} Championship Tour" and e.get("status") != "cancelled"]
    ct_events.sort(key=lambda e: e.get("start") or "")
    names = [e["name"] for e in ct_events]
    res = {}
    for g, title in (("M", "men's standings"), ("W", "women's standings")):
        if title in secs:
            res[g] = standings(page, secs[title], len(names))
    return {"year": year, "events": [{"name": e["name"], "start": e.get("start"), "end": e.get("end"), "id": e["id"]} for e in ct_events],
            "standings": res, "source": f"https://en.wikipedia.org/wiki/{page.replace(' ', '_')}"}


def place_num(p):
    m = re.match(r"(\d+)", p or "")
    return int(m.group(1)) if m else None


def isa():
    sc = load(os.path.join(D, "scores.json"), {})
    heats = sorted(sc.get("heats", {}).values(), key=lambda h: (h.get("g"), h.get("id", 0)))
    people = {}
    for h in heats:
        for s in h.get("surfers", []):
            k = key(s["name"])
            p = people.setdefault(k, {"name": s["name"], "country": s.get("country", ""), "g": h["g"], "heats": 0, "waves": 0,
                                      "best_wave": 0, "best_heat": 0, "sum": 0.0, "wins": 0, "last": None, "all_waves": []})
            if h.get("state") != "completed" and not s.get("total"):
                continue
            p["heats"] += 1
            p["sum"] += s.get("total") or 0
            p["best_heat"] = max(p["best_heat"], s.get("total") or 0)
            w = s.get("waves") or []
            p["waves"] += len(w)
            p["all_waves"] += w
            p["best_wave"] = max([p["best_wave"]] + w)
            if s.get("place") == 1 and h.get("state") == "completed":
                p["wins"] += 1
            p["last"] = {"round": h["round"], "heat": h["heat"], "place": s.get("place"), "state": h.get("state"), "total": s.get("total")}
    out = {}
    for k, p in people.items():
        last = p.pop("last")
        allw = p.pop("all_waves")
        p["avg_heat"] = round(p.pop("sum") / p["heats"], 2) if p["heats"] else 0
        p["avg_wave"] = round(sum(allw) / len(allw), 2) if allw else 0
        p["excellent"] = sum(1 for x in allw if x >= 8)
        out_status = "competing"
        if last and last["state"] == "completed" and "REPECHAGE" in last["round"] and (last["place"] or 0) >= 3:
            out_status = "eliminated"
        if last and "FINAL" in last["round"] and "SEMI" not in last["round"] and "QUARTER" not in last["round"] and last["state"] == "completed":
            out_status = {1: "gold", 2: "silver", 3: "bronze", 4: "copper"}.get(last["place"], "finalist")
        p["status"] = out_status
        p["last"] = last
        out[k] = p
    return out


def main():
    prev = load(OUT, {})
    events = load(os.path.join(D, "events.json"), {}).get("events", [])
    seed = load(os.path.join(ROOT, "collector", "events_seed.json"), {"events": []})["events"]
    sources = {}
    year = NOW.year
    try:
        season = ct(year, events)
        sources["wsl_ct"] = {"ok": bool(season and season["standings"])}
    except Exception as e:
        season = prev.get("ct")
        sources["wsl_ct"] = {"ok": False, "error": str(e)[:200]}
    try:
        isa_p = isa()
        sources["isa"] = {"ok": True, "surfers": len(isa_p)}
    except Exception as e:
        isa_p = {}
        sources["isa"] = {"ok": False, "error": str(e)[:200]}

    S = {}

    def person(name, country, g):
        k = key(name)
        p = S.setdefault(k, {"id": re.sub(" ", "-", k), "name": name, "country": country, "g": g, "tags": []})
        if country and not p["country"]:
            p["country"] = country
        return p

    if season:
        for g, rows in season["standings"].items():
            for r in rows:
                p = person(r["name"], r["country"], g)
                p["name"] = r["name"]  # Wikipedia spelling keeps accents
                places = [n for n in (place_num(x["place"]) for x in r["results"]) if n]
                p["ct"] = {**{k: r[k] for k in ("rank", "rank_label", "points", "results")},
                           "events": len(places), "wins": places.count(1), "finals": sum(1 for x in places if x in (1, 2)),
                           "best": min(places) if places else None,
                           "avg": round(sum(places) / len(places), 1) if places else None}
                p["tags"].append("CT " + ("wildcard" if r["rank_label"] == "WC" else "Men" if g == "M" else "Women"))
    for k, v in isa_p.items():
        p = person(v["name"], v["country"], v["g"])
        p["isa"] = v
        p["tags"].append("ISA 2026")
    for e in seed:
        for role in ("invitees", "alternates"):
            for x in e.get(role, []):
                p = person(x["name"], x["country"], x["g"])
                p["eddie"] = "Invitee" if role == "invitees" else "Alternate"
                p["tags"].append("Eddie " + p["eddie"].lower())

    surfers = sorted(S.values(), key=lambda p: (p.get("ct", {}).get("rank") or 999, -(p.get("isa", {}).get("best_heat") or 0), p["name"]))
    data = {"updated_at": NOW.isoformat(timespec="seconds"), "sources": sources, "ct": season,
            "count": len(surfers), "surfers": surfers,
            "credits": "Championship Tour standings from Wikipedia (CC BY-SA); ISA heats and waves from SurfScores; Eddie roster from Rip Curl."}
    with open(OUT, "w") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    print(json.dumps({"surfers": len(surfers), "sources": sources}))


if __name__ == "__main__":
    main()
