#!/usr/bin/env python3
"""Contest spot guides -> data/places.json

For every event location: the wave/spot, the town, the country, a map, a trip guide and what's nearby.
  - Spot, town, country summaries: Wikipedia (CC BY-SA, linked back)
  - Country facts (capital, population, languages, currency): Wikidata (CC0)
  - Trip guide (Understand, Get in, See, Do, Eat, Drink, Sleep, Stay safe, Go next): Wikivoyage (CC BY-SA)
  - Nearby places: Wikipedia geosearch around the spot's coordinates
collector/places_seed.json maps known locations to the right articles; new event locations are guessed
from their location text the first time they appear.

Usage: places.py          only fills places not yet in data/places.json (cheap, runs hourly)
       places.py --all    refreshes everything (runs weekly)
"""
import json, os, re, sys, time, unicodedata
from datetime import datetime, timezone
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "..", "data")
UA = {"User-Agent": "surf-fantasy-places/1.0 (https://ignitecontentlab.github.io/isa-peru-fantasy-2026/; ignitecontentlab@gmail.com)"}
WP, WV = "https://en.wikipedia.org/w/api.php", "https://en.wikivoyage.org/w/api.php"
GUIDE = ["Understand", "Get in", "Get around", "See", "Do", "Eat", "Drink", "Sleep", "Stay safe", "Go next"]
S = requests.Session(); S.headers.update(UA)


def load(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d


def slug(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40]


def api(url, **params):
    params.update(format="json", formatversion=2)
    for i in range(3):
        try:
            r = S.get(url, params=params, timeout=30); r.raise_for_status(); return r.json()
        except Exception:
            time.sleep(2 + i * 3)
    return {}


def sections(text):
    out, cur = {"_lead": []}, "_lead"
    for line in text.split("\n"):
        m = re.match(r"^(=+)\s*(.+?)\s*=+$", line.strip())
        if m:
            cur = m.group(2) if len(m.group(1)) == 2 else cur
            if len(m.group(1)) == 2: out.setdefault(cur, [])
            continue
        if line.strip(): out.setdefault(cur, []).append(line.strip())
    return out


def page(url, title, chars=1200):
    """Summary, coords, thumb and plain-text sections of a wiki page (follows redirects)."""
    if not title: return None
    j = api(url, action="query", prop="extracts|coordinates|pageimages|description|pageprops", explaintext=1,
            titles=title, redirects=1, piprop="thumbnail", pithumbsize=800, ppprop="disambiguation")
    ps = j.get("query", {}).get("pages", [])
    if not ps or ps[0].get("missing") or "disambiguation" in ps[0].get("pageprops", {}): return None
    p = ps[0]; secs = sections(p.get("extract", ""))
    lead = " ".join(secs.pop("_lead", []))
    c = (p.get("coordinates") or [{}])[0]
    base = "https://en.wikipedia.org/wiki/" if "wikipedia" in url else "https://en.wikivoyage.org/wiki/"
    return {"title": p["title"], "url": base + p["title"].replace(" ", "_"), "desc": p.get("description", ""),
            "summary": trim(lead, chars), "lat": c.get("lat"), "lon": c.get("lon"),
            "thumb": (p.get("thumbnail") or {}).get("source"), "_secs": secs}


def search(url, q):
    j = api(url, action="query", list="search", srsearch=q, srlimit=1)
    h = j.get("query", {}).get("search", [])
    return h[0]["title"] if h else None


def trim(t, n):
    t = re.sub(r"\s+", " ", t or "").strip()
    if len(t) <= n: return t
    cut = t[:n]; k = max(cut.rfind(". "), cut.rfind("! "))
    return cut[: k + 1] if k > n * 0.5 else cut.rsplit(" ", 1)[0] + "…"


def clean(p):
    if p: p.pop("_secs", None)
    return p


def country_facts(title):
    p = page(WP, title, 1100)
    if not p: return None
    j = api(WP, action="query", prop="pageprops", titles=p["title"], ppprop="wikibase_item")
    qid = (j.get("query", {}).get("pages", [{}])[0].get("pageprops") or {}).get("wikibase_item")
    facts = {}
    if qid:
        q = f"""SELECT ?capLabel ?pop ?langLabel ?curLabel ?tzLabel ?flag WHERE {{
          OPTIONAL{{wd:{qid} wdt:P36 ?cap}} OPTIONAL{{wd:{qid} wdt:P1082 ?pop}} OPTIONAL{{wd:{qid} wdt:P37 ?lang}}
          OPTIONAL{{wd:{qid} wdt:P38 ?cur}} OPTIONAL{{wd:{qid} wdt:P41 ?flag}}
          SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" }} }}"""
        try:
            r = S.get("https://query.wikidata.org/sparql", params={"query": q}, headers={"Accept": "application/sparql-results+json"}, timeout=60)
            B = r.json()["results"]["bindings"]
            MAJOR = ["English", "Spanish", "Portuguese", "French", "Arabic", "Mandarin Chinese", "Indonesian", "Japanese", "Filipino"]
            pick = lambda k: sorted({b[k]["value"] for b in B if k in b}, key=lambda x: (MAJOR.index(x) if x in MAJOR else 99, x))
            pops = [int(float(x)) for x in pick("pop")]
            facts = {"capital": ", ".join(pick("capLabel")[:2]), "population": max(pops) if pops else None,
                     "languages": ", ".join(pick("langLabel")[:4]), "currency": ", ".join(pick("curLabel")[:2])}
        except Exception as e:
            print("wikidata country facts failed", title, e)
    surf = page(WP, "Surfing in " + p["title"], 700)
    sections_ = p.pop("_secs", {})
    hist = " ".join(sections_.get("History", [])[:3])
    return {**p, "qid": qid, "facts": facts, "history": trim(hist, 900),
            "surfing": clean(surf) if surf and surf["summary"] else None}


def guide(title):
    p = page(WV, title, 900)
    if not p: return None
    secs = p.pop("_secs", {}); g = {}
    for k in GUIDE:
        lines = secs.get(k, [])
        items = []
        for ln in lines:
            ln = re.sub(r"\(updated [A-Za-z]{3} \d{4}\)", "", ln).strip()
            if len(ln) < 4: continue
            items.append(trim(re.sub(r"^\d+\s+", "", ln), 360))
        if items: g[k] = items[:14]
    p["guide"] = g
    return p


def nearby(lat, lon, skip):
    if lat is None: return []
    j = api(WP, action="query", list="geosearch", gscoord=f"{lat}|{lon}", gsradius=10000, gslimit=40)
    hits = [h for h in j.get("query", {}).get("geosearch", []) if h["title"] not in skip]
    if not hits: return []
    titles = [h["title"] for h in hits[:30]]
    j2 = api(WP, action="query", prop="description|pageimages|extracts", exintro=1, explaintext=1, exsentences=2,
             titles="|".join(titles[:20]), piprop="thumbnail", pithumbsize=320)
    info = {p["title"]: p for p in j2.get("query", {}).get("pages", [])}
    out = []
    for h in hits[:20]:
        p = info.get(h["title"], {})
        d = p.get("description", "")
        if re.search(r"disambiguation|electoral|census|district of|ward\b", d, re.I): continue
        out.append({"title": h["title"], "km": round(h["dist"] / 1000, 1), "desc": d, "summary": trim(p.get("extract", ""), 260),
                    "thumb": (p.get("thumbnail") or {}).get("source"), "url": "https://en.wikipedia.org/wiki/" + h["title"].replace(" ", "_")})
    return out[:16]


def guess(loc):
    parts = [x.strip() for x in re.sub(r"\(.*?\)", "", loc).split(",") if x.strip()]
    if not parts or loc.lower().startswith("to be announced"): return None
    first, last = parts[0], parts[-1]
    return {"name": loc, "spot": first if len(parts) > 1 else None, "town": parts[1] if len(parts) > 2 else first,
            "voyage": parts[1] if len(parts) > 2 else first, "country": last, "match": [first], "guessed": True}


def build(cfg):
    sp = page(WP, cfg.get("spot"), 1400) if cfg.get("spot") else None
    if not sp and cfg.get("spot") and not cfg.get("spot_text"):
        t = search(WP, cfg["spot"] + " surf")
        words = {w for w in re.findall(r"[a-z]{4,}", cfg["spot"].lower())}
        if t and not re.match(r"\d", t) and words & set(re.findall(r"[a-z]{4,}", t.lower())): sp = page(WP, t, 1400)
    spot_secs = sp.pop("_secs", {}) if sp else {}
    surf_txt = " ".join(sum([v for k, v in spot_secs.items() if re.search(r"surf|wave|break", k, re.I)], []))
    if sp: sp["surf"] = trim(surf_txt, 1000)
    if cfg.get("spot_text"):
        sp = {"title": cfg["name"], "summary": cfg["spot_text"]["summary"], "sources": cfg["spot_text"]["sources"], "manual": True,
              "lat": cfg.get("lat"), "lon": cfg.get("lon"), "thumb": None, "url": cfg["spot_text"]["sources"][0][1], "surf": ""}
    town = page(WP, cfg.get("town"), 900); town and town.pop("_secs", None)
    if town and sp and town["title"] == sp["title"]: town = None
    region = clean(page(WP, cfg["region"], 600)) if cfg.get("region") else None
    gd = guide(cfg.get("voyage") or cfg.get("town"))
    lat = cfg.get("lat") or (sp or {}).get("lat") or (town or {}).get("lat") or (gd or {}).get("lat")
    lon = cfg.get("lon") or (sp or {}).get("lon") or (town or {}).get("lon") or (gd or {}).get("lon")
    skip = {x["title"] for x in (sp, town) if x}
    return {"name": cfg["name"], "lat": lat, "lon": lon, "spot": sp, "town": town, "region": region,
            "country_name": cfg.get("country"), "guide": gd, "nearby": nearby(lat, lon, skip),
            "guessed": bool(cfg.get("guessed")), "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def main():
    full = "--all" in sys.argv
    seed = load(os.path.join(HERE, "places_seed.json"), {}).get("places", {})
    E = load(os.path.join(D, "events.json"), {}).get("events", [])
    old = load(os.path.join(D, "places.json"), {})
    places, countries, evmap = old.get("places", {}), old.get("countries", {}), {}
    cfgs = dict(seed)
    for e in E:
        loc = e.get("location") or ""
        sid = next((k for k, c in seed.items() if any(m.lower() in loc.lower() for m in c.get("match", []))), None)
        if not sid:
            g = guess(loc)
            if not g: continue
            sid = slug(loc.split(",")[0]); cfgs.setdefault(sid, g)
        evmap[e["id"]] = sid
    todo = [k for k in set(evmap.values()) if full or k not in places]
    for k in sorted(todo):
        print("place", k)
        try:
            places[k] = build(cfgs[k])
        except Exception as ex:
            print("  failed", ex)
        time.sleep(0.5)
    for k in set(evmap.values()):
        c = (places.get(k) or {}).get("country_name") or cfgs.get(k, {}).get("country")
        if c and (full or c not in countries):
            print("country", c)
            cf = country_facts(c)
            if cf:
                cf["facts"].update(load(os.path.join(HERE, "places_seed.json"), {}).get("country_facts", {}).get(c, {}))
                countries[c] = cf
    out = {"updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "events": evmap,
           "places": places, "countries": countries}
    json.dump(out, open(os.path.join(D, "places.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0, sort_keys=True)
    print("places", len(places), "countries", len(countries), "events", len(evmap))


if __name__ == "__main__":
    main()
