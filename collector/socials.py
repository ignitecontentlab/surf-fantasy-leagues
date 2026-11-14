#!/usr/bin/env python3
"""Surfer socials and photos -> data/profiles.json

Sources, in priority order:
  1. collector/socials_manual.json  (hand-checked handles and photo overrides; always wins)
  2. Wikidata  (Instagram P2003, TikTok P7085, YouTube P2397, X P2002, Facebook P2013, website P856,
                photo P18 from Wikimedia Commons, which is freely licensed)
  3. collector/socials_found.json   (handles found by web search; only used where 1 and 2 are empty)

Photos are only taken from Wikimedia Commons (free licence, credit link kept). Instagram profile pictures
are not copied: they belong to the surfer and Instagram blocks automated reading. Surfers without a free
photo show initials on the site.
"""
import json, os, re, unicodedata, urllib.parse
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "..", "data")
UA = {"User-Agent": "surf-fantasy-socials/1.0 (https://ignitecontentlab.github.io/isa-peru-fantasy-2026/; ignitecontentlab@gmail.com)"}
FIELDS = {"ig": "instagram", "tt": "tiktok", "yt": "youtube", "x": "x", "fb": "facebook", "web": "website"}

Q = """SELECT ?p ?pLabel ?alt ?ig ?tt ?yt ?x ?fb ?web ?img WHERE {
  { ?p wdt:P106 wd:Q13561328 } UNION { ?p wdt:P641 wd:Q159992 }
  ?p wdt:P31 wd:Q5 .
  OPTIONAL{?p wdt:P2003 ?ig} OPTIONAL{?p wdt:P7085 ?tt} OPTIONAL{?p wdt:P2397 ?yt}
  OPTIONAL{?p wdt:P2002 ?x} OPTIONAL{?p wdt:P2013 ?fb} OPTIONAL{?p wdt:P856 ?web} OPTIONAL{?p wdt:P18 ?img}
  OPTIONAL{?p skos:altLabel ?alt FILTER(LANG(?alt) IN ("en","pt","es","fr"))}
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en,pt,es,fr,ja" }
}"""


def key(n):
    n = unicodedata.normalize("NFKD", str(n)).encode("ascii", "ignore").decode().lower().replace("-", " ")
    return " ".join(re.sub(r"[^a-z ]", "", n).split())


def load(p, d):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return d


def wikidata():
    r = requests.post("https://query.wikidata.org/sparql", data={"query": Q},
                      headers={**UA, "Accept": "application/sparql-results+json"}, timeout=120)
    r.raise_for_status()
    people = {}
    for b in r.json()["results"]["bindings"]:
        q = b["p"]["value"].rsplit("/", 1)[-1]
        p = people.setdefault(q, {"qid": q, "names": set(), "s": {}, "img": None})
        p["names"].add(key(b["pLabel"]["value"]))
        if "alt" in b: p["names"].add(key(b["alt"]["value"]))
        for k, f in FIELDS.items():
            if k in b: p["s"].setdefault(f, b[k]["value"])
        if "img" in b and not p["img"]: p["img"] = b["img"]["value"]
    idx = {}
    for p in people.values():
        for n in p["names"]:
            idx.setdefault(n, []).append(p)
    return idx


def commons(file_url):
    name = urllib.parse.unquote(file_url.rsplit("/", 1)[-1])
    return {"src": "https://commons.wikimedia.org/wiki/Special:FilePath/" + urllib.parse.quote(name) + "?width=400",
            "page": "https://commons.wikimedia.org/wiki/File:" + urllib.parse.quote(name.replace(" ", "_")),
            "credit": "Wikimedia Commons"}


def url_for(f, h):
    h = str(h).strip().lstrip("@")
    if h.startswith("http"): return h
    return {"instagram": f"https://www.instagram.com/{h}/", "tiktok": f"https://www.tiktok.com/@{h}",
            "youtube": f"https://www.youtube.com/channel/{h}" if h.startswith("UC") else f"https://www.youtube.com/@{h}",
            "x": f"https://x.com/{h}", "facebook": f"https://www.facebook.com/{h}"}.get(f, h)


def main():
    S = load(os.path.join(D, "surfers.json"), {}).get("surfers", [])
    manual = load(os.path.join(HERE, "socials_manual.json"), {})
    found = load(os.path.join(HERE, "socials_found.json"), {})
    old = load(os.path.join(D, "profiles.json"), {}).get("profiles", {})
    try:
        idx = wikidata(); wd_ok = True
    except Exception as e:
        print("wikidata failed, keeping old data:", e); idx = {}; wd_ok = False
    out, stats = {}, {"wikidata": 0, "search": 0, "manual": 0, "photos": 0}
    for s in S:
        sid, prof = s["id"], {"socials": {}, "src": {}}
        hits = idx.get(key(s["name"]), [])
        if len(hits) == 1:  # skip ambiguous names
            w = hits[0]; prof["wikidata"] = w["qid"]
            for f, h in w["s"].items():
                prof["socials"][f] = url_for(f, h); prof["src"][f] = "wikidata"
            if w["img"]: prof["photo"] = commons(w["img"])
            stats["wikidata"] += 1
        elif not wd_ok and sid in old:
            prof = old[sid]
        fd = found.get(sid) or {}
        for f in FIELDS.values():
            if fd.get(f) and f not in prof["socials"]:
                prof["socials"][f] = url_for(f, fd[f]); prof["src"][f] = "search"; stats["search"] += 1
        m = manual.get(sid) or {}
        for f in FIELDS.values():
            if f in m:
                if m[f]: prof["socials"][f] = url_for(f, m[f]); prof["src"][f] = "manual"
                else: prof["socials"].pop(f, None)
        if m.get("photo"): prof["photo"] = m["photo"]
        if m: stats["manual"] += 1
        if prof.get("photo"): stats["photos"] += 1
        if prof["socials"] or prof.get("photo"): out[sid] = prof
    from datetime import datetime, timezone
    json.dump({"updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "stats": stats,
               "count": len(out), "profiles": out}, open(os.path.join(D, "profiles.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=0, sort_keys=True)
    print("profiles", len(out), stats)


if __name__ == "__main__":
    main()
