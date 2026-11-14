#!/usr/bin/env python3
"""Surfer bios -> data/bios.json

For each surfer: who they are, where they're from and live, stance, how they surf, the road to the tour,
family and background, career highlights. Sources (all free licences, linked back on the site):
  - Wikipedia article text, split into its sections (lead, early life, career, style, personal life)
  - Wikipedia infobox (stance, hometown, residence, nickname, height)
  - Wikidata (birthplace, birth date, residence)
  - collector/bios_manual.json  hand-written notes that override or fill gaps
New names are looked up the first time they appear (hourly run). Everyone is refreshed every 30 days
(weekly --all run refreshes only entries older than 30 days, so it stays light).
"""
import json, os, re, sys, time, unicodedata
from datetime import datetime, timezone, timedelta
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "..", "data")
WP = "https://en.wikipedia.org/w/api.php"
S = requests.Session(); S.headers.update({"User-Agent": "surf-fantasy-bios/1.0 (https://ignitecontentlab.github.io/isa-peru-fantasy-2026/; ignitecontentlab@gmail.com)"})
NOW = datetime.now(timezone.utc)
GROUPS = [("background", r"early life|childhood|background|biograph|family|personal|youth|upbringing"),
          ("road", r"career|professional|competit|amateur|junior|rookie|qualif|tour|olymp"),
          ("style", r"style|technique|approach"),
          ("highlights", r"victor|wins|titles|achievement|honou?rs|record|accomplish|result")]
SKIP = r"references|external links|see also|notes|further reading|filmography|bibliography"


def load(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d


def key(n):
    n = unicodedata.normalize("NFKD", str(n)).encode("ascii", "ignore").decode().lower()
    return " ".join(re.sub(r"[^a-z ]", " ", n).split())


def api(**params):
    params.update(format="json", formatversion=2)
    for i in range(3):
        try:
            r = S.get(WP, params=params, timeout=30); r.raise_for_status(); return r.json()
        except Exception:
            time.sleep(2 + 3 * i)
    return {}


def trim(t, n):
    t = re.sub(r"\s+", " ", t or "").strip()
    if len(t) <= n: return t
    cut = t[:n]; k = cut.rfind(". ")
    return cut[: k + 1] if k > n * 0.5 else cut.rsplit(" ", 1)[0] + "…"


def sitelinks(qids):
    out = {}
    for i in range(0, len(qids), 50):
        r = {}
        for t in range(4):
            try:
                r = S.get("https://www.wikidata.org/w/api.php", params={"action": "wbgetentities", "ids": "|".join(qids[i:i + 50]),
                          "props": "sitelinks", "sitefilter": "enwiki", "format": "json"}, timeout=30).json(); break
            except Exception:
                time.sleep(5 + 10 * t)
        for q, e in r.get("entities", {}).items():
            t = e.get("sitelinks", {}).get("enwiki", {}).get("title")
            if t: out[q] = t
    return out


def wd_facts(qids):
    out = {}
    for i in range(0, len(qids), 80):
        vals = " ".join("wd:" + q for q in qids[i:i + 80])
        q = f"""SELECT ?p ?bpLabel ?dob ?resLabel ?h WHERE {{ VALUES ?p {{ {vals} }}
          OPTIONAL{{?p wdt:P19 ?bp}} OPTIONAL{{?p wdt:P569 ?dob}} OPTIONAL{{?p wdt:P551 ?res}} OPTIONAL{{?p wdt:P2048 ?h}}
          SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" }} }}"""
        try:
            B = S.get("https://query.wikidata.org/sparql", params={"query": q}, headers={"Accept": "application/sparql-results+json"}, timeout=90).json()["results"]["bindings"]
        except Exception as e:
            print("wikidata facts failed", e); continue
        for b in B:
            f = out.setdefault(b["p"]["value"].rsplit("/", 1)[-1], {})
            if "bpLabel" in b and not re.match(r"Q\d+$", b["bpLabel"]["value"]): f.setdefault("born_in", b["bpLabel"]["value"])
            if "dob" in b: f.setdefault("born", b["dob"]["value"][:10])
            if "resLabel" in b and not re.match(r"Q\d+$", b["resLabel"]["value"]): f.setdefault("lives", b["resLabel"]["value"])
            if "h" in b: f.setdefault("height_m", b["h"]["value"])
    return out


def find_title(name):
    j = api(action="query", list="search", srsearch=f'"{name}" surfer', srlimit=3)
    last = key(name).split()[-1] if key(name) else ""
    for h in j.get("query", {}).get("search", []):
        if last and last in key(h["title"]) and re.search(r"surf", h.get("snippet", ""), re.I):
            return h["title"]
    return None


def wikitext_cleanup(v):
    v = re.sub(r"<ref[^>]*/>|<ref[^>]*>.*?</ref>|<!--.*?-->", "", v, flags=re.S)
    v = re.sub(r"\{\{(?:flag(?:icon|u)?|nowrap)\|([^}|]+)[^}]*\}\}", r"\1", v, flags=re.I)
    v = re.sub(r"\{\{[^{}]*\}\}", "", v)
    v = re.sub(r"\[\[(?:[^|\]]*\|)?([^\]]+)\]\]", r"\1", v)
    v = re.sub(r"<br\s*/?>", ", ", v); v = re.sub(r"<[^>]+>|'''?", "", v)
    return " ".join(v.split()).strip(" ,")


def infobox(title):
    j = api(action="query", prop="revisions", rvprop="content", rvslots="main", rvsection=0, titles=title)
    try: txt = j["query"]["pages"][0]["revisions"][0]["slots"]["main"]["content"]
    except Exception: return {}
    out = {}
    for f, k in (("stance", "stance"), ("hometown", "hometown"), ("residence", "lives"), ("nickname", "nickname"),
                 ("birth_place", "born_in_text"), ("height", "height"), ("sponsors", "sponsors"), ("years_active", "years_active")):
        m = re.search(r"^[ \t]*\|[ \t]*" + f + r"[ \t]*=[ \t]*([^\n]+)$", txt, re.M | re.I)
        if m and not m.group(1).strip().startswith("|"):
            v = wikitext_cleanup(m.group(1))
            if v and len(v) < 160: out[k] = v
    if "stance" in out:
        s = out["stance"].lower()
        out["stance"] = "Goofy (right foot forward)" if "goofy" in s else "Regular (left foot forward)" if "regular" in s or "natural" in s else out["stance"]
    return out


def article(title):
    j = api(action="query", prop="extracts|description|info", explaintext=1, titles=title, redirects=1, inprop="url")
    ps = j.get("query", {}).get("pages", [])
    if not ps or ps[0].get("missing"): return None
    p = ps[0]; text = p.get("extract", "")
    secs, cur = {"_lead": []}, "_lead"
    for line in text.split("\n"):
        m = re.match(r"^(=+)\s*(.+?)\s*=+$", line.strip())
        if m:
            if len(m.group(1)) == 2: cur = m.group(2); secs.setdefault(cur, [])
            continue
        if line.strip(): secs.setdefault(cur, []).append(line.strip())
    out = {"title": p["title"], "url": "https://en.wikipedia.org/wiki/" + p["title"].replace(" ", "_"),
           "desc": p.get("description", ""), "summary": trim(" ".join(secs.pop("_lead")), 900)}
    if not re.search(r"surf", out["desc"] + out["summary"], re.I): return None
    for g, rx in GROUPS:
        parts = [(k, v) for k, v in secs.items() if re.search(rx, k, re.I) and not re.search(SKIP, k, re.I) and v]
        if parts:
            used = {k for k, _ in parts}
            for k in used: secs.pop(k, None)
            body = " ".join(" ".join(v) for _, v in parts)
            out[g] = trim(body, 1500 if g == "road" else 900)
    return out


def main():
    full = "--all" in sys.argv
    SU = load(os.path.join(D, "surfers.json"), {}).get("surfers", [])
    PR = load(os.path.join(D, "profiles.json"), {}).get("profiles", {})
    manual = load(os.path.join(HERE, "bios_manual.json"), {})
    old = load(os.path.join(D, "bios.json"), {}).get("bios", {})
    stale = lambda b: not b or NOW - datetime.fromisoformat(b.get("checked_at", "2000-01-01T00:00:00+00:00")) > timedelta(days=30)
    todo = [s for s in SU if s["id"] not in old or (full and stale(old.get(s["id"])))]
    print("to look up:", len(todo), "of", len(SU))
    qids = {s["id"]: PR.get(s["id"], {}).get("wikidata") for s in todo if PR.get(s["id"], {}).get("wikidata")}
    titles = sitelinks(sorted(set(qids.values()))) if qids else {}
    facts = wd_facts(sorted(set(qids.values()))) if qids else {}
    bios = dict(old)
    for i, s in enumerate(todo):
        q = qids.get(s["id"]); t = titles.get(q) if q else None
        if not t: t = find_title(s["name"])
        b = {"checked_at": NOW.isoformat(timespec="seconds")}
        if t:
            a = article(t)
            if a:
                b["wiki"] = a; b.update({k: v for k, v in infobox(a["title"]).items()})
        if q and q in facts: b.update({k: v for k, v in facts[q].items() if k not in b})
        bios[s["id"]] = b
        if i % 25 == 0: print(i, s["name"], "->", (b.get("wiki") or {}).get("title"))
        time.sleep(0.2)
    for sid, m in manual.items():
        if sid in bios and isinstance(m, dict): bios[sid].update(m); bios[sid]["manual"] = True
    found = sum(1 for b in bios.values() if b.get("wiki"))
    json.dump({"updated_at": NOW.isoformat(timespec="seconds"), "count": len(bios), "with_wikipedia": found, "bios": bios},
              open(os.path.join(D, "bios.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0, sort_keys=True)
    print("bios", len(bios), "with Wikipedia", found)


if __name__ == "__main__":
    main()
