#!/usr/bin/env python3
"""Events hub collector -> data/events.json, data/changes.json

Sources (all open, no keys):
  * Wikipedia season pages ("2026 World Surf League", next year when it appears):
    Championship Tour schedule + event winners. Licensed CC BY-SA.
  * collector/events_seed.json: events Wikipedia does not list (big wave, ISA, Olympics, QS).
  * Rip Curl event news feed (Atom) for The Eddie go / no-go news.
  * nazarewaves.com news page headline for the Nazare alert status.
  * Google News RSS for recent headlines per event.

WSL's own site is NOT read automatically (its terms prohibit automated collection).

Any meaningful change (new event, new dates, status change, winners posted, alert) is
written to data/changes.json and to $NOTIFY_FILE (markdown) so the workflow can email it.
A source that fails keeps the last good value and is reported in events.json "sources".
"""
import json, os, re, sys, hashlib, html, datetime as dt
import xml.etree.ElementTree as ET
import requests

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
D = os.path.join(ROOT, "data")
SEED = os.path.join(ROOT, "collector", "events_seed.json")
OUT = os.path.join(D, "events.json")
LOG = os.path.join(D, "changes.json")
NOTIFY = os.environ.get("NOTIFY_FILE", "")
UA = {"User-Agent": "isa-fantasy-events/1.0 (https://ignitecontentlab.github.io/isa-peru-fantasy-2026/; ignitecontentlab@gmail.com)"}
WIKI = "https://en.wikipedia.org/w/api.php"
NOW = dt.datetime.now(dt.timezone.utc)
TODAY = NOW.date()
MONTHS = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july",
                                       "august", "september", "october", "november", "december"], 1)}
FLAGS = {"australia": "AUS", "new zealand": "NZL", "el salvador": "ESA", "brazil": "BRA", "tahiti": "PYF",
         "fiji": "FIJ", "united states": "USA", "portugal": "POR", "phi": "PHI", "philippines": "PHI",
         "uae": "UAE", "hawaii": "HAW", "south africa": "RSA", "mexico": "MEX", "france": "FRA", "japan": "JPN"}
sources = {}


def get(url, headers=None, **kw):
    r = requests.get(url, headers=headers or UA, timeout=25, **kw)
    r.raise_for_status()
    return r


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


# ---------------- Wikipedia: WSL Championship Tour ----------------
def clean(cell):
    s = re.sub(r"<ref[^>]*/>|<ref.*?</ref>", "", cell, flags=re.S)
    flag = re.search(r"\{\{\s*flag(?:icon|athlete)?\s*\|\s*([^}|]+)", s, re.I)
    s = re.sub(r"\{\{[^}]*\}\}", "", s)
    s = re.sub(r"\[\[(?:[^\]|]*\|)?([^\]]*)\]\]", r"\1", s)
    s = re.sub(r"</?s>|'''?|<[^>]+>", "", s)
    s = html.unescape(s).strip()
    code = flag.group(1).strip() if flag else ""
    return s, FLAGS.get(code.lower(), code.upper()[:3] if code else "")


def wiki_section(page, title):
    j = get(WIKI, params={"action": "parse", "page": page, "prop": "sections", "format": "json"}).json()
    if "error" in j:
        return None
    for s in j["parse"]["sections"]:
        if s["line"].strip().lower() == title.lower():
            t = get(WIKI, params={"action": "parse", "page": page, "prop": "wikitext",
                                  "section": s["index"], "format": "json"}).json()
            return t["parse"]["wikitext"]["*"]
    return ""


def table_rows(text):
    m = re.search(r"\{\|(.*?)\n\|\}", text, re.S)
    if not m:
        return []
    rows = []
    for chunk in m.group(1).split("\n|-")[1:]:
        cells = []
        for line in chunk.strip().split("\n"):
            line = line.strip()
            if line.startswith(("!", "|")) and not line.startswith("|+"):
                cells += [c for c in re.split(r"\|\||!!", line[1:])]
        if cells:
            rows.append(cells)
    return rows


def parse_dates(txt, year):
    t = txt.replace("–", "-").replace("—", "-").lower()
    m = re.match(r"\s*([a-z]+)\s+(\d+)\s*-\s*(?:([a-z]+)\s+)?(\d+)", t)
    if not m or m.group(1) not in MONTHS:
        return "", ""
    m1, d1, m2, d2 = MONTHS[m.group(1)], int(m.group(2)), MONTHS.get(m.group(3) or m.group(1)), int(m.group(4))
    y2 = year + (1 if m2 < m1 else 0)
    return dt.date(year, m1, d1).isoformat(), dt.date(y2, m2, d2).isoformat()


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def wsl_season(year):
    page = f"{year} World Surf League"
    sched = wiki_section(page, "Schedule")
    if sched is None:
        return None  # page does not exist yet
    results = wiki_section(page, "Event results") or ""
    winners = {}
    for r in table_rows(results):
        if len(r) < 6:
            continue
        ev, _ = clean(r[1])
        vals = [clean(c) for c in r[2:6]]
        winners[norm(ev)] = {k: {"name": v[0], "country": v[1]} for k, v in
                             zip(["men_champ", "men_runner", "women_champ", "women_runner"], vals) if v[0]}
    out = []
    for r in table_rows(sched):
        if len(r) < 4:
            continue
        cancelled = "<s>" in r[0] or "<s>" in r[1]
        rnd, _ = clean(r[0])
        name, country = clean(r[2])
        loc, _ = clean(r[3])
        start, end = parse_dates(clean(r[1])[0], year)
        if not name:
            continue
        ev = {"id": f"wsl-ct-{year}-{norm(name)[:24]}", "name": name, "org": "WSL", "host": "WSL",
              "series": f"{year} Championship Tour", "round": rnd, "start": start, "end": end,
              "location": loc, "country": country, "kind": "contest", "live": "link",
              "pool": "Draft pool: 3 men, 2 women" if not cancelled else "",
              "official": "https://www.worldsurfleague.com/events",
              "watch": "https://www.youtube.com/@wsl/streams",
              "news": f"{name} surf", "source": f"https://en.wikipedia.org/wiki/{page.replace(' ', '_')}"}
        if cancelled:
            ev["status_override"] = "cancelled"
        w = winners.get(norm(name))
        if w:
            ev["results"] = w
        if "pipe" in norm(name):
            ev["pool"] = "Best fit: same draft format as Peru. World titles decided here."
        out.append(ev)
    return out


# ---------------- Status watchers ----------------
EDDIE_ON = re.compile(r"\b(green light|is on\b|it'?s on\b|will run|will go|the eddie goes|called on|holding ceremony|go call)", re.I)
EDDIE_DONE = re.compile(r"\b(wins|winner|champion|crowned)\b", re.I)


def watch_eddie(ev):
    feed = get("https://www.ripcurl.com/blogs/events.atom").text
    ns = {"a": "http://www.w3.org/2005/Atom"}
    root = ET.fromstring(feed)
    hits = []
    for e in root.findall("a:entry", ns):
        title = e.findtext("a:title", "", ns)
        pub = e.findtext("a:published", "", ns)
        link = e.find("a:link", ns).get("href")
        if "eddie" not in title.lower():
            continue
        try:
            age = (NOW - dt.datetime.fromisoformat(pub)).days
        except Exception:
            age = 999
        hits.append({"title": title, "date": pub[:10], "url": link, "age": age})
    ev["official_news"] = hits[:3]
    recent = [h for h in hits if h["age"] <= 4]
    if any(EDDIE_DONE.search(h["title"]) for h in recent) and TODAY >= dt.date.fromisoformat(ev["start"]):
        return "completed", recent[0]["title"]
    if any(EDDIE_ON.search(h["title"]) for h in recent):
        return "on", recent[0]["title"]
    return None, ""


def watch_nazare(ev):
    t = get("https://nazarewaves.com/en/news", headers={"User-Agent": "Mozilla/5.0"}).text
    t = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t))
    m = re.search(r"[Bb]ig [Ww]ave [Cc]hallenge 20\d\d/(?:20)?\d\d\s*[–-]\s*([A-Z][A-Z \-]{3,40})", t)
    phrase = re.sub(r"\s+[A-Z]$", "", m.group(1).strip()) if m else ""
    ev["alert_text"] = phrase.title() if phrase else ""
    if "GREEN" in phrase or re.search(r"\bON\b|CALLED", phrase):
        return "on", phrase.title()
    if "YELLOW" in phrase:
        return "alert", phrase.title()
    if "COMPLETE" in phrase or "WINNER" in phrase:
        return "completed", phrase.title()
    return None, phrase.title()


# ---------------- News ----------------
def news(query, keyword):
    url = "https://news.google.com/rss/search"
    r = get(url, params={"q": f"{query} when:14d", "hl": "en-US", "gl": "US", "ceid": "US:en"})
    root = ET.fromstring(r.content)
    out, kw = [], [w for w in re.findall(r"[a-zé]{4,}", keyword.lower()) if w not in ("surf", "surfing", "world", "games")]
    for it in root.iter("item"):
        title = it.findtext("title") or ""
        if kw and not any(k in title.lower() for k in kw):
            continue
        try:
            d = dt.datetime.strptime(it.findtext("pubDate"), "%a, %d %b %Y %H:%M:%S %Z").date().isoformat()
        except Exception:
            d = ""
        src = it.find("source")
        out.append({"title": re.sub(r"\s+-\s+[^-]+$", "", title), "date": d,
                    "source": src.text if src is not None else "", "url": it.findtext("link")})
        if len(out) >= 4:
            break
    return sorted(out, key=lambda x: x["date"], reverse=True)


# ---------------- Status ----------------
def status_of(ev):
    if ev.get("status_override"):
        return ev["status_override"]
    if not ev.get("start"):
        return "tba"
    s, e = dt.date.fromisoformat(ev["start"]), dt.date.fromisoformat(ev["end"] or ev["start"])
    if ev.get("results", {}).get("men_champ") or ev.get("results", {}).get("women_champ"):
        return "completed"
    if TODAY < s:
        return "upcoming"
    if TODAY <= e:
        return "window" if ev.get("kind") == "window" else "live"
    return "did_not_run" if ev.get("kind") == "window" else "finished"


KEY_FIELDS = ("name", "start", "end", "status", "location", "alert_text")


def describe(old, new):
    msgs = []
    if old is None:
        return [f"New event added: **{new['name']}** ({new.get('start') or 'dates TBA'} to {new.get('end') or 'TBA'})"]
    for k in KEY_FIELDS:
        if (old.get(k) or "") != (new.get(k) or ""):
            label = {"alert_text": "alert", "start": "start date", "end": "end date"}.get(k, k)
            msgs.append(f"**{new['name']}**: {label} changed from `{old.get(k) or '-'}` to `{new.get(k) or '-'}`")
    ow, nw = old.get("results") or {}, new.get("results") or {}
    for k, v in nw.items():
        if (ow.get(k) or {}).get("name") != v.get("name"):
            label = {"men_champ": "Men's winner", "women_champ": "Women's winner",
                     "men_runner": "Men's runner-up", "women_runner": "Women's runner-up"}[k]
            msgs.append(f"**{new['name']}**: {label} posted: {v['name']}")
    return msgs


def main():
    prev = load(OUT, {})
    prev_ev = {e["id"]: e for e in prev.get("events", [])}
    seed = load(SEED, {"events": []})["events"]
    events = []

    # WSL CT seasons from Wikipedia: this year and next (next appears automatically once published)
    for year in (TODAY.year, TODAY.year + 1):
        key = f"wikipedia_{year}"
        try:
            got = wsl_season(year)
            if got is None:
                sources[key] = {"ok": True, "note": "season page not published yet"}
                continue
            events += got
            sources[key] = {"ok": True, "events": len(got)}
        except Exception as e:
            sources[key] = {"ok": False, "error": str(e)[:200]}
            events += [v for v in prev_ev.values() if v["id"].startswith(f"wsl-ct-{year}-")]

    ids = {e["id"] for e in events}
    events += [dict(e) for e in seed if e["id"] not in ids]

    for ev in events:
        old = prev_ev.get(ev["id"], {})
        w = ev.get("watcher")
        if w:
            try:
                st, why = (watch_eddie if w == "eddie" else watch_nazare)(ev)
                if st:
                    ev["status_override"] = st
                ev["watch_note"] = why
                sources[w] = {"ok": True}
            except Exception as e:
                sources[w] = {"ok": False, "error": str(e)[:200]}
                for k in ("status_override", "watch_note", "alert_text", "official_news"):
                    if k in old:
                        ev[k] = old[k]
        ev["status"] = status_of(ev)
        # News: refresh every 3 hours, or every run while the event is live / window open
        stale = (NOW - dt.datetime.fromisoformat(old.get("news_at", "2000-01-01T00:00:00+00:00"))).total_seconds() > 3 * 3600
        relevant = ev["status"] in ("live", "window", "on", "alert", "upcoming") or ev["status"] == "completed" and ev.get("end", "") >= (TODAY - dt.timedelta(days=21)).isoformat()
        if ev.get("news") and relevant and (stale or ev["status"] in ("live", "on", "alert")):
            try:
                ev["headlines"] = news(ev["news"], ev["name"])
                ev["news_at"] = NOW.isoformat(timespec="seconds")
                sources["news"] = {"ok": True}
            except Exception as e:
                sources["news"] = {"ok": False, "error": str(e)[:200]}
                ev["headlines"], ev["news_at"] = old.get("headlines", []), old.get("news_at", "")
        else:
            ev["headlines"], ev["news_at"] = old.get("headlines", []), old.get("news_at", "2000-01-01T00:00:00+00:00")

    order = {"on": 0, "live": 0, "alert": 1, "window": 2, "upcoming": 3, "tba": 4, "completed": 5,
             "finished": 6, "did_not_run": 7, "cancelled": 8}
    events.sort(key=lambda e: (order.get(e["status"], 9), e.get("start") or "9999"))

    # Changes -> log + notify
    changes = []
    for ev in events:
        for m in describe(prev_ev.get(ev["id"]) if prev_ev else {}, ev) if prev_ev else []:
            changes.append({"at": NOW.isoformat(timespec="seconds"), "event": ev["id"], "text": m,
                            "important": ev["status"] in ("on", "alert", "live") or "winner" in m.lower() or "status" in m})
    gone = set(prev_ev) - {e["id"] for e in events}
    for g in gone:
        changes.append({"at": NOW.isoformat(timespec="seconds"), "event": g,
                        "text": f"Event no longer listed by its source: **{prev_ev[g]['name']}** (kept off the page; check if it was cancelled)",
                        "important": True})

    data = {"updated_at": NOW.isoformat(timespec="seconds"),
            "content_hash": "", "sources": sources, "events": events,
            "credits": "Schedules and results from Wikipedia (CC BY-SA), Rip Curl, nazarewaves.com and Google News headlines."}
    body = json.dumps(events, sort_keys=True)
    data["content_hash"] = hashlib.sha1(body.encode()).hexdigest()[:12]
    if prev.get("content_hash") == data["content_hash"] and not changes:
        data["updated_at"] = prev.get("updated_at", data["updated_at"])
    data["checked_at"] = NOW.isoformat(timespec="seconds")
    with open(OUT, "w") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)

    if changes:
        log = load(LOG, {"changes": []})
        log["changes"] = (changes + log["changes"])[:200]
        with open(LOG, "w") as f:
            json.dump(log, f, indent=1, ensure_ascii=False)
    # only email a failing source the first time it fails (the watchdog follows up if it stays down)
    failed = [k for k, v in sources.items() if not v.get("ok") and prev.get("sources", {}).get(k, {}).get("ok", True)]
    if NOTIFY and (changes or failed):
        with open(NOTIFY, "w") as f:
            f.write("The events collector ran and updated the site automatically.\n\n")
            if changes:
                f.write("### What changed\n" + "\n".join(f"- {c['text']}" for c in changes) + "\n\n")
            if failed:
                f.write("### Sources that failed (last good data kept)\n" +
                        "\n".join(f"- {k}: {sources[k].get('error')}" for k in failed) + "\n\n")
            f.write("Review: https://ignitecontentlab.github.io/isa-peru-fantasy-2026/#events\n")
    print(json.dumps({"events": len(events), "changes": len(changes), "sources": sources}, indent=1))


if __name__ == "__main__":
    main()
