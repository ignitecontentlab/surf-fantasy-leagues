"""Official WSL event rosters, read from the event's own results / heat-draw page.

worldsurfleague.com/events/<year>/<tour>/<id>/<slug>/results lists every heat of every round
for each division (men's and women's are separate statEventIds). Each surfer block carries the
WSL athlete id, full name, country and an "eliminated" class, so we get the full field plus who
is still in the event.
"""
import html as H, re, requests

HDR = {"User-Agent": "Mozilla/5.0 (compatible; fantasy-collector)"}
BASE = "https://www.worldsurfleague.com"


def _get(url):
    r = requests.get(url, headers=HDR, timeout=30)
    r.raise_for_status()
    return r.text


def _size(name):
    n = (name or "").lower()
    if "semi" in n:
        return 4
    if "quarter" in n:
        return 8
    if "final" in n:
        return 2
    m = re.search(r"(\d+)", n)
    return int(m.group(1)) if m else None


def _athletes(page):
    out = []
    for m in re.finditer(r'class="hot-heat-athlete ([^"]*)"\s+data-athlete-id="(\d+)"', page):
        cls, aid = m.group(1), m.group(2)
        seg = page[m.end(): m.end() + 4000]
        n = re.search(r'hot-heat-athlete__name--full">([^<]+)<', seg)
        if not n:
            continue
        c = re.search(r'athlete-country-flag[^>]*title="([^"]+)"', seg)
        pl = re.search(r"athlete-place-(\d+)", cls)
        out.append({"id": aid, "name": H.unescape(n.group(1)).strip(), "country": H.unescape(c.group(1)) if c else "",
                    "out": "--eliminated" in cls, "place": int(pl.group(1)) if pl else None})
    return out


def _rounds(page):
    rs, seen = [], set()
    for m in re.finditer(r'href="[^"]*results\?roundId=(\d+)[^"]*"[^>]*?click_text&quot;:&quot;([^&]+)&quot;', page):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            rs.append((m.group(1), H.unescape(m.group(2))))
    return rs


def roster(event_url):
    """event_url: https://www.worldsurfleague.com/events/2026/qs/506/taiwan-open-of-surfing
    Returns {"men": [...], "women": [...], "divisions": {...}} or None."""
    url = event_url.rstrip("/").removesuffix("/main").removesuffix("/results") + "/results"
    first = _get(url)
    divs = re.findall(r'results\?statEventId=(\d+)"[^>]*title="([^"]+)"', first)
    if not divs:
        divs = [(None, "Men's Heats")]
    R = {"men": {}, "women": {}}
    meta = {}
    for sid, title in dict.fromkeys(divs):
        d = "women" if "women" in title.lower() else "men"
        page = first if sid is None else _get(url + "?statEventId=" + sid)
        rounds = _rounds(page)
        meta[d] = {"statEventId": sid, "rounds": [r[1] for r in rounds]}
        for i, (rid, rname) in enumerate(rounds):
            try:
                rp = _get(url + "?roundId=" + rid + ("&statEventId=" + sid if sid else ""))
            except Exception:
                continue
            for a in _athletes(rp):
                s = R[d].setdefault(a["id"], {"wsl_id": a["id"], "name": a["name"], "country": a["country"], "out": False, "place": None, "first_round": i})
                if a["out"]:
                    s["out"] = True
                    s["elim"] = i
    for d in R:
        L = sorted(R[d].values(), key=lambda s: (s["out"], -s["first_round"], s["name"]))  # still in first, seeds (enter later) first
        # finish = 1 + everyone who lasted longer (ties for surfers knocked out in the same round)
        for s in L:
            if s["out"]:
                s["place"] = 1 + sum(1 for q in L if not q["out"] or q.get("elim", -1) > s["elim"])
        for s in L:
            s.pop("first_round", None)
            s.pop("elim", None)
        R[d] = L
    return {"men": R["men"], "women": R["women"], "divisions": meta, "url": url}


def find_event_url(name, year):
    """Look the event up on the official WSL schedule by name."""
    try:
        page = _get(f"{BASE}/events?all=1&year={year}")
    except Exception:
        return None
    want = set(re.findall(r"[a-z0-9]+", (name or "").lower())) - {"the", "of", "pro", "open", "surfing", str(year)}
    best, score = None, 0
    for path, slug in set(re.findall(r'href="(?:https://www\.worldsurfleague\.com)?(/events/%d/[a-z]+/\d+/([a-z0-9-]+))' % year, page)):
        got = set(slug.split("-"))
        if any(t in want and t not in got for t in ("junior", "longboard")):
            continue
        if "junior" not in want and "junior" in got or "longboard" not in want and "longboard" in got:
            continue
        sc = len(want & got)
        if sc > score:
            best, score = BASE + path, sc
    strict = bool(want & {"junior", "longboard"})  # many junior/longboard events share words, so demand a closer match
    return best if score and (not strict or score * 2 >= len(want)) else None
