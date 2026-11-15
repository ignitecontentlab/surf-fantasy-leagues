#!/usr/bin/env python3
"""Surf news and viral videos -> data/news.json, data/videos.json

News: surf outlets' RSS feeds, plus Google News RSS for outlets that block feed readers and for
general surf coverage. Only headlines, outlet, date and link are kept (people click through to read).
Videos: public YouTube channel feeds (WSL, ISA, Red Bull Surfing, Stab, brands, surfers). YouTube feeds
include view counts, so clips are ranked by views per day since posting ("going viral"). Shorts and
long videos are listed separately. Live streams are skipped.
Surfer names in headlines/titles are tagged so profiles can show "In the news" and "Videos".
"""
import json, os, re, time, unicodedata, html
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "..", "data")
UA = {"User-Agent": "Mozilla/5.0 (compatible; surf-fantasy-media/1.0; +https://ignitecontentlab.github.io/surf-fantasy-leagues/)"}
GN = "https://news.google.com/rss/search?hl=en-US&gl=US&ceid=US:en&q="

NEWS = [
    ("Surfer", "https://www.surfer.com/feed", None),
    ("ISA", "https://isasurf.org/feed/", None),
    ("Stab", GN + "site:stabmag.com+when:7d", "Stab"),
    ("Surfline", GN + "site:surfline.com+when:7d", "Surfline"),
    ("The Inertia", GN + "site:theinertia.com+when:7d", "The Inertia"),
    ("BeachGrit", GN + "site:beachgrit.com+when:7d", "BeachGrit"),
    ("Tracks", GN + "site:tracksmag.com.au+when:7d", "Tracks"),
    ("World Surf League", GN + "site:worldsurfleague.com+when:7d", "World Surf League"),
    ("Surfertoday", GN + "site:surfertoday.com+when:7d", "Surfertoday"),
    ("In the news", GN + "surfing+surfer+when:3d", None),
    ("In the news", GN + "surf+competition+OR+big+wave+when:3d", None),
]

CHANNELS = {
    "UChuLeaTGRcfzo0UjL-2qSbQ": "World Surf League", "UCJEfE-E8DA40SdQG_MXpgiQ": "ISA",
    "UC--3c8RqSfAqYBdDjIG3UNA": "Red Bull Surfing", "UCBXm56zSM934juoKwGLvOzQ": "Stab",
    "UC4i3-yfVazfuqwoz71T79Sw": "Surfline", "UCKo-NbWOxnxBnU41b-AoKeA": "Surfer",
    "UCccOBk6ck17-l_x2THCshdw": "The Inertia", "UCupITk8bqzlfq2egIszumBQ": "Kai Lenny",
    "UC6uX6GF5q2JxLjMkyivM2Og": "Nathan Florence", "UC0gpsoHWwq5RJIzAEFuJwlw": "Koa Smith",
    "UCM7nkBGadxKOa4DAJVFwoWg": "Rip Curl", "UCTYHNSWYy4jCSCj1Q1Fq0ew": "Billabong",
    "UCwMV2FVARycp5_p665_eyZg": "Quiksilver", "UChnzJ9uc4JtCeIDuheRZF1A": "Hurley",
    "UCxjIzJVpyz3P-5NUNVhf3mg": "Mikey February", "UC8bEqBo6HUYBETZZS2AsMlg": "Surf Simply",
    "UCS6dSQUsSpduwJzSfPLTueg": "Jack Robinson", "UCUjMkcyu8kOnW2DQU6JcaxA": "Kanoa Igarashi",
    "UCT3YdhMDklrsRai2nMMlcYA": "Gabriel Medina", "UC7jiV4VwjlKTFIAsYUHS1Mw": "Kelly Slater",
    "UC0VWB9Fc8HugHDf58SNkj_Q": "Wavepool Mag",
}
NS = {"a": "http://www.w3.org/2005/Atom", "m": "http://search.yahoo.com/mrss/", "media": "http://search.yahoo.com/mrss/"}
SURFY = re.compile(r"surf|wave|barrel|tube|swell|wipeout|nazar|pipeline|jaws|teahupo|mavericks|board|ocean|heat|ct\b|wsl|isa\b", re.I)


def key(n):
    n = unicodedata.normalize("NFKD", str(n)).encode("ascii", "ignore").decode().lower()
    return " ".join(re.sub(r"[^a-z ]", " ", n).split())


def load(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d


def get(url):
    r = requests.get(url, headers=UA, timeout=25); r.raise_for_status(); return r.content


def clean(s):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", s or "")).split())


def tagger():
    S = load(os.path.join(D, "surfers.json"), {}).get("surfers", [])
    P = load(os.path.join(D, "profiles.json"), {}).get("profiles", {})
    names = [(s["id"], " " + key(s["name"]) + " ") for s in S if len(key(s["name"])) > 6]
    handles = {}
    for sid, p in P.items():
        m = re.search(r"instagram\.com/([^/?]+)", p.get("socials", {}).get("instagram", ""))
        if m: handles[m.group(1).lower()] = sid
    def tag(text):
        out = [i for i, n in names if n in " " + key(text) + " "]
        for h in re.findall(r"@([A-Za-z0-9._]{3,30})", text or ""):
            sid = handles.get(h.lower().rstrip("."))
            if sid and sid not in out: out.append(sid)
        return out[:6]
    return tag


def news(tag, now):
    items, ok = [], {}
    for label, url, force in NEWS:
        try:
            root = ET.fromstring(get(url))
        except Exception as e:
            ok[label] = f"failed: {type(e).__name__}"; continue
        n = 0
        for it in root.iter("item"):
            title = clean(it.findtext("title")); link = (it.findtext("link") or "").strip()
            src_el = it.find("source"); src = force or (src_el.text if src_el is not None else label)
            if src_el is not None and title.endswith(" - " + (src_el.text or "")): title = title[: -len(src_el.text) - 3]
            try: dt = parsedate_to_datetime(it.findtext("pubDate")).astimezone(timezone.utc)
            except Exception: continue
            if now - dt > timedelta(days=7) or not title or not link: continue
            img = None
            for el in list(it.iter("{http://search.yahoo.com/mrss/}content")) + list(it.iter("{http://search.yahoo.com/mrss/}thumbnail")) + list(it.iter("enclosure")):
                if el.get("url") and re.search(r"\.(jpe?g|png|webp)", el.get("url"), re.I): img = el.get("url"); break
            if not img:
                m = re.search(r'<img[^>]+src="([^"]+)"', (it.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or it.findtext("description") or ""))
                if m: img = m.group(1)
            desc = clean(it.findtext("description"))[:220] if label not in ("In the news",) and "news.google" not in url else ""
            if label == "In the news" and not SURFY.search(title): continue
            if re.search(r"surf report|surf forecast|surf cams?\b|tide chart", title, re.I): continue
            items.append({"title": title, "link": link, "source": src, "at": dt.isoformat(timespec="minutes"),
                          "img": img, "desc": desc, "surfers": tag(title + " " + desc),
                          "kind": "outlet" if label != "In the news" else "media"})
            n += 1
        ok[label] = n
    seen, out = set(), []
    for x in sorted(items, key=lambda x: x["at"], reverse=True):
        k = key(x["title"])[:70]
        if k in seen: continue
        seen.add(k); out.append(x)
    return out[:120], ok


def videos(tag, now, extra):
    chans = dict(CHANNELS); chans.update(extra)
    items, ok = [], {}
    for cid, name in chans.items():
        try:
            root = ET.fromstring(get("https://www.youtube.com/feeds/videos.xml?channel_id=" + cid))
        except Exception as e:
            ok[name] = f"failed: {type(e).__name__}"; continue
        n = 0
        for e in root.findall("a:entry", NS):
            link = e.find("a:link", NS).get("href"); vid = e.findtext("{http://www.youtube.com/xml/schemas/2015}videoId")
            title = e.findtext("a:title", namespaces=NS) or ""
            dt = datetime.fromisoformat(e.findtext("a:published", namespaces=NS).replace("Z", "+00:00"))
            st = e.find("m:group/m:community/m:statistics", NS)
            views = int(st.get("views")) if st is not None and st.get("views") else 0
            age_h = max((now - dt).total_seconds() / 3600, 3)
            if age_h > 24 * 30 or views == 0: continue
            if re.search(r"\blive\b|ao vivo|en vivo|🔴|webcast|replay|full day", title, re.I): continue
            if cid in CHANNELS or SURFY.search(title):
                desc = clean(e.findtext("m:group/m:description", namespaces=NS))[:400]
                items.append({"id": vid, "title": title, "channel": name, "at": dt.isoformat(timespec="minutes"),
                              "views": views, "per_day": round(views / (age_h / 24)), "short": "/shorts/" in link,
                              "link": link, "surfers": tag(title + " " + desc)})
                n += 1
        ok[name] = n
        time.sleep(0.3)
    # viral score: views per day, gently favouring fresh clips
    for x in items:
        age_d = max((now - datetime.fromisoformat(x["at"])).total_seconds() / 86400, 0.15)
        x["score"] = round(x["views"] / (age_d ** 0.8))
    items.sort(key=lambda x: x["score"], reverse=True)
    shorts = [x for x in items if x["short"]][:48]
    long = [x for x in items if not x["short"]][:36]
    return shorts, long, ok


def main():
    now = datetime.now(timezone.utc); tag = tagger()
    prof = load(os.path.join(D, "profiles.json"), {}).get("profiles", {})
    S = {s["id"]: s["name"] for s in load(os.path.join(D, "surfers.json"), {}).get("surfers", [])}
    extra = {}
    for sid, p in prof.items():
        y = p.get("socials", {}).get("youtube", "")
        m = re.search(r"/channel/(UC[\w-]{20,})", y)
        if m and m.group(1) not in CHANNELS: extra[m.group(1)] = S.get(sid, sid)
    N, nok = news(tag, now)
    sh, lo, vok = videos(tag, now, extra)
    old_n = load(os.path.join(D, "news.json"), {}); old_v = load(os.path.join(D, "videos.json"), {})
    ts = now.isoformat(timespec="seconds")
    # never wipe good data with an empty run
    if N or not old_n.get("items"):
        json.dump({"updated_at": ts, "sources": nok, "items": N}, open(os.path.join(D, "news.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    if sh or lo or not (old_v.get("shorts") or old_v.get("videos")):
        json.dump({"updated_at": ts, "channels": vok, "shorts": sh, "videos": lo}, open(os.path.join(D, "videos.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    print("news", len(N), nok); print("shorts", len(sh), "videos", len(lo)); print({k: v for k, v in vok.items() if not isinstance(v, int)})


if __name__ == "__main__":
    main()
