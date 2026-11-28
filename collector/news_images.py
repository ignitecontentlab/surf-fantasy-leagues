"""Story thumbnails for the news feed.

Google News RSS links are redirect links, so each one is turned into the publisher's real article URL,
then the article's own share image (og:image / twitter:image) is read. That is the picture the publisher
chose for link previews; the site shows it next to the headline with the outlet named, and the card links
to the full story. Results are cached in data/news_meta.json so each article is looked up only once.
Generic share images (site logos, default cards) are skipped so the site shows its own tile instead.
"""
import html, json, os, re, time
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "..", "data", "news_meta.json")
BUA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"}
GENERIC = re.compile(r"share[-_]?default|default[-_]?(share|og|image)|placeholder|/logo|logo[-_.]|favicon|blank\.|apple-touch|social[-_]?card[-_]?default", re.I)
OG = [re.compile(p, re.I | re.S) for p in (
    r'<meta[^>]+(?:property|name)=["\'](?:og:image(?::secure_url)?|twitter:image(?::src)?)["\'][^>]*?content=["\']([^"\']+)',
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*?(?:property|name)=["\'](?:og:image|twitter:image)')]


def decode_gn(u):
    gid = u.split("/articles/")[1].split("?")[0]
    r = requests.get(f"https://news.google.com/articles/{gid}", headers=BUA, timeout=15)
    sg = re.search(r'data-n-a-sg="([^"]+)"', r.text); ts = re.search(r'data-n-a-ts="([^"]+)"', r.text)
    if not (sg and ts): return None
    inner = ["garturlreq", [["X", "X", ["X", "X"], None, None, 1, 1, "US:en", None, 1, None, None, None, None, None, 0, 1],
             "X", "X", 1, [1, 1, 1], 1, 1, None, 0, 0, None, 0], gid, int(ts.group(1)), sg.group(1)]
    body = "f.req=" + requests.utils.quote(json.dumps([[["Fbv4je", json.dumps(inner)]]]))
    r = requests.post("https://news.google.com/_/DotsSplashUi/data/batchexecute", data=body, timeout=15,
                      headers={**BUA, "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
    out = json.loads(json.loads(r.text.split("\n\n")[1])[0][2])[1]
    return out if isinstance(out, str) and out.startswith("http") else None


def og_image(u):
    r = requests.get(u, headers=BUA, timeout=15)
    t = r.text[:400000]
    for p in OG:
        m = p.search(t)
        if m:
            img = html.unescape(m.group(1)).strip()
            if img.startswith("//"): img = "https:" + img
            if img.startswith("http") and not GENERIC.search(img): return img
            return None
    return None


def enrich(items, budget=45, pause=1.2):
    try: cache = json.load(open(CACHE, encoding="utf-8"))
    except Exception: cache = {}
    done = 0
    for it in items:
        k = it["link"]
        c = cache.get(k)
        retry = c is not None and not c.get("url") and c.get("n", 1) < 4 and time.time() - c.get("t", 0) > 6 * 3600
        if (c is None or retry) and done < budget:
            done += 1; c = {"url": None, "img": None, "t": int(time.time()), "n": (c or {}).get("n", 0) + 1}
            try:
                url = decode_gn(k) if "news.google." in k else k
                c["url"] = url
                if url: c["img"] = og_image(url)
            except Exception as e:
                c["err"] = type(e).__name__
            cache[k] = c; time.sleep(pause)
        if c:
            if c.get("url"): it["gn"] = k if "news.google." in k else None; it["link"] = c["url"]
            if not it.get("img") and c.get("img"): it["img"] = c["img"]
        if it.get("img") and GENERIC.search(it["img"]): it["img"] = None
        it.pop("gn", None) if not it.get("gn") else None
    keep = {it.get("gn") or it["link"] for it in items}
    cache = {k: v for k, v in cache.items() if k in keep or time.time() - v.get("t", 0) < 14 * 86400}
    json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    return done
