"""Find today's ISA YouTube streams (English, Spanish, Podium 2) and write data/youtube.json.
Never fails the workflow: on any error it keeps the previous file."""
import json, re, sys, datetime, pathlib
import requests

URL = "https://www.youtube.com/@isasurfing/streams"
OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "youtube.json"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Cookie": "CONSENT=YES+1; SOCS=CAI",
}

def parse(html):
    out, seen = [], set()
    for m in re.finditer(r'"videoId":"([\w-]{11})"', html):
        vid = m.group(1)
        if vid in seen:
            continue
        seg = html[m.end():m.end() + 3000]
        t = re.search(r'"(?:title|headline)":\{(?:"runs":\[\{"text"|"simpleText"|"content"):"(.*?)"', seg)
        if not t:
            continue
        seen.add(vid)
        title = t.group(1)
        try:
            title = json.loads('"' + title + '"')
        except Exception:
            pass
        out.append({"id": vid, "title": title, "live": "LIVE_NOW" in seg[:2500]})
        if len(out) >= 30:
            break
    return out

def pick(items):
    wsg = [v for v in items if re.search(r"World Surfing Games", v["title"], re.I)]
    not_p2 = [v for v in wsg if not re.search(r"podium\s*2", v["title"], re.I)]
    es = next((v for v in not_p2 if re.search(r"(competencia|d[ií]a\s*\d|finales|en vivo)", v["title"], re.I)), None)
    en = next((v for v in not_p2 if v is not es and not re.search(r"(competencia|finales|en vivo)", v["title"], re.I)
               and re.search(r"(competition day|finals|live!|day\s*\d)", v["title"], re.I)), None)
    ref = (en or es or {}).get("title", "")
    lab = re.search(r"(Competition Day \d+|Finals Day|Competencia D[ií]a \d+|Finales)", ref, re.I)
    n = re.search(r"d[ií]a\s*(\d+)|day\s*(\d+)", ref, re.I)
    day_no = (n.group(1) or n.group(2)) if n else None
    finals = bool(re.search(r"final", ref, re.I))
    p2 = None
    for v in wsg:
        if re.search(r"podium\s*2", v["title"], re.I) and (
            re.search(r"final", v["title"], re.I) if finals else (day_no and re.search(r"day\s*" + day_no + r"(?!\d)", v["title"], re.I))):
            p2 = v
            break
    return {"en": en, "es": es, "p2": p2, "label": lab.group(1) if lab else ""}

def main():
    try:
        r = requests.get(URL, headers=HEADERS, timeout=25)
        r.raise_for_status()
        items = parse(r.text)
        if not items:
            raise RuntimeError("no videos found on channel page")
        data = {"ok": True, "checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), **pick(items), "recent": items[:8]}
        if not data["en"] or not data["es"]:
            raise RuntimeError("could not identify English/Spanish streams")
        old = {}
        if OUT.exists():
            try:
                old = json.loads(OUT.read_text())
            except Exception:
                pass
        # Only rewrite when the chosen streams change, to avoid a commit every 5 minutes.
        keys = lambda d: [(d.get(k) or {}).get("id") for k in ("en", "es", "p2")] + [d.get("label")]
        if keys(old) == keys(data) and old.get("ok"):
            print("youtube: unchanged", keys(data))
            return
        OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1))
        print("youtube: updated", keys(data))
    except Exception as e:
        print("youtube: skipped -", e, file=sys.stderr)

if __name__ == "__main__":
    main()
