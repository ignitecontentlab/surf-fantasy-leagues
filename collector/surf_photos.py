#!/usr/bin/env python3
"""Credited surf photos for page banners -> data/surf_photos.json

Only freely licensed photos from Wikimedia Commons are used (CC BY, CC BY-SA, CC0, public domain; no
NonCommercial or NoDerivatives licences). Each photo keeps its photographer, licence and file page so the
site can credit it under the picture. data/surf_photos_manual.json adds photos shared with written
permission and the photographers' social handles ("social": {"instagram": "handle"}), keyed by file page or id.
"""
import json, os, re, time
import requests

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
API = "https://commons.wikimedia.org/w/api.php"
HDR = {"User-Agent": "surf-fantasy-leagues-photos/1.0 (https://ignitecontentlab.github.io/surf-fantasy-leagues/)"}
CATS = {
    "peru": ["Surfing in Peru", "Punta Rocas", "Chicama"], "elsalvador": ["Surfing in El Salvador", "Surfing locations in El Salvador"],
    "pipeline": ["Banzai Pipeline", "Surfing at Banzai Pipeline"], "hawaii": ["Surfing in Hawaii", "Sunset Beach, Hawaii"],
    "nazare": ["Big wave surfing in Nazaré", "Praia do Norte (Nazaré)"], "bells": ["Bells Beach, Victoria"],
    "teahupoo": ["Teahupoo", "Surfing at the 2024 Summer Olympics"], "contest": ["Surfing competitions", "World Surf League"],
    "longboard": ["Longboard (surfing)"], "action": ["Surfing in California", "Surfing in Australia"],
}
OK = re.compile(r"^(CC BY(-SA)? [\d.]+|CC0|Public domain|PD|CC BY(-SA)?$)", re.I)
BAD = re.compile(r"NC|ND", re.I)
SKIP = re.compile(r"dog|business district|stirling|map|logo|flag|diagram|poster|stamp|coat of arms|\.svg|\.tif|\.gif|drawing|museum|statue|shop|store|board shorts|sign\b", re.I)


def strip(s): return " ".join(re.sub(r"<[^>]+>", " ", s or "").split())


def href(s):
    m = re.search(r'href="([^"]+)"', s or "")
    if not m: return None
    u = m.group(1); return "https:" + u if u.startswith("//") else u


def members(cat):
    r = requests.get(API, headers=HDR, timeout=30, params={
        "action": "query", "format": "json", "generator": "categorymembers", "gcmtitle": "Category:" + cat,
        "gcmtype": "file", "gcmlimit": 60, "prop": "imageinfo", "iiprop": "url|size|extmetadata", "iiurlwidth": 1600})
    return list(r.json().get("query", {}).get("pages", {}).values())


def main():
    old = {p["page"]: p for p in json.load(open(os.path.join(D, "surf_photos.json"), encoding="utf-8")).get("photos", [])} if os.path.exists(os.path.join(D, "surf_photos.json")) else {}
    manual = json.load(open(os.path.join(D, "surf_photos_manual.json"), encoding="utf-8")) if os.path.exists(os.path.join(D, "surf_photos_manual.json")) else {}
    out, seen = [], set()
    for tag, cats in CATS.items():
        n = 0
        for cat in cats:
            try: pages = members(cat)
            except Exception as e: print("skip", cat, e); continue
            for p in pages:
                ii = (p.get("imageinfo") or [{}])[0]; m = ii.get("extmetadata", {})
                lic = (m.get("LicenseShortName", {}).get("value") or "").strip()
                w, h = ii.get("width", 0), ii.get("height", 0)
                if p["title"] in seen or SKIP.search(p["title"]) or not OK.match(lic) or BAD.search(lic): continue
                if w < 1400 or h < 700 or w < h * 1.25: continue
                if m.get("Restrictions", {}).get("value"): continue
                artist = strip(m.get("Artist", {}).get("value")) or "Unknown photographer"
                if len(artist) > 70: artist = artist[:70].rsplit(" ", 1)[0]
                seen.add(p["title"])
                out.append({"id": p["title"][5:], "tag": tag, "src": ii.get("thumburl") or ii.get("url"), "page": ii.get("descriptionurl"),
                            "author": artist, "author_url": href(m.get("Artist", {}).get("value")),
                            "license": lic, "license_url": m.get("LicenseUrl", {}).get("value"),
                            "caption": strip(m.get("ImageDescription", {}).get("value"))[:140]})
                n += 1
                if n >= 8: break
            time.sleep(0.5)
            if n >= 8: break
        print(tag, n)
    for p in out:
        x = manual.get(p["page"]) or manual.get(p["id"])
        if x: p.update(x)
    for k, x in manual.items():
        if k.startswith("_"): continue
        if x.get("src") and x.get("own") and not any(p["page"] == k for p in out): out.append({"id": k, **x})
    out = [p for p in out if not p.get("hide")]
    if out or not old:
        json.dump({"updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "photos": out},
                  open(os.path.join(D, "surf_photos.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    print("photos", len(out))


if __name__ == "__main__":
    main()
