#!/usr/bin/env python3
"""Every wave score for every heat -> data/scores.json (feeds the Top scores tab).

SurfScores' results pages list each heat with a numeric heat id (showHeat(event, id)).
getlive.php returns that heat's full wave-by-wave scores when catname is given.
Only heats that are new, or whose totals changed on the results page, are refetched.
"""
import json, os, re, time, datetime as dt
import requests
from bs4 import BeautifulSoup

EVENT = "PER2026ISAWSG"
BASE = "https://surfscores.com/PER/2026/isawsg/"
LIVE = "https://surfscores.com/scoreboard/getlive.php?eventid=%s&catname=%s&heatid=%s"
HDR = {"User-Agent": "Mozilla/5.0 (compatible; fantasy-collector)"}
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
OUT = os.path.join(D, "scores.json")


def num(s):
    try:
        return float((s or "").strip().replace(",", "."))
    except ValueError:
        return None


def results_heats(page):
    r = requests.get(BASE + page, headers=HDR, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.content, "html.parser")
    out = []
    for wrap in soup.select("div.tablewrap"):
        state = [c for c in wrap.get("class", []) if c != "tablewrap"]
        t = wrap.find("table", class_="heattab")
        if not t:
            continue
        m = re.search(r"showHeat\(\s*[\"']?([A-Z0-9]+)[\"']?\s*,\s*(\d+)\)", t.get("onclick", ""))
        if not m:
            continue
        rows = []
        for tr in t.find_all("tr")[1:]:
            td = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
            if len(td) >= 4 and td[1]:
                rows.append((td[1], num(td[3]), td[2][:3].upper(), int(td[4]) if len(td) > 4 and td[4].strip().isdigit() else None))
        sect = wrap.find_parent("div", class_="content")
        rnd = next((c.replace("-", " ") for c in (sect.get("class", []) if sect else []) if c != "content" and re.match(r"[A-Z]", c)), "")
        th = t.find("th")
        hm = re.search(r"HEAT\s*(\d+)", th.get_text(" ", strip=True) if th else "", re.I)
        out.append({"ev": m.group(1), "id": int(m.group(2)), "state": state[0] if state else "", "round": rnd,
                    "heat": int(hm.group(1)) if hm else (1 if rnd == "FINAL" else None),
                    "totals": sorted(r[1] for r in rows if r[1] is not None),
                    "rows": [{"name": r[0], "country": r[2], "place": r[3], "total": r[1], "waves": []} for r in rows]})
    return out


def heat_detail(ev, cat, hid):
    r = requests.get(LIVE % (ev, cat, hid), headers=HDR, timeout=30)
    r.raise_for_status()
    j = r.json()
    if str(j.get("heat")) != str(hid):
        return None
    sc = BeautifulSoup(j.get("scores", ""), "html.parser")
    cols = {}
    for td in sc.select("td.scorecol"):
        head = td.select_one("div.head")
        c = re.search(r"background-color:\s*(#[0-9A-Fa-f]+)", head.get("style", "")) if head else None
        if c:
            cols[c.group(1).upper()] = [(num(a.get_text()), "topscore" in a.get("class", [])) for a in td.select("div.avg")]
    st = BeautifulSoup(j.get("standings", ""), "html.parser")
    surfers = []
    for s in st.select("div.surfer"):
        pl = s.select_one("div.place")
        c = re.search(r"background-color:\s*(#[0-9A-Fa-f]+)", pl.get("style", "")) if pl else None
        pn = re.match(r"\d+", pl.get_text(strip=True)) if pl else None
        nm = s.select_one("div.name")
        if not nm or not nm.get_text(strip=True):
            continue
        col = [w for w in (cols.get(c.group(1).upper(), []) if c else []) if w[0] is not None]
        waves = [w for w, _ in col]
        counted = [i for i, (_, top) in enumerate(col) if top]
        surfers.append({
            "name": nm.get_text(strip=True),
            "country": (s.select_one("div.info").get_text(strip=True) if s.select_one("div.info") else "")[:3].upper(),
            "place": int(pn.group()) if pn else None,
            "total": num(s.select_one("div.score").get_text(strip=True)) if s.select_one("div.score") else None,
            "waves": waves,
            "counted": counted,
        })
    parts = [p.strip() for p in str(j.get("CatDescr", "")).split(" - ")]
    hm = re.search(r"HEAT\s*(\d+)", parts[-1] if parts else "", re.I)
    if parts and parts[0].upper() in ("MEN", "WOMEN"):
        parts = parts[1:]
    return {"round": parts[0] if len(parts) > 1 else "", "heat": int(hm.group(1)) if hm else None,
            "status": str(j.get("heatstatus", "")).upper(), "surfers": surfers}


def main():
    store = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {"heats": {}}
    heats = store.setdefault("heats", {})
    fetched = 0
    for div, cat, page in (("M", "MEN", "men.php"), ("W", "WOMEN", "women.php")):
        try:
            listing = results_heats(page)
        except Exception as e:
            print(page, "error", e)
            continue
        for h in listing:
            if h["state"] not in ("completed", "running"):
                continue
            key = f"{div}{h['ev']}:{h['id']}"
            old = heats.get(key)
            if old and h["round"]:
                old["round"], old["heat"] = h["round"], h["heat"] or old.get("heat")
            # Finished heats are fetched once; refetched only if the results page totals change.
            if old and h["state"] == "completed" and old.get("state") == "completed" and old.get("totals") == h["totals"] and (not old.get("no_waves") or old.get("checked", 0) > time.time() - 6 * 3600):
                continue
            try:
                d = heat_detail(h["ev"], cat, h["id"])
            except Exception as e:
                print(key, "error", e)
                continue
            if not d or not d["surfers"] or any(x["name"] == "Results Unavailable" for x in d["surfers"]):
                # SurfScores has no wave detail for this heat: keep the results-page totals so heat rankings stay complete.
                if not h["rows"]:
                    continue
                d = {"round": h["round"], "heat": h["heat"], "status": "", "surfers": h["rows"], "no_waves": True}
            d["round"] = h["round"] or d["round"]
            d["heat"] = h["heat"] or d["heat"]
            d.update({"g": div, "ev": h["ev"], "id": h["id"], "state": h["state"], "totals": h["totals"], "checked": int(time.time())})
            heats[key] = d
            fetched += 1
            time.sleep(0.25)
    store["updated_utc"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tmp = OUT + ".tmp"
    json.dump(store, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, OUT)
    print("scores.json heats:", len(heats), "fetched this run:", fetched)


if __name__ == "__main__":
    main()
