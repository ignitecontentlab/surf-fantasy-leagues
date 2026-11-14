#!/usr/bin/env python3
"""Fail-safe watchdog. Runs every 15 minutes in GitHub Actions.

Checks: live site, data workers, collector freshness, events freshness, Pages deploys,
and that every data/*.json file is valid. It repairs what it can by itself:
  * re-runs a late or failed collector (workflow_dispatch)
  * restores a broken data file from the last good git version
  * keeps scheduled workflows alive (GitHub pauses them after 60 days without commits)
Then it emails the owner through a GitHub issue (GitHub sends issue emails to the repo
owner). One issue per problem; it comments and closes the issue once fixed.
State lives in data/watchdog.json, which the site reads for its status panel.
"""
import json, os, glob, subprocess, datetime as dt
import requests

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
D = os.path.join(ROOT, "data")
STATE = os.path.join(D, "watchdog.json")
REPO = os.environ.get("GITHUB_REPOSITORY", "ignitecontentlab/isa-peru-fantasy-2026")
OWNER = REPO.split("/")[0]
SITE = f"https://{OWNER}.github.io/{REPO.split('/')[1]}/"
NOW = dt.datetime.now(dt.timezone.utc)
LIVE_UNTIL = os.environ.get("LIVE_UNTIL", "2026-11-16")  # collector is expected to run until this date
FORCE_TEST = os.environ.get("WATCHDOG_TEST") == "true"
checks, actions = {}, []


def sh(*a, check=False):
    p = subprocess.run(a, capture_output=True, text=True, cwd=ROOT)
    if check and p.returncode:
        raise RuntimeError(p.stderr.strip()[:300])
    return p.stdout.strip()


def ago(iso):
    try:
        return (NOW - dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))).total_seconds() / 60
    except Exception:
        return 1e9


def last_run(workflow, ok_only=False):
    args = ["gh", "run", "list", "-R", REPO, "-w", workflow, "-L", "5", "--json", "conclusion,createdAt,status,databaseId"]
    try:
        runs = json.loads(sh(*args, check=True) or "[]")
    except Exception as e:
        return None, str(e)
    done = [r for r in runs if r["status"] == "completed"]
    good = [r for r in done if r["conclusion"] == "success"]
    return {"last": runs[0] if runs else None, "last_success": good[0] if good else None,
            "recent_failures": sum(1 for r in done[:3] if r["conclusion"] not in ("success", "cancelled", "skipped"))}, ""


def dispatch(workflow, why):
    try:
        sh("gh", "workflow", "run", workflow, "-R", REPO, check=True)
        actions.append(f"Re-ran the **{workflow}** workflow because {why}.")
        return True
    except Exception as e:
        actions.append(f"Tried to re-run **{workflow}** ({why}) but GitHub refused: {e}")
        return False


def check_site():
    try:
        r = requests.get(SITE + f"?wd={int(NOW.timestamp())}", timeout=20)
        ok = r.status_code == 200 and "VERSION='" in r.text
        checks["site"] = {"ok": ok, "detail": f"HTTP {r.status_code}" + ("" if ok else " (page missing its version tag)")}
    except Exception as e:
        checks["site"] = {"ok": False, "detail": str(e)[:150]}


def check_url(key, url, label):
    try:
        r = requests.get(url, timeout=20)
        checks[key] = {"ok": r.status_code < 500, "detail": f"{label}: HTTP {r.status_code}"}
    except Exception as e:
        checks[key] = {"ok": False, "detail": f"{label}: {str(e)[:120]}"}


def check_json_files():
    bad = []
    for path in sorted(glob.glob(os.path.join(D, "*.json"))):
        name = os.path.relpath(path, ROOT)
        try:
            with open(path) as f:
                json.load(f)
        except Exception:
            bad.append(name)
            # find the most recent committed version that parses, and restore it
            for rev in sh("git", "log", "-n", "20", "--format=%H", "--", name).split():
                blob = subprocess.run(["git", "show", f"{rev}:{name}"], capture_output=True, text=True, cwd=ROOT).stdout
                try:
                    json.loads(blob)
                except Exception:
                    continue
                with open(path, "w") as f:
                    f.write(blob)
                actions.append(f"Restored `{name}` from commit {rev[:7]} because the current file was broken.")
                break
    checks["data_files"] = {"ok": not bad, "detail": "all valid" if not bad else "broken: " + ", ".join(bad)}


def check_collectors():
    live_season = NOW.date().isoformat() <= LIVE_UNTIL
    info, err = last_run("collect")
    if info is None:
        checks["collector"] = {"ok": False, "detail": "could not read workflow runs: " + err}
    else:
        ls = info["last_success"]
        mins = ago(ls["createdAt"]) if ls else 1e9
        ok = (mins < 75 and info["recent_failures"] < 3) or not live_season
        checks["collector"] = {"ok": ok, "detail": f"last success {int(mins)} min ago, {info['recent_failures']} of last 3 failed"}
        if not ok and not (info["last"] and info["last"]["status"] in ("queued", "in_progress")):
            dispatch("collect", f"its last successful run was {int(mins)} minutes ago")
    info, err = last_run("events")
    if info is not None:
        ls = info["last_success"]
        mins = ago(ls["createdAt"]) if ls else 1e9
        ok = mins < 240
        checks["events"] = {"ok": ok or not ls, "detail": f"last success {int(mins)} min ago" if ls else "first run pending"}
        if not ok and not (info["last"] and info["last"]["status"] in ("queued", "in_progress")):
            dispatch("events", f"events were last refreshed {int(mins)} minutes ago")
    info, _ = last_run("pages")
    if info and info["last"]:
        checks["pages"] = {"ok": info["recent_failures"] < 2, "detail": f"{info['recent_failures']} of last 3 deploys failed"}
        if info["recent_failures"] >= 2:
            dispatch("pages", "the last site deploys failed")
    ev = {}
    try:
        with open(os.path.join(D, "events.json")) as f:
            ev = json.load(f)
        bad = [k for k, v in ev.get("sources", {}).items() if not v.get("ok")]
        checks["event_sources"] = {"ok": not bad, "detail": "all sources answering" if not bad else "failing: " + ", ".join(bad) + " (last good data kept)"}
    except Exception:
        pass


def keepalive():
    last = sh("git", "log", "-1", "--format=%cI")
    if last and ago(last) > 40 * 24 * 60:
        actions.append("Saved a keep-alive commit so GitHub does not pause the scheduled jobs.")
        return True
    return False


def issue(title, body, labels="watchdog"):
    sh("gh", "label", "create", labels, "-R", REPO, "--color", "d73a4a", "-f")
    out = sh("gh", "issue", "create", "-R", REPO, "--title", title, "--body", body + f"\n\n@{OWNER}", "--label", labels)
    return out


def main():
    state = {}
    try:
        with open(STATE) as f:
            state = json.load(f)
    except Exception:
        pass
    open_issues = state.get("open_issues", {})
    fails = state.get("fail_counts", {})

    check_site()
    check_url("data_worker", "https://isa-proxy.ignitecontentlab.workers.dev/?src=live", "live data worker")
    check_url("video_worker", "https://isa-youtube.ignitecontentlab.workers.dev/", "video worker")
    check_json_files()
    check_collectors()
    beat = keepalive()

    gh_ok = True
    for key, c in checks.items():
        fails[key] = 0 if c["ok"] else fails.get(key, 0) + 1
        # email after 2 bad checks in a row (30 min) so short blips do not spam you
        if not c["ok"] and fails[key] >= 2 and key not in open_issues:
            fixes = "\n".join(f"- {a}" for a in actions) or "- Nothing could be fixed automatically yet; it will keep retrying every 15 minutes."
            url = issue(f"Watchdog: {key.replace('_', ' ')} needs attention",
                        f"**Problem:** {c['detail']}\n\n**What the watchdog did:**\n{fixes}\n\n"
                        f"The site keeps showing the last good data meanwhile. This issue closes itself when fixed.\n\nSite: {SITE}")
            if url:
                open_issues[key] = url
            else:
                gh_ok = False
        if c["ok"] and key in open_issues:
            sh("gh", "issue", "close", open_issues.pop(key), "-R", REPO, "-c",
               f"Fixed: {c['detail']}. Checked {NOW:%Y-%m-%d %H:%M} UTC.")

    # Auto-fixes that succeeded on their own still get a short email (you asked to know when it ran something)
    restored = [a for a in actions if a.startswith("Restored")]
    if restored or FORCE_TEST:
        issue("Watchdog test: email alerts are working" if FORCE_TEST else "Watchdog fixed something automatically",
              ("This is a test alert. If you got this email, alerts work.\n\n" if FORCE_TEST else "") +
              "\n".join(f"- {a}" for a in actions or ["No problems found."]) +
              "\n\nCurrent checks:\n" + "\n".join(f"- {'OK' if c['ok'] else 'PROBLEM'} · {k}: {c['detail']}" for k, c in checks.items()))

    new = {"checked_at": NOW.isoformat(timespec="seconds"), "ok": all(c["ok"] for c in checks.values()),
           "checks": checks, "open_issues": open_issues, "fail_counts": fails,
           "last_actions": (actions + state.get("last_actions", []))[:20] if actions else state.get("last_actions", []),
           "last_action_at": NOW.isoformat(timespec="seconds") if actions else state.get("last_action_at", ""),
           "heartbeat": NOW.isoformat(timespec="seconds") if beat else state.get("heartbeat", "")}
    # write only when something changed (or hourly) to keep the commit history light
    sig = lambda s: json.dumps([s.get("ok"), {k: v.get("ok") for k, v in (s.get("checks") or {}).items()},
                                s.get("open_issues"), s.get("last_actions"), s.get("heartbeat")], sort_keys=True)
    old_sig, new_sig = sig(state), sig(new)
    if old_sig != new_sig or ago(state.get("checked_at", "2000-01-01T00:00:00+00:00")) > 60 or beat:
        with open(STATE, "w") as f:
            json.dump(new, f, indent=1)
    print(json.dumps(new, indent=1))


if __name__ == "__main__":
    main()
