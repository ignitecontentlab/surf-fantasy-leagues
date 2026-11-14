# Surf Pools Backend: Making It Work for Anyone

How the Peru site's backend grows into a platform that any group can use to run a surf pool for any event, without someone babysitting it.

## What runs today (v2.0.0)

- The root URL is now the public stats site: live heats, events, every surfer, rankings and records.
- The Peru friends pool lives at /pool/ and is linked from the footer. Logins for private pools come later.


| Piece | What it does | Where it runs |
|---|---|---|
| Score collector (`collector/collect_isa.py`, `scores.py`) | Reads ISA SurfScores heats and waves into `data/*.json` | GitHub Actions, every 5 min (GitHub actually runs it about every 30 min) |
| Live data worker | Proxies live heat scores to the browser in real time | Cloudflare Worker `isa-proxy` |
| Video worker | Finds the live ISA YouTube stream | Cloudflare Worker `isa-youtube` |
| Events collector (`collector/events.py`) | Builds the Events tab: schedules, winners, go / no-go status, headlines | GitHub Actions, hourly |
| Watchdog (`collector/watchdog.py`) | Checks every part every 15 min, re-runs late jobs, restores broken files, emails problems | GitHub Actions, every 15 min |
| Website | Single page on GitHub Pages; keeps last good data if a source fails | GitHub Pages |

Email alerts go out as GitHub issues in this repo. GitHub emails new issues and comments to the repo owner. Labels: `watchdog` (problems, auto-closed when fixed) and `events-update` (what the events collector changed).

## The idea in one line

Separate the four jobs that are mixed together in the Peru site: **data sources**, **events**, **pools**, and **people**. Then any pool can point at any event, and any event can pull from any source.

## Building blocks

### 1. Source adapters (where scores come from)

Each source is a small module with the same three functions: `schedule()`, `heats(event)`, `live(event)`. Adding a new organization means writing one adapter, not changing the app.

| Adapter | Live scores | Status |
|---|---|---|
| ISA SurfScores | Yes, automatic | Built (Peru) |
| Wikipedia season pages | Final results only | Built (events collector) |
| Rip Curl / Nazaré status feeds | Go / no-go only | Built (events collector) |
| Manual entry screen | Whatever the pool admin types | Next to build |
| WSL | Only with written permission from WSL (their terms prohibit automated collection) | Ask WSL |
| Other organizations' feeds (licensed) | Depends on the deal | Later |

Rule: every adapter writes the same heat format (surfers, waves, totals, places), so scoring and the score bug work for every event.

### 2. Event registry

One list of events (what `data/events.json` already is) with an ID, dates, which adapter feeds it, and its status. Pools pick from this list. Admins can add a custom event and enter results by hand.

### 3. Pool engine

Rules become settings instead of code:

- Buy-in, extra money added (like Jay's $100), payout split (60 / 25 / 15)
- Draft type (snake, random order), rounds per division (3 men, 2 women), order flip for women
- Scoring (ISA points, best single finish, cumulative team)

The Peru rules become the first saved template, and any group can copy it.

### 4. People

Accounts (Google / Apple sign-in, email, phone), invite links, managers, and pool admins. Each pool's data is kept separate from every other pool's data.

### 5. Fail-safe, for every event

The watchdog pattern is reused for every live event. It checks each adapter, keeps the last good data, re-runs late jobs, and alerts the pool admin, not just the owner.

## Where it should live

| Stage | Hosting | Why |
|---|---|---|
| Now (friends' pools) | GitHub Actions + GitHub Pages + 2 Cloudflare Workers | Free for a public repo, already working |
| Next (many pools) | One Cloudflare Worker API + D1 database (the separate Surf Pools Worker you planned) + the same collectors writing into D1 | Accounts and pools need a real database; Workers' free tier covers early traffic |
| Later (public product) | Same, plus a paid Workers plan, backups, and a status page | More traffic, uptime promises |

GitHub's scheduled jobs are best-effort and often run late. Once real money or many users depend on it, move live polling into a Cloudflare Worker cron (Cron Triggers), and keep GitHub Actions as the backup.

## Steps, in order

1. **Manual results screen.** Lets an admin enter heat results for any event, which unlocks WSL events without breaking their terms. This is the fastest way to run a Pipe Masters pool.
2. **Rules as settings.** Move Peru's payout and draft rules into a pool settings object, then rebuild Peru from those settings and confirm the numbers match.
3. **Event picker.** The Surf Pools app reads the event registry, so creating a pool means choosing an event and a rules template.
4. **Accounts and invites** in the Surf Pools Worker and D1 database, with $0 entry while testing.
5. **Adapter interface.** Wrap the ISA code as the first adapter and the manual screen as the second.
6. **Per-pool alerts.** The watchdog emails each pool's admin about that pool's event.
7. **Data permissions.** Email WSL about a data license or a partner arrangement. Until then, WSL events use manual results plus links to WSL's live coverage.
8. **Money (only after legal review).** Paid entry and payouts are regulated differently by country and US state. Get advice for your launch market before taking money. Use a payment provider that supports contests, and keep test mode ($0) until then.

## Things that keep it safe for anyone

- Every source can fail without breaking the site, because the site always has a last good copy.
- Every automatic change is logged in `data/changes.json` and emailed.
- No secrets are stored in the website. Keys live in Cloudflare or GitHub secrets.
- Each pool's data is separate.
- Events and pools never depend on one organization: adapters can be swapped.

## Open fantasy (planned)

- Anyone signs in (login from the Surf Pools project) and picks 5 surfers per event: 3 men and 2 women.
- Leaderboards each event or week: Men (3-man team score), Women (2-woman team score), and Total.
- Unique teams: the first person to save a lineup owns it. If you save the exact same 5, the site asks you to swap at least one surfer. Optional price tiers keep everyone from stacking the same favorites.
- Paid private leagues: friends create a league and pay a service fee. The site never holds or pays out prize money; members settle among themselves. Get a legal review before charging anything.
