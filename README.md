# Asifah Analytics — Asia Backend

Backend API for the Asifah Analytics Asia-Pacific Conflict Probability Dashboard.

## Overview

Monitors geopolitical conflict probability across eight Asia-Pacific countries using multi-source OSINT: NewsAPI, GDELT (6 languages), Google News RSS, Reddit, and optional Telegram signal integration.

**Targets:** Afghanistan · China · India · Japan · North Korea · Pakistan · South Korea · Taiwan

## Architecture

- **Runtime:** Python 3 / Flask on Render (Web Service)
- **Caching:** Upstash Redis (persistent) + in-memory (4-hour TTL)
- **Background refresh:** Daemon thread refreshes all country caches every 4 hours
- **GDELT languages:** English, Mandarin (zho), Korean (kor), Urdu (urd), Dari (prs), Japanese (jpn)

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/asia/threat/<target>` | Threat assessment for a single country |
| `GET /api/asia/dashboard` | All country scores in one call |
| `GET /api/asia/notams` | Asia-Pacific NOTAMs (FAA API) |
| `GET /api/asia/flights` | Flight disruption monitor |
| `GET /api/asia/travel-advisories` | State Dept travel advisories |
| `GET /api/asia/cache-status` | Cache freshness for all targets |
| `GET /health` | Health check |

Append `?force=true` to any endpoint to bypass cache and run a live scan.

## Environment Variables

Set these in Render → Environment:

| Variable | Description |
|---|---|
| `NEWSAPI_KEY` | NewsAPI.org API key |
| `UPSTASH_REDIS_URL` | Upstash Redis REST URL |
| `UPSTASH_REDIS_TOKEN` | Upstash Redis REST token |

## Deployment

1. Connect `SassAndSweet/asifah-asia-backend` repo to a new Render **Web Service**
2. Set environment variables above
3. Start command: `gunicorn app:app --timeout 120 --workers 2`
4. Add UptimeRobot monitor pointing to `/health` to prevent cold starts

## Optional: Telegram Signals

Create `telegram_signals_asia.py` exporting `fetch_asia_telegram_signals(hours_back, include_extended)` to enable Telegram channel monitoring. The backend will gracefully skip Telegram if the file is absent.

---

© 2026 Asifah Analytics. All rights reserved. See LICENSE for terms.
