"""
Asifah Analytics — Asia Backend v1.0.0
March 2026

Asia-Pacific Conflict Probability Dashboard Backend
Targets: Afghanistan, China, India, Japan, North Korea, Pakistan, South Korea, Taiwan

Architecture modeled on Europe backend (app.py v1.1.0)
Adapted for Asia-Pacific geopolitical monitoring with:
  - Asia-Pacific source weights (SCMP, Nikkei, The Hindu, Yonhap, etc.)
  - GDELT languages: English, Mandarin (zho), Korean (kor), Urdu (urd), Dari (prs)
  - Asia-Pacific Reddit subreddits
  - NOTAM monitoring (FAA NOTAM API — ICAO regions)
  - Flight disruption tracking
  - Military posture integration hooks

v1.0.0 — Initial build
  - All threat/NOTAM/flight data cached in memory with 4-hour TTL
  - Background thread refreshes all caches every 4 hours automatically
  - Normal page loads return cached data in <100ms
  - Force fresh scan with ?force=true query parameter
  - /api/asia/dashboard endpoint returns all country scores in one call

© 2026 Asifah Analytics. All rights reserved.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
import requests
from datetime import datetime, timezone, timedelta
import os
import time
import re
import math
import xml.etree.ElementTree as ET
import threading
import json

try:
    from telegram_signals_asia import fetch_asia_telegram_signals
    TELEGRAM_AVAILABLE = True
    print("[Asia Backend] ✅ Telegram signals available")
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("[Asia Backend] ⚠️ Telegram signals not available")

app = Flask(__name__)
# CORS handled by after_request handler

# ========================================
# CONFIGURATION
# ========================================
NEWSAPI_KEY = os.environ.get('NEWSAPI_KEY')
GDELT_BASE_URL = "http://api.gdeltproject.org/api/v2/doc/doc"

# Cache TTL in seconds (4 hours)
CACHE_TTL = 4 * 60 * 60

# NOTAM cache TTL (2 hours)
NOTAM_CACHE_TTL = 2 * 60 * 60

# Upstash Redis (persistent cache across Render cold starts)
UPSTASH_REDIS_URL = os.environ.get('UPSTASH_REDIS_URL')
UPSTASH_REDIS_TOKEN = os.environ.get('UPSTASH_REDIS_TOKEN')
NOTAM_REDIS_KEY = 'asia_notam_cache'
FLIGHT_REDIS_KEY = 'asia_flight_cache'
FLIGHT_CACHE_TTL = 12 * 60 * 60  # 12 hours
THREAT_REDIS_PREFIX = 'asia_threat_'  # e.g. asia_threat_taiwan_7d
THREAT_CACHE_TTL = 4 * 60 * 60  # 4 hours

# Rate limiting
RATE_LIMIT = 100
RATE_LIMIT_WINDOW = 86400
rate_limit_data = {
    'requests': 0,
    'reset_time': time.time() + RATE_LIMIT_WINDOW
}

# ========================================
# IN-MEMORY RESPONSE CACHE
# ========================================
_cache = {}
_cache_lock = threading.Lock()


def cache_get(key):
    """Get a cached response if it exists and is fresh."""
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        if time.time() - entry['timestamp'] > CACHE_TTL:
            del _cache[key]
            return None
        return entry['data']


def cache_set(key, data):
    """Store a response in the in-memory cache."""
    with _cache_lock:
        _cache[key] = {
            'data': data,
            'timestamp': time.time()
        }


def cache_age(key):
    """Return age of cache entry in seconds, or None if not cached."""
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        return time.time() - entry['timestamp']


# ========================================
# REDIS HELPERS
# ========================================

def _redis_request(method, path, **kwargs):
    """Make a request to Upstash Redis REST API."""
    if not UPSTASH_REDIS_URL or not UPSTASH_REDIS_TOKEN:
        return None
    try:
        url = f"{UPSTASH_REDIS_URL}{path}"
        headers = {"Authorization": f"Bearer {UPSTASH_REDIS_TOKEN}"}
        resp = requests.request(method, url, headers=headers, timeout=5, **kwargs)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"[Redis] Error: {str(e)[:100]}")
    return None


def load_threat_cache_redis(target, days=7):
    """Load threat cache from Redis."""
    key = f"{THREAT_REDIS_PREFIX}{target}_{days}d"
    result = _redis_request('GET', f"/get/{key}")
    if result and result.get('result'):
        try:
            return json.loads(result['result'])
        except Exception:
            pass
    return None


def save_threat_cache_redis(target, data, days=7):
    """Save threat cache to Redis with TTL."""
    key = f"{THREAT_REDIS_PREFIX}{target}_{days}d"
    try:
        payload = json.dumps(data)
        _redis_request('POST', f"/set/{key}/{THREAT_CACHE_TTL}", json=payload)
    except Exception as e:
        print(f"[Redis] Save error: {str(e)[:100]}")


def is_threat_cache_fresh_redis(target, days=7):
    """Check if Redis threat cache is fresh. Returns (is_fresh, data)."""
    cached = load_threat_cache_redis(target, days)
    if not cached:
        return False, None
    cached_at = cached.get('cached_at', '')
    if cached_at:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(
                cached_at.replace('Z', '+00:00'))).total_seconds()
            if age < THREAT_CACHE_TTL:
                return True, cached
        except Exception:
            pass
    return False, None


def is_notam_cache_fresh():
    """Check if Redis NOTAM cache is fresh."""
    result = _redis_request('GET', f"/get/{NOTAM_REDIS_KEY}")
    if result and result.get('result'):
        try:
            data = json.loads(result['result'])
            cached_at = data.get('timestamp', '')
            if cached_at:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(
                    cached_at.replace('Z', '+00:00'))).total_seconds()
                if age < NOTAM_CACHE_TTL:
                    return True, data
        except Exception:
            pass
    return False, None


def save_notam_cache_redis(data):
    """Save NOTAM cache to Redis."""
    try:
        payload = json.dumps(data)
        _redis_request('POST', f"/set/{NOTAM_REDIS_KEY}/{NOTAM_CACHE_TTL}", json=payload)
    except Exception as e:
        print(f"[Redis] NOTAM save error: {str(e)[:100]}")


def is_flight_cache_fresh():
    """Check if Redis flight cache is fresh."""
    result = _redis_request('GET', f"/get/{FLIGHT_REDIS_KEY}")
    if result and result.get('result'):
        try:
            data = json.loads(result['result'])
            cached_at = data.get('timestamp', '')
            if cached_at:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(
                    cached_at.replace('Z', '+00:00'))).total_seconds()
                if age < FLIGHT_CACHE_TTL:
                    return True, data
        except Exception:
            pass
    return False, None


def save_flight_cache_redis(data):
    """Save flight disruption cache to Redis."""
    try:
        payload = json.dumps(data)
        _redis_request('POST', f"/set/{FLIGHT_REDIS_KEY}/{FLIGHT_CACHE_TTL}", json=payload)
    except Exception as e:
        print(f"[Redis] Flight save error: {str(e)[:100]}")


# ========================================
# RATE LIMITING
# ========================================

def check_rate_limit():
    """Simple daily rate limiter."""
    now = time.time()
    if now > rate_limit_data['reset_time']:
        rate_limit_data['requests'] = 0
        rate_limit_data['reset_time'] = now + RATE_LIMIT_WINDOW
    rate_limit_data['requests'] += 1
    return rate_limit_data['requests'] <= RATE_LIMIT


def get_rate_limit_info():
    return {
        'requests_today': rate_limit_data['requests'],
        'limit': RATE_LIMIT,
        'reset_time': rate_limit_data['reset_time']
    }


# ========================================
# BACKGROUND REFRESH THREAD
# ========================================

def _refresh_all_caches():
    """
    Refresh all cached data in the background.
    Runs every CACHE_TTL seconds so no user request ever triggers a cold scan.
    """
    print("[Background Refresh] Waiting 30s for app to stabilize before first refresh...")
    time.sleep(30)

    targets = list(TARGET_KEYWORDS.keys())

    while True:
        print(f"\n[Background Refresh] Starting full cache refresh at {datetime.now(timezone.utc).isoformat()}")
        start = time.time()

        for target in targets:
            try:
                print(f"[Background Refresh] Refreshing {target}...")
                data = _run_threat_scan(target, days=7)
                cache_set(f'threat_{target}_7d', data)
                save_threat_cache_redis(target, data, days=7)
                print(f"[Background Refresh] ✓ {target} cached (probability: {data.get('probability', '?')}%)")
            except Exception as e:
                print(f"[Background Refresh] ✗ {target} failed: {e}")
            time.sleep(5)

        try:
            print("[Background Refresh] Refreshing NOTAMs via FAA...")
            notam_data = _run_notam_scan()
            cache_set('notams', notam_data)
            print(f"[Background Refresh] ✓ NOTAMs cached ({notam_data.get('total_notams', 0)} alerts)")
        except Exception as e:
            print(f"[Background Refresh] ✗ NOTAMs failed: {e}")

        time.sleep(5)

        try:
            print("[Background Refresh] Refreshing flights...")
            flight_data = _run_flight_scan()
            cache_set('flights', flight_data)
            print(f"[Background Refresh] ✓ Flights cached ({flight_data.get('total_disruptions', 0)} disruptions)")
        except Exception as e:
            print(f"[Background Refresh] ✗ Flights failed: {e}")

        time.sleep(5)

        try:
            print("[Background Refresh] Refreshing travel advisories...")
            ta_data = _run_travel_advisory_scan()
            cache_set('travel_advisories', ta_data)
            print(f"[Background Refresh] ✓ Travel advisories cached")
        except Exception as e:
            print(f"[Background Refresh] ✗ Travel advisories failed: {e}")

        elapsed = time.time() - start
        print(f"[Background Refresh] Complete in {elapsed:.1f}s. Sleeping {CACHE_TTL}s until next refresh.\n")
        time.sleep(CACHE_TTL)


def start_background_refresh():
    """Start the background refresh thread (daemon so it dies with the app)."""
    thread = threading.Thread(target=_refresh_all_caches, daemon=True)
    thread.start()
    print("[Background Refresh] Thread started — will refresh all caches every 4 hours")


# ========================================
# U.S. STATE DEPT TRAVEL ADVISORIES
# ========================================
TRAVEL_ADVISORY_API = "https://cadataapi.state.gov/api/TravelAdvisories"

TRAVEL_ADVISORY_CODES = {
    'afghanistan': ['AF'],
    'china':       ['CH'],
    'india':       ['IN'],
    'japan':       ['JA'],
    'north_korea': ['KN'],
    'pakistan':    ['PK'],
    'south_korea': ['KS'],
    'taiwan':      ['TW'],
}

TRAVEL_ADVISORY_LEVELS = {
    1: {'label': 'Exercise Normal Precautions',    'short': 'Normal Precautions',  'color': '#10b981'},
    2: {'label': 'Exercise Increased Caution',     'short': 'Increased Caution',   'color': '#f59e0b'},
    3: {'label': 'Reconsider Travel',              'short': 'Reconsider Travel',   'color': '#f97316'},
    4: {'label': 'Do Not Travel',                  'short': 'Do Not Travel',       'color': '#ef4444'},
}


# ========================================
# SOURCE WEIGHTS — ASIA-PACIFIC EDITION
# ========================================
SOURCE_WEIGHTS = {
    'premium': {
        'sources': [
            'The New York Times', 'The Washington Post', 'Reuters',
            'Associated Press', 'AP News', 'BBC News', 'The Guardian',
            'Financial Times', 'Wall Street Journal', 'The Economist',
            'Nikkei Asia', 'South China Morning Post', 'The Hindu',
            'Yonhap News', 'Kyodo News',
        ],
        'weight': 1.0
    },
    'regional_asia': {
        'sources': [
            'NHK World', 'Japan Times', 'Mainichi', 'Asahi Shimbun',
            'Korea Herald', 'Korea Times', 'Chosun Ilbo',
            'Dawn (Pakistan)', 'The News International', 'Geo News',
            'Times of India', 'Hindustan Times', 'NDTV',
            'Taipei Times', 'Focus Taiwan', 'Liberty Times',
            'Global Times', 'Xinhua', 'CGTN',
            'Radio Free Asia', 'NK News', 'Daily NK',
            'TOLOnews', 'Ariana News', 'Pajhwok',
            'Voice of America', 'Radio Free Europe',
        ],
        'weight': 0.8
    },
    'standard': {
        'sources': ['*'],
        'weight': 0.5
    }
}


# ========================================
# TARGET KEYWORDS — ASIA-PACIFIC
# ========================================
TARGET_KEYWORDS = {

    'afghanistan': {
        'keywords': [
            'afghanistan', 'afghan', 'kabul', 'taliban', 'kandahar',
            'isis-k', 'iskp', 'islamic state khorasan',
            'national resistance front', 'panjshir',
            'afghanistan pakistan border', 'ttp', 'tehrik-i-taliban',
            'balochistan afghanistan', 'afghanistan iran',
            'afghanistan collapse', 'afghanistan famine',
        ],
        'reddit_keywords': [
            'afghanistan', 'taliban', 'isis-k', 'kabul',
            'afghan military', 'resistance front',
        ],
    },

    'china': {
        'keywords': [
            'china military', 'pla', 'chinese military', 'peoples liberation army',
            'south china sea', 'taiwan strait', 'china taiwan',
            'china navy', 'plan warship', 'chinese carrier',
            'china nuclear', 'china missile', 'df-41', 'df-21',
            'china us military', 'china india border',
            'china air force', 'j-20', 'h-6 bomber',
            'xi jinping military', 'china war',
        ],
        'reddit_keywords': [
            'china military', 'pla', 'south china sea', 'taiwan strait',
            'sino', 'china news',
        ],
    },

    'india': {
        'keywords': [
            'india military', 'indian army', 'indian air force', 'indian navy',
            'india pakistan', 'india china border', 'lac', 'line of actual control',
            'kashmir', 'line of control', 'india nuclear',
            'india missile', 'agni missile', 'brahmos',
            'india military exercise', 'quad india',
            'india china standoff', 'galwan valley',
            'india pakistan tension', 'india border skirmish',
        ],
        'reddit_keywords': [
            'india military', 'india pakistan', 'india china',
            'kashmir', 'indiandefense',
        ],
    },

    'japan': {
        'keywords': [
            'japan military', 'jsdf', 'japan self defense force',
            'japan taiwan', 'japan china', 'senkaku',
            'japan north korea missile', 'dprk missile japan',
            'japan rearmament', 'japan defense budget',
            'japan us military', 'us bases japan', 'okinawa base',
            'japan scramble jets', 'japan airspace violation',
            'japan coast guard', 'japan naval exercise',
            'japan missile defense', 'pac-3 japan',
        ],
        'reddit_keywords': [
            'japan military', 'jsdf', 'senkaku', 'japan defense',
            'japan', 'japannews',
        ],
    },

    'north_korea': {
        'keywords': [
            'north korea', 'dprk', 'kim jong un', 'pyongyang',
            'north korea missile', 'dprk launch', 'icbm',
            'hwasong', 'north korea nuclear', 'punggye-ri',
            'north korea troops russia', 'dprk soldiers ukraine',
            'inter-korean', 'dmz', 'north korea provocation',
            'north korea submarine', 'dprk hypersonic',
            'north korea south korea', 'yongbyon',
        ],
        'reddit_keywords': [
            'north korea', 'dprk', 'kim jong un', 'northkorea',
            'korean peninsula', 'pyongyang',
        ],
    },

    'pakistan': {
        'keywords': [
            'pakistan military', 'pakistan army', 'ispr',
            'pakistan nuclear', 'shaheen missile', 'nasr missile',
            'india pakistan', 'line of control', 'kashmir military',
            'pakistan taliban', 'ttp attack', 'balochistan attack',
            'pakistan airspace', 'pakistan us military',
            'pakistan china military', 'cpec security',
            'pakistan coup', 'pakistan imf crisis',
            'pakistan afghanistan border',
        ],
        'reddit_keywords': [
            'pakistan military', 'pakistan army', 'india pakistan',
            'kashmir', 'pakistan', 'pakistan news',
        ],
    },

    'south_korea': {
        'keywords': [
            'south korea military', 'rok military', 'roka',
            'south korea north korea', 'inter-korean',
            'korea us military', 'us forces korea', 'usfk',
            'south korea missile', 'south korea nuclear',
            'dmz incident', 'korean demilitarized zone',
            'south korea japan defense', 'quad south korea',
            'south korea ukraine', 'rok arms export',
            'korea defense budget', 'korea rearmament',
        ],
        'reddit_keywords': [
            'south korea military', 'korea', 'korean peninsula',
            'north korea', 'CredibleDefense',
        ],
    },

    'taiwan': {
        'keywords': [
            'taiwan strait', 'taiwan military', 'roc military',
            'pla taiwan', 'taiwan adiz', 'china taiwan',
            'taiwan invasion', 'taiwan blockade',
            'taiwan us arms', 'us taiwan defense',
            'taiwan strait incursion', 'median line violation',
            'joint sword', 'pla exercise taiwan',
            'taiwan independence', 'taiwan contingency',
            'seventh fleet taiwan', 'taiwan japan defense',
        ],
        'reddit_keywords': [
            'taiwan', 'taiwan strait', 'pla taiwan', 'china taiwan',
            'taiwan defense', 'CredibleDefense',
        ],
    },
}


# ========================================
# NOTAM REGIONS — ASIA-PACIFIC ICAO CODES
# ========================================
NOTAM_REGIONS = {
    'taiwan_strait': {
        'name': 'Taiwan Strait / East China Sea',
        'icao_codes': ['RCTP', 'RCSS', 'ZGGG'],  # Taipei, Songshan, Guangzhou
        'fir': ['RJJJ', 'RCFIR'],
    },
    'korean_peninsula': {
        'name': 'Korean Peninsula',
        'icao_codes': ['RKSI', 'RKSS', 'ZKPY'],  # Incheon, Gimpo, Pyongyang
        'fir': ['RKRR', 'ZKKP'],
    },
    'south_china_sea': {
        'name': 'South China Sea',
        'icao_codes': ['WMKK', 'RPLL', 'VVTS'],  # Kuala Lumpur, Manila, Ho Chi Minh
        'fir': ['WSJC', 'RPHI'],
    },
    'japan': {
        'name': 'Japan / Okinawa',
        'icao_codes': ['RJTT', 'RJBB', 'ROAH'],  # Tokyo, Osaka, Naha (Okinawa)
        'fir': ['RJJJ', 'RJTT'],
    },
    'south_asia': {
        'name': 'South Asia (India/Pakistan/Afghanistan)',
        'icao_codes': ['VIDP', 'OPKC', 'OAKB'],  # Delhi, Karachi, Kabul
        'fir': ['VIDF', 'OPLR', 'OAKX'],
    },
}


# ========================================
# REDDIT CONFIGURATION — ASIA-PACIFIC
# ========================================
REDDIT_USER_AGENT = "AsifahAnalytics-Asia/1.0.0 (OSINT monitoring tool)"
REDDIT_SUBREDDITS = {
    'afghanistan': ['afghanistan', 'geopolitics', 'worldnews', 'CredibleDefense', 'islam'],
    'china':       ['sino', 'china', 'geopolitics', 'worldnews', 'CredibleDefense', 'taiwan'],
    'india':       ['india', 'indiandefense', 'geopolitics', 'worldnews', 'CredibleDefense', 'IndiaSpeaks'],
    'japan':       ['japan', 'japannews', 'geopolitics', 'worldnews', 'CredibleDefense'],
    'north_korea': ['northkorea', 'geopolitics', 'worldnews', 'CredibleDefense', 'korea'],
    'pakistan':    ['pakistan', 'geopolitics', 'worldnews', 'CredibleDefense', 'india'],
    'south_korea': ['korea', 'southkorea', 'geopolitics', 'worldnews', 'CredibleDefense'],
    'taiwan':      ['taiwan', 'geopolitics', 'worldnews', 'CredibleDefense', 'sino', 'china'],
}


# ========================================
# ASIA-PACIFIC ESCALATION KEYWORDS
# ========================================
ESCALATION_KEYWORDS = [
    'strike', 'attack', 'bombing', 'airstrike', 'missile', 'rocket',
    'military operation', 'offensive', 'retaliate', 'retaliation',
    'response', 'counterattack', 'invasion', 'incursion',
    'shelling', 'artillery', 'drone strike', 'drone attack',
    'threatens', 'warned', 'vowed', 'promised to strike',
    'will respond', 'severe response', 'consequences',
    'mobilization', 'troops deployed', 'forces gathering',
    'military buildup', 'reserves called up',
    'killed', 'dead', 'casualties', 'wounded', 'injured',
    'death toll', 'fatalities',
    'nuclear threat', 'nuclear posture', 'tactical nuclear',
    'airspace violation', 'airspace closed', 'no-fly zone',
    'sovereignty violation', 'territorial integrity',
    'flight cancellations', 'cancelled flights', 'suspend flights',
    'suspended flights', 'airline suspends', 'halted flights',
    'grounded flights', 'travel advisory',
    'do not travel', 'avoid all travel', 'reconsider travel',
    # Asia-specific escalation
    'median line violation', 'adiz violation',
    'taiwan strait closure', 'blockade taiwan',
    'icbm launch', 'missile test north korea',
    'nuclear test dprk', 'kim jong un orders',
    'line of actual control', 'galwan', 'doklam',
    'pakistan india skirmish', 'kashmir shelling',
    'pla exercise live fire', 'joint sword',
    'carrier group deployment', 'seventh fleet',
    'scrambles jets', 'jets scrambled',
    'base attacked', 'base hit', 'base struck',
    'intercepts missile', 'shoots down missile',
    'air defense activated', 'pac-3 activated',
    'regime change', 'coup attempt',
    # Airlines
    'cathay pacific cancel', 'japan airlines cancel',
    'ana cancel flights', 'korean air cancel',
    'air india cancel', 'pia cancel flights',
    'china airlines cancel', 'eva air cancel',
]


# ========================================
# ARTICLE FETCHING — NEWS API
# ========================================

def fetch_newsapi_articles(query, days=7):
    """Fetch articles from NewsAPI."""
    if not NEWSAPI_KEY:
        return []
    try:
        from_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        response = requests.get(
            'https://newsapi.org/v2/everything',
            params={
                'q': query,
                'from': from_date,
                'sortBy': 'publishedAt',
                'language': 'en',
                'pageSize': 30,
                'apiKey': NEWSAPI_KEY,
            },
            timeout=15
        )
        if response.status_code == 200:
            articles = response.json().get('articles', [])
            for a in articles:
                a['language'] = 'en'
            return articles
    except Exception as e:
        print(f"[Asia v1.0] NewsAPI error: {str(e)[:100]}")
    return []


# ========================================
# ARTICLE FETCHING — GDELT
# ========================================

def fetch_gdelt_articles(query, days=7, language='eng'):
    """Fetch articles from GDELT API."""
    try:
        params = {
            'query': query,
            'mode': 'artlist',
            'maxrecords': 30,
            'timespan': f'{days}d',
            'format': 'json',
            'sourcelang': language,
        }
        resp = None
        for attempt in range(2):
            try:
                resp = requests.get(GDELT_BASE_URL, params=params, timeout=60)
                if resp.status_code == 200:
                    break
            except requests.Timeout:
                if attempt == 0:
                    print(f"[Asia GDELT] {language}: Retry after timeout...")
                    time.sleep(2)
                    continue
                raise

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                print(f"[Asia GDELT] {language}: Non-JSON response, skipping")
                return []

            lang_map = {
                'eng': 'en', 'zho': 'zh', 'kor': 'ko',
                'urd': 'ur', 'prs': 'fa', 'jpn': 'ja',
            }
            articles = []
            for art in data.get('articles', []):
                articles.append({
                    'title': art.get('title', ''),
                    'description': art.get('title', ''),
                    'url': art.get('url', ''),
                    'publishedAt': art.get('seendate', ''),
                    'source': {'name': f"GDELT ({language})"},
                    'content': art.get('title', ''),
                    'language': lang_map.get(language, language),
                })
            return articles
    except Exception as e:
        print(f"[Asia GDELT] {language} error: {str(e)[:80]}")
    return []


# ========================================
# ARTICLE FETCHING — GOOGLE NEWS RSS
# ========================================

def fetch_google_news_rss(query, source_name, lang='en', gl='US'):
    """Fetch articles from Google News RSS."""
    articles = []
    try:
        encoded_query = requests.utils.quote(query)
        ceid = f"{lang.upper()}-{gl}"
        url = f"https://news.google.com/rss/search?q={encoded_query}&hl={lang}&gl={gl}&ceid={ceid}"
        response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            items = root.findall('.//item')
            for item in items[:15]:
                title_elem = item.find('title')
                link_elem = item.find('link')
                pub_elem = item.find('pubDate')
                if title_elem is not None:
                    articles.append({
                        'title': title_elem.text or '',
                        'description': title_elem.text or '',
                        'url': link_elem.text if link_elem is not None else '',
                        'publishedAt': pub_elem.text if pub_elem is not None else '',
                        'source': {'name': source_name},
                        'content': title_elem.text or '',
                        'language': lang,
                    })
    except Exception as e:
        print(f"[Asia RSS] {source_name} error: {str(e)[:100]}")
    return articles


# ========================================
# ARTICLE FETCHING — REDDIT
# ========================================

def fetch_reddit_posts(target, keywords, days=7):
    """Fetch Reddit posts from relevant subreddits."""
    articles = []
    subreddits = REDDIT_SUBREDDITS.get(target, [])
    if not subreddits:
        return []
    since = datetime.now(timezone.utc) - timedelta(days=days)
    for subreddit in subreddits:
        try:
            for keyword in keywords[:3]:
                url = f"https://www.reddit.com/r/{subreddit}/search.json"
                params = {
                    'q': keyword,
                    'sort': 'new',
                    'limit': 10,
                    't': 'week',
                    'restrict_sr': 'true'
                }
                response = requests.get(
                    url, params=params, timeout=10,
                    headers={"User-Agent": REDDIT_USER_AGENT}
                )
                if response.status_code == 200:
                    posts = response.json().get('data', {}).get('children', [])
                    for post in posts:
                        post_data = post.get('data', {})
                        created = post_data.get('created_utc', 0)
                        post_time = datetime.fromtimestamp(created, tz=timezone.utc)
                        if post_time >= since:
                            articles.append({
                                'title': post_data.get('title', ''),
                                'description': post_data.get('selftext', '')[:500],
                                'url': f"https://www.reddit.com{post_data.get('permalink', '')}",
                                'publishedAt': post_time.isoformat(),
                                'source': {'name': f"r/{subreddit}"},
                                'content': post_data.get('selftext', '')[:500],
                                'language': 'en',
                            })
                time.sleep(0.5)
        except Exception as e:
            print(f"[Asia Reddit] r/{subreddit} error: {str(e)[:80]}")
    return articles


# ========================================
# THREAT SCORING
# ========================================

def get_source_weight(source_name):
    """Return source credibility weight."""
    for tier, tier_data in SOURCE_WEIGHTS.items():
        if tier == 'standard':
            continue
        if source_name in tier_data.get('sources', []):
            return tier_data['weight']
    return SOURCE_WEIGHTS['standard']['weight']


def calculate_threat_probability(articles, days=7, target=None):
    """
    Score articles against escalation keywords with time decay and source weighting.
    Returns probability (0-100), momentum, and breakdown.
    """
    if not articles:
        return {'probability': 0, 'momentum': 'stable', 'breakdown': {}, 'top_contributors': []}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    scored_articles = []
    deescalation_keywords = [
        'ceasefire', 'peace talks', 'negotiations', 'diplomacy', 'de-escalation',
        'withdraw', 'pullback', 'summit', 'agreement', 'deal', 'truce',
        'diplomatic solution', 'talks resume', 'dialogue',
    ]

    for article in articles:
        title = (article.get('title', '') or '').lower()
        description = (article.get('description', '') or '').lower()
        content = (article.get('content', '') or '').lower()
        text = f"{title} {description} {content}"

        # Time decay
        pub_str = article.get('publishedAt', '')
        try:
            if pub_str:
                pub_date = datetime.fromisoformat(pub_str.replace('Z', '+00:00'))
                age_hours = (now - pub_date).total_seconds() / 3600
                if age_hours <= 24:
                    time_decay = 1.0
                elif age_hours <= 48:
                    time_decay = 0.8
                elif age_hours <= 72:
                    time_decay = 0.6
                else:
                    time_decay = max(0.2, 1.0 - (age_hours / (days * 24)) * 0.8)
            else:
                time_decay = 0.5
        except Exception:
            time_decay = 0.5

        # Escalation scoring
        matched_keywords = [kw for kw in ESCALATION_KEYWORDS if kw in text]
        severity = len(matched_keywords)

        # De-escalation penalty
        deesc_matches = [kw for kw in deescalation_keywords if kw in text]
        if deesc_matches:
            severity = max(0, severity - len(deesc_matches) * 2)

        if severity == 0:
            continue

        source_name = article.get('source', {}).get('name', 'Unknown') if isinstance(
            article.get('source'), dict) else str(article.get('source', 'Unknown'))
        source_weight = get_source_weight(source_name)

        contribution = severity * source_weight * time_decay
        scored_articles.append({
            'article': article,
            'severity': severity,
            'source_weight': source_weight,
            'time_decay': time_decay,
            'contribution': contribution,
            'source': source_name,
            'deescalation': len(deesc_matches) > 0,
        })

    if not scored_articles:
        return {'probability': 0, 'momentum': 'stable', 'breakdown': {
            'weighted_score': 0, 'recent_articles_48h': 0, 'older_articles': 0,
            'deescalation_count': 0,
        }, 'top_contributors': []}

    weighted_score = sum(s['contribution'] for s in scored_articles)
    recent_count = sum(1 for s in scored_articles
                       if (now - datetime.fromisoformat(
                           (s['article'].get('publishedAt', '') or '').replace('Z', '+00:00')
                           if s['article'].get('publishedAt') else now.isoformat()
                       ).replace(tzinfo=timezone.utc if '+' not in (s['article'].get('publishedAt', '') or '') else None)
                       ).total_seconds() / 3600 <= 48)

    deesc_count = sum(1 for s in scored_articles if s['deescalation'])
    older_count = len(scored_articles) - recent_count

    # Normalize to 0-100
    probability = min(100, int(weighted_score * 1.5))

    # Momentum
    if recent_count > older_count * 1.5:
        momentum = 'increasing'
    elif older_count > recent_count * 1.5:
        momentum = 'decreasing'
    else:
        momentum = 'stable'

    top_contributors = sorted(scored_articles, key=lambda x: x['contribution'], reverse=True)[:10]

    return {
        'probability': probability,
        'momentum': momentum,
        'breakdown': {
            'weighted_score': round(weighted_score, 2),
            'recent_articles_48h': recent_count,
            'older_articles': older_count,
            'deescalation_count': deesc_count,
        },
        'top_contributors': [
            {
                'source': c['source'],
                'contribution': round(c['contribution'], 2),
                'severity': c['severity'],
                'source_weight': c['source_weight'],
                'time_decay': round(c['time_decay'], 2),
                'deescalation': c['deescalation'],
            } for c in top_contributors
        ]
    }


# ========================================
# FLIGHT DISRUPTION SCANNER
# ========================================

def scan_asian_flight_disruptions(articles):
    """Scan articles for Asia-Pacific flight disruption signals."""
    disruptions = []
    flight_keywords = [
        'flight cancelled', 'flights cancelled', 'flights suspended',
        'airspace closed', 'airport closed', 'no fly zone',
        'airline suspend', 'flights grounded', 'aviation warning',
        'taiwan strait closed', 'korean airspace', 'japan airspace',
    ]
    seen = set()
    for article in articles:
        title = (article.get('title', '') or '').lower()
        desc = (article.get('description', '') or '').lower()
        text = f"{title} {desc}"
        if any(kw in text for kw in flight_keywords):
            url = article.get('url', '')
            if url not in seen:
                seen.add(url)
                disruptions.append({
                    'title': article.get('title', ''),
                    'source': article.get('source', {}).get('name', 'Unknown') if isinstance(
                        article.get('source'), dict) else str(article.get('source', '')),
                    'url': url,
                    'publishedAt': article.get('publishedAt', ''),
                })
    return disruptions[:20]


# ========================================
# NOTAM SCANNING — FAA API
# ========================================

def scan_asia_notams():
    """Scan FAA NOTAM API for Asia-Pacific regions."""
    notams = []
    FAA_NOTAM_URL = "https://external-api.faa.gov/notamapi/v1/notams"

    for region_key, region in NOTAM_REGIONS.items():
        icao_codes = region.get('icao_codes', [])[:3]
        for icao in icao_codes:
            try:
                params = {
                    'icaoLocation': icao,
                    'pageSize': 10,
                }
                response = requests.get(
                    FAA_NOTAM_URL, params=params,
                    headers={'Accept': 'application/json'},
                    timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    for item in items:
                        props = item.get('properties', {})
                        core = props.get('coreNOTAMData', {})
                        notam = core.get('notam', {})
                        text = notam.get('text', '') or notam.get('traditionalMessage', '')
                        notams.append({
                            'icao': icao,
                            'region': region['name'],
                            'id': notam.get('id', ''),
                            'text': text[:500],
                            'effectiveStart': notam.get('effectiveStart', ''),
                            'effectiveEnd': notam.get('effectiveEnd', ''),
                        })
            except Exception as e:
                print(f"[Asia NOTAM] {icao} error: {str(e)[:80]}")
            time.sleep(0.3)

    return notams


# ========================================
# TRAVEL ADVISORY SCANNER
# ========================================

def _run_travel_advisory_scan():
    """Fetch State Dept travel advisories for all Asia targets."""
    advisories = {}
    try:
        response = requests.get(TRAVEL_ADVISORY_API, timeout=15)
        if response.status_code == 200:
            data = response.json()
            all_advisories = data if isinstance(data, list) else data.get('advisories', [])
            for country, codes in TRAVEL_ADVISORY_CODES.items():
                for adv in all_advisories:
                    if adv.get('countryCode') in codes:
                        level = adv.get('advisoryLevel', 1)
                        level_info = TRAVEL_ADVISORY_LEVELS.get(level, TRAVEL_ADVISORY_LEVELS[1])
                        advisories[country] = {
                            'level': level,
                            'label': level_info['label'],
                            'short': level_info['short'],
                            'color': level_info['color'],
                            'message': adv.get('message', ''),
                            'updated': adv.get('dateLastUpdated', ''),
                        }
                        break
    except Exception as e:
        print(f"[Asia Travel Advisory] Error: {str(e)[:100]}")

    return {
        'success': True,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'advisories': advisories,
        'version': '1.0.0-asia',
    }


# ========================================
# MAIN THREAT SCAN
# ========================================

def _run_threat_scan(target, days=7):
    """
    Run a full threat scan for a target. Returns the complete response dict.
    Used by both the API endpoint and the background refresh thread.
    """
    query = ' OR '.join(TARGET_KEYWORDS[target]['keywords'][:8])

    # English
    articles_en = fetch_newsapi_articles(query, days)
    articles_gdelt_en = fetch_gdelt_articles(query, days, 'eng')

    # Language-specific GDELT
    articles_gdelt_zh = []
    articles_gdelt_ko = []
    articles_gdelt_ur = []
    articles_gdelt_fa = []
    articles_gdelt_ja = []

    if target in ('china', 'taiwan'):
        articles_gdelt_zh = fetch_gdelt_articles(query, days, 'zho')
    if target in ('south_korea', 'north_korea'):
        articles_gdelt_ko = fetch_gdelt_articles(query, days, 'kor')
    if target in ('pakistan', 'afghanistan'):
        articles_gdelt_ur = fetch_gdelt_articles(query, days, 'urd')
        articles_gdelt_fa = fetch_gdelt_articles(query, days, 'prs')
    if target == 'japan':
        articles_gdelt_ja = fetch_gdelt_articles(query, days, 'jpn')

    # Reddit
    articles_reddit = fetch_reddit_posts(
        target,
        TARGET_KEYWORDS[target]['reddit_keywords'],
        days
    )

    # Target-specific RSS
    rss_articles = []

    if target == 'taiwan':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'Taiwan strait OR PLA OR China military taiwan OR blockade',
                'Taiwan News'))
        except Exception as e:
            print(f"Taiwan RSS error: {e}")
        try:
            rss_articles.extend(fetch_google_news_rss(
                '台灣海峽 OR 解放軍 OR 台海', 'Taiwan News (ZH)', lang='zh', gl='TW'))
        except Exception as e:
            print(f"Taiwan ZH RSS error: {e}")

    if target == 'north_korea':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'North Korea missile OR DPRK launch OR Kim Jong Un military',
                'North Korea News'))
        except Exception as e:
            print(f"North Korea RSS error: {e}")
        try:
            rss_articles.extend(fetch_google_news_rss(
                '북한 미사일 OR 김정은', 'North Korea News (KO)', lang='ko', gl='KR'))
        except Exception as e:
            print(f"North Korea KO RSS error: {e}")

    if target == 'china':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'China military OR PLA OR south china sea OR taiwan strait',
                'China News'))
        except Exception as e:
            print(f"China RSS error: {e}")

    if target == 'pakistan':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'Pakistan military OR Pakistan army OR India Pakistan border',
                'Pakistan News'))
        except Exception as e:
            print(f"Pakistan RSS error: {e}")

    if target == 'afghanistan':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'Afghanistan Taliban OR ISIS-K OR Kabul attack OR Afghanistan military',
                'Afghanistan News'))
        except Exception as e:
            print(f"Afghanistan RSS error: {e}")

    if target == 'india':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'India military OR India China border OR India Pakistan OR Kashmir',
                'India News'))
        except Exception as e:
            print(f"India RSS error: {e}")

    if target == 'japan':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'Japan JSDF OR Japan military OR Japan North Korea OR Senkaku',
                'Japan News'))
        except Exception as e:
            print(f"Japan RSS error: {e}")
        try:
            rss_articles.extend(fetch_google_news_rss(
                '自衛隊 OR 北朝鮮 ミサイル OR 尖閣', 'Japan News (JA)', lang='ja', gl='JP'))
        except Exception as e:
            print(f"Japan JA RSS error: {e}")

    if target == 'south_korea':
        try:
            rss_articles.extend(fetch_google_news_rss(
                'South Korea military OR Korea DPRK OR inter-Korean',
                'South Korea News'))
        except Exception as e:
            print(f"South Korea RSS error: {e}")

    # Telegram
    telegram_articles = []
    if TELEGRAM_AVAILABLE:
        try:
            telegram_msgs = fetch_asia_telegram_signals(hours_back=days * 24, include_extended=True)
            if telegram_msgs:
                target_kws = [kw.lower() for kw in TARGET_KEYWORDS.get(target, {}).get('keywords', [])]
                target_name = target.replace('_', ' ').lower()
                for msg in telegram_msgs:
                    msg_text = (msg.get('title', '') or '').lower()
                    if target_name in msg_text or any(kw in msg_text for kw in target_kws[:15]):
                        telegram_articles.append({
                            'title': msg.get('title', '')[:200],
                            'description': msg.get('title', '')[:500],
                            'url': msg.get('url', ''),
                            'publishedAt': msg.get('published', ''),
                            'source': {'name': msg.get('source', 'Telegram')},
                            'content': msg.get('title', '')[:500],
                            'language': 'multi',
                        })
        except Exception as e:
            print(f"[Asia Scan] Telegram error: {str(e)[:100]}")

    all_articles = (
        articles_en + articles_gdelt_en +
        articles_gdelt_zh + articles_gdelt_ko +
        articles_gdelt_ur + articles_gdelt_fa + articles_gdelt_ja +
        articles_reddit + rss_articles + telegram_articles
    )

    # Score
    scoring_result = calculate_threat_probability(all_articles, days, target)
    probability = scoring_result['probability']
    momentum = scoring_result['momentum']
    breakdown = scoring_result['breakdown']

    # Timeline
    if probability < 30:
        timeline = "180+ Days (Low priority)"
    elif probability < 50:
        timeline = "91-180 Days"
    elif probability < 70:
        timeline = "31-90 Days"
    else:
        timeline = "0-30 Days (Elevated threat)"

    if momentum == 'increasing' and probability > 50:
        timeline = "0-30 Days (Elevated threat)"

    # Confidence
    unique_sources = len(set(
        a.get('source', {}).get('name', 'Unknown') if isinstance(a.get('source'), dict)
        else str(a.get('source', 'Unknown'))
        for a in all_articles
    ))
    if len(all_articles) >= 20 and unique_sources >= 8:
        confidence = "High"
    elif len(all_articles) >= 10 and unique_sources >= 5:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Top articles
    top_articles = []
    for contributor in scoring_result.get('top_contributors', []):
        for article in all_articles:
            src = article.get('source', {}).get('name', '') if isinstance(
                article.get('source'), dict) else str(article.get('source', ''))
            if src == contributor['source']:
                top_articles.append({
                    'title': article.get('title', 'No title'),
                    'source': contributor['source'],
                    'url': article.get('url', ''),
                    'publishedAt': article.get('publishedAt', ''),
                    'contribution': contributor['contribution'],
                    'severity': contributor['severity'],
                    'source_weight': contributor['source_weight'],
                    'time_decay': contributor['time_decay'],
                    'deescalation': contributor['deescalation'],
                })
                break

    # Flight disruptions
    flight_disruptions = []
    try:
        flight_disruptions = scan_asian_flight_disruptions(all_articles)
    except Exception as e:
        print(f"Flight disruption scan error: {e}")

    return {
        'success': True,
        'target': target,
        'region': 'asia',
        'probability': probability,
        'timeline': timeline,
        'confidence': confidence,
        'momentum': momentum,
        'total_articles': len(all_articles),
        'recent_articles_48h': breakdown.get('recent_articles_48h', 0),
        'older_articles': breakdown.get('older_articles', 0),
        'deescalation_count': breakdown.get('deescalation_count', 0),
        'scoring_breakdown': breakdown,
        'top_scoring_articles': top_articles,
        'escalation_keywords': ESCALATION_KEYWORDS,
        'target_keywords': TARGET_KEYWORDS[target]['keywords'],
        'flight_disruptions': flight_disruptions,
        'articles_en': [a for a in all_articles if a.get('language') == 'en'][:20],
        'articles_zh': [a for a in all_articles if a.get('language') == 'zh'][:20],
        'articles_ko': [a for a in all_articles if a.get('language') == 'ko'][:20],
        'articles_ur': [a for a in all_articles if a.get('language') == 'ur'][:20],
        'articles_fa': [a for a in all_articles if a.get('language') == 'fa'][:20],
        'articles_ja': [a for a in all_articles if a.get('language') == 'ja'][:20],
        'articles_reddit': [a for a in all_articles
                            if isinstance(a.get('source'), dict) and
                            a.get('source', {}).get('name', '').startswith('r/')][:20],
        'days_analyzed': days,
        'cached_at': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0-asia',
    }


def _run_notam_scan():
    """Run a full NOTAM scan. Returns the complete response dict."""
    is_fresh, cached = is_notam_cache_fresh()
    if is_fresh and cached:
        cached['cached'] = True
        cached['cache_source'] = 'redis'
        return cached

    print("[NOTAM Scan] Running fresh Asia NOTAM scan from FAA...")
    notams = scan_asia_notams()

    result = {
        'success': True,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_notams': len(notams),
        'notams': notams,
        'regions_scanned': list(NOTAM_REGIONS.keys()),
        'data_source': 'FAA NOTAM API',
        'version': '1.0.0-asia',
        'cached': False,
    }

    save_notam_cache_redis(result)
    cache_set('notams', result)
    return result


def _run_flight_scan():
    """Run a full flight disruption scan."""
    is_fresh, cached = is_flight_cache_fresh()
    if is_fresh and cached:
        cached['cached'] = True
        cached['cache_source'] = 'redis'
        return cached

    print("[Flight Scan] Running fresh Asia flight disruption scan...")

    flight_queries = [
        'Asia flight cancelled OR suspended OR grounded Taiwan Strait',
        'airline cancel flights Korea OR Japan OR Taiwan OR China',
        'airspace closed Asia OR Taiwan OR Korea OR Japan',
        'Cathay Pacific OR Japan Airlines OR Korean Air cancel suspend flights',
        'NOTAM airspace restriction Asia Pacific',
        'flight disruption war zone Asia',
        'Taiwan Strait aviation warning OR closed',
        'North Korea missile flight warning Japan Korea',
    ]

    all_articles = []
    for fq in flight_queries:
        try:
            all_articles.extend(fetch_newsapi_articles(fq, days=3))
        except Exception as e:
            print(f"[Asia] Flight query error: {e}")
        try:
            all_articles.extend(fetch_gdelt_articles(fq, days=3, language='eng'))
        except Exception as e:
            print(f"[Asia] Flight GDELT query error: {e}")

    seen_urls = set()
    unique_articles = []
    for a in all_articles:
        url = a.get('url', '')
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_articles.append(a)

    disruptions = scan_asian_flight_disruptions(unique_articles)

    result = {
        'success': True,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_disruptions': len(disruptions),
        'disruptions': disruptions,
        'cancellations': disruptions,
        'version': '1.0.0-asia',
        'cached': False,
    }

    save_flight_cache_redis(result)
    cache_set('flights', result)
    return result


# ========================================
# API ENDPOINTS
# ========================================

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,OPTIONS'
    return response

@app.errorhandler(500)
def internal_error(e):
    import traceback
    tb = traceback.format_exc()
    print(f"[500 ERROR] {tb}")
    response = jsonify({'error': 'Internal server error', 'detail': str(e)})
    response.status_code = 500
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,OPTIONS'
    return response

@app.errorhandler(Exception)
def unhandled_exception(e):
    import traceback
    tb = traceback.format_exc()
    print(f"[UNHANDLED EXCEPTION] {tb}")
    response = jsonify({'error': 'Unhandled exception', 'detail': str(e)})
    response.status_code = 500
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,OPTIONS'
    return response


@app.route('/api/asia/threat/<target>', methods=['GET'])
def api_asia_threat(target):
    """
    Main threat assessment endpoint for Asia-Pacific targets.
    Returns cached data by default. Pass ?force=true to trigger a fresh OSINT scan.
    """
    try:
        force = request.args.get('force', 'false').lower() == 'true'
        days = int(request.args.get('days', 7))

        if target not in TARGET_KEYWORDS:
            return jsonify({
                'success': False,
                'error': f"Invalid target. Must be one of: {', '.join(TARGET_KEYWORDS.keys())}"
            }), 400

        cache_key = f'threat_{target}_{days}d'

        if not force:
            cached = cache_get(cache_key)
            if cached:
                cached['cached'] = True
                cached['cache_source'] = 'memory'
                age = cache_age(cache_key)
                cached['cache_age_seconds'] = int(age) if age else 0
                cached['cache_age_human'] = f"{int(age / 60)}m ago" if age else 'unknown'
                return jsonify(cached)

            is_fresh, redis_cached = is_threat_cache_fresh_redis(target, days)
            if is_fresh and redis_cached:
                redis_cached['cached'] = True
                redis_cached['cache_source'] = 'redis'
                redis_cached['cache_age_human'] = 'from redis'
                cache_set(cache_key, redis_cached)
                return jsonify(redis_cached)

        if not check_rate_limit():
            return jsonify({
                'success': False,
                'error': 'Hourly limit reached. Try again later.',
                'probability': 0,
                'timeline': 'Rate limited',
                'confidence': 'Low',
                'rate_limited': True
            }), 200

        response_data = _run_threat_scan(target, days)
        response_data['cached'] = False
        response_data['cache_age_seconds'] = 0
        response_data['cache_age_human'] = 'fresh scan'
        cache_set(cache_key, response_data)
        save_threat_cache_redis(target, response_data, days)
        return jsonify(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'probability': 0,
            'timeline': 'Unknown',
            'confidence': 'Low'
        }), 500


@app.route('/api/asia/dashboard', methods=['GET'])
def api_asia_dashboard():
    """
    Single batch endpoint — returns all country scores in one response.
    Returns cached data by default. Pass ?force=true to trigger fresh scans.
    """
    try:
        force = request.args.get('force', 'false').lower() == 'true'
        days = int(request.args.get('days', 7))
        targets = list(TARGET_KEYWORDS.keys())

        dashboard = {
            'success': True,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0-asia',
            'countries': {}
        }

        all_cached = True

        for target in targets:
            cache_key = f'threat_{target}_{days}d'

            if not force:
                cached = cache_get(cache_key)
                if cached:
                    dashboard['countries'][target] = {
                        'probability': cached.get('probability', 0),
                        'momentum': cached.get('momentum', 'stable'),
                        'timeline': cached.get('timeline', 'Unknown'),
                        'confidence': cached.get('confidence', 'Low'),
                        'total_articles': cached.get('total_articles', 0),
                        'flight_disruptions': len(cached.get('flight_disruptions', [])),
                        'cached': True,
                        'cache_age_seconds': int(cache_age(cache_key) or 0)
                    }
                    continue

            all_cached = False
            if not check_rate_limit():
                dashboard['countries'][target] = {
                    'probability': 0,
                    'error': 'Rate limited',
                    'cached': False
                }
                continue

            data = _run_threat_scan(target, days=days)
            cache_set(cache_key, data)
            dashboard['countries'][target] = {
                'probability': data.get('probability', 0),
                'momentum': data.get('momentum', 'stable'),
                'timeline': data.get('timeline', 'Unknown'),
                'confidence': data.get('confidence', 'Low'),
                'total_articles': data.get('total_articles', 0),
                'flight_disruptions': len(data.get('flight_disruptions', [])),
                'cached': False,
                'cache_age_seconds': 0
            }

        dashboard['all_cached'] = all_cached
        return jsonify(dashboard)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/asia/notams', methods=['GET'])
def api_asia_notams():
    """Asia-Pacific NOTAMs endpoint. Redis-cached with ?force=true override."""
    try:
        force = request.args.get('force', 'false').lower() == 'true'

        if not force:
            cached = cache_get('notams')
            if cached:
                cached['cached'] = True
                cached['cache_source'] = 'memory'
                cached['cache_age_seconds'] = int(cache_age('notams') or 0)
                return jsonify(cached)

            is_fresh, redis_cached = is_notam_cache_fresh()
            if is_fresh and redis_cached:
                redis_cached['cached'] = True
                redis_cached['cache_source'] = 'redis'
                cache_set('notams', redis_cached)
                return jsonify(redis_cached)

        if not check_rate_limit():
            return jsonify({'error': 'Rate limit exceeded'}), 429

        data = _run_notam_scan()
        return jsonify(data)

    except Exception as e:
        return jsonify({
            'success': False, 'error': str(e),
            'notams': [], 'total_notams': 0
        }), 500


@app.route('/api/asia/flights', methods=['GET'])
def api_asia_flights():
    """Asia-Pacific flight disruptions endpoint. Redis-cached with ?force=true override."""
    try:
        force = request.args.get('force', 'false').lower() == 'true'

        if not force:
            cached = cache_get('flights')
            if cached:
                cached['cached'] = True
                cached['cache_source'] = 'memory'
                return jsonify(cached)

            is_fresh, redis_cached = is_flight_cache_fresh()
            if is_fresh and redis_cached:
                redis_cached['cached'] = True
                redis_cached['cache_source'] = 'redis'
                cache_set('flights', redis_cached)
                return jsonify(redis_cached)

        if not check_rate_limit():
            return jsonify({'error': 'Rate limit exceeded'}), 429

        data = _run_flight_scan()
        return jsonify(data)

    except Exception as e:
        return jsonify({
            'success': False, 'error': str(e),
            'disruptions': [], 'total_disruptions': 0
        }), 500


@app.route('/api/asia/travel-advisories', methods=['GET'])
def api_asia_travel_advisories():
    """State Dept travel advisories for Asia-Pacific targets."""
    try:
        force = request.args.get('force', 'false').lower() == 'true'

        if not force:
            cached = cache_get('travel_advisories')
            if cached:
                cached['cached'] = True
                return jsonify(cached)

        data = _run_travel_advisory_scan()
        cache_set('travel_advisories', data)
        return jsonify(data)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/asia/cache-status', methods=['GET'])
def api_asia_cache_status():
    """See cache freshness for all endpoints."""
    status = {}
    targets = list(TARGET_KEYWORDS.keys())
    for target in targets:
        key = f'threat_{target}_7d'
        age = cache_age(key)
        status[target] = {
            'cached': age is not None,
            'age_minutes': int(age / 60) if age else None,
            'fresh': age is not None and age < CACHE_TTL,
        }
    return jsonify({
        'success': True,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cache_ttl_hours': CACHE_TTL / 3600,
        'targets': status,
        'notams': {'cached': cache_get('notams') is not None},
        'flights': {'cached': cache_get('flights') is not None},
    })


@app.route('/rate-limit', methods=['GET'])
def rate_limit_status():
    return jsonify(get_rate_limit_info())


@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /api/\n", 200, {'Content-Type': 'text/plain'}


@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'Backend is running',
        'message': 'Asifah Analytics — Asia API v1.0.0',
        'version': '1.0.0',
        'region': 'asia',
        'features': [
            'In-memory response caching (4-hour TTL)',
            'Background refresh thread (auto-refreshes all caches)',
            'Single dashboard endpoint (/api/asia/dashboard)',
            'Force fresh scan with ?force=true',
            'GDELT multilingual: English, Mandarin, Korean, Urdu, Dari, Japanese',
        ],
        'targets': list(TARGET_KEYWORDS.keys()),
        'endpoints': {
            '/api/asia/threat/<target>': 'Get threat assessment (cached, ?force=true for fresh)',
            '/api/asia/dashboard': 'Get all country scores in one call (cached)',
            '/api/asia/notams': 'Get Asia-Pacific NOTAMs (cached, ?force=true for fresh)',
            '/api/asia/flights': 'Get Asia-Pacific flight disruptions (cached)',
            '/api/asia/travel-advisories': 'Get State Dept travel advisories',
            '/api/asia/cache-status': 'See cache freshness for all endpoints',
            '/rate-limit': 'Get rate limit status',
            '/health': 'Health check',
        }
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0-asia',
        'region': 'asia',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cache_entries': len(_cache),
        'targets': list(TARGET_KEYWORDS.keys()),
    })


# ========================================
# START BACKGROUND REFRESH ON BOOT
# ========================================
# On Render with gunicorn, this runs once per worker.
start_background_refresh()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
