"""
Telegram Signal Source for Asia-Pacific Conflict Dashboard
v1.0.0 — March 2026

Bridges Telethon (async) with Flask (sync) to pull messages
from monitored Telegram channels and feed them into the
Asia-Pacific conflict probability scanner.

Channels monitored:
- Taiwan Strait / PLA activity watchers
- North Korea missile/nuclear monitoring
- Afghanistan/Taliban/ISIS-K reporting
- Pakistan military and border conflict
- India-Pakistan / India-China border
- Japan/South Korea defense
- OSINT aggregators covering Indo-Pacific theatre

Usage:
    from telegram_signals_asia import fetch_asia_telegram_signals
    messages = fetch_asia_telegram_signals(hours_back=24)
    # Returns list of dicts with 'title', 'url', 'published', 'source' keys
"""

import os
import asyncio
import base64
from datetime import datetime, timezone, timedelta

# Telethon import with graceful fallback
try:
    from telethon import TelegramClient
    from telethon.tl.functions.messages import GetHistoryRequest
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("[Telegram Asia] ⚠️ telethon not installed — Telegram signals disabled")


# ========================================
# CONFIGURATION
# ========================================

TELEGRAM_API_ID = os.environ.get('TELEGRAM_API_ID')
TELEGRAM_API_HASH = os.environ.get('TELEGRAM_API_HASH')
TELEGRAM_PHONE = os.environ.get('TELEGRAM_PHONE')
SESSION_NAME = 'asifah_session'

# Core Asia-Pacific conflict channels — verified working March 2026
ASIA_CHANNELS = [
    # OSINT aggregators — high volume, high signal
    'IntelSlava',              # Intel Slava — broad OSINT incl. Indo-Pacific
    'OSINTdefender',           # OSINT Defender — high signal, covers Asia
    'ClashReport',             # Clash Report — global conflict monitoring
    'WarMonitors',             # War Monitor — multilingual conflict
    'C_Military1',             # Military conflict OSINT

    # Afghanistan / Taliban / ISIS-K
    'AfghanistanInternational', # Afghanistan Intl — exile media, active
    'kabulnow',                # Kabul Now — Afghan ground reporting
    'AfghanistanTaliban',      # Taliban activity monitoring
    'AfghanOSINT',             # Afghan OSINT aggregator

    # Pakistan
    'GeoNews',                 # Geo News Pakistan

    # Japan
    'NHKWorldNews',            # NHK World — Japan public broadcaster

    # South Korea
    'yonhapnewsagency',        # Yonhap News Agency — South Korea wire

    # General English news
    'BBCBreaking',             # BBC Breaking News
]

# Extended channels — deeper regional coverage (verified or best-guess replacements)
EXTENDED_ASIA_CHANNELS = [
    # North Korea — replacements for dead nknewsorg/northkoreatech
    'NorthKoreaNews',          # NK news aggregator

    # Taiwan / China
    'Taiwan_News',             # Taiwan news
    'StraitsTimesSG',          # Straits Times — Singapore, covers Taiwan Strait
    'scmpnews',                # South China Morning Post

    # India / Pakistan / Afghanistan
    'thenewsinternational',    # The News International — Pakistan

    # Myanmar

    # Broader Indo-Pacific
]


def _telegram_available():
    """Check if Telegram integration is fully configured."""
    if not TELETHON_AVAILABLE:
        return False
    if not all([TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE]):
        print("[Telegram Asia] ⚠️ Missing environment variables")
        return False
    return True


def _ensure_session_file():
    """Decode session file from base64 env var if needed."""
    session_path = f'{SESSION_NAME}.session'
    if os.path.exists(session_path):
        return True

    session_b64 = os.environ.get('TELEGRAM_SESSION_BASE64')
    if session_b64:
        try:
            session_data = base64.b64decode(session_b64)
            with open(session_path, 'wb') as f:
                f.write(session_data)
            print(f"[Telegram Asia] ✅ Session file decoded ({len(session_data)} bytes)")
            return True
        except Exception as e:
            print(f"[Telegram Asia] ❌ Session decode error: {str(e)[:100]}")
            return False

    print("[Telegram Asia] ⚠️ No session file and no TELEGRAM_SESSION_BASE64 env var")
    return False


async def _async_fetch_messages(channels, hours_back=24):
    """
    Async function to fetch messages from Telegram channels.
    Returns list of messages compatible with Asia backend article format.
    """
    if not _ensure_session_file():
        return []

    messages = []
    since = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    try:
        client = TelegramClient(SESSION_NAME, int(TELEGRAM_API_ID), TELEGRAM_API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            print("[Telegram Asia] ❌ Session not authorized")
            await client.disconnect()
            return []

        print(f"[Telegram Asia] ✅ Connected, fetching from {len(channels)} channels...")

        for channel in channels:
            try:
                entity = await client.get_entity(channel)
                history = await client(GetHistoryRequest(
                    peer=entity,
                    limit=50,
                    offset_date=None,
                    offset_id=0,
                    max_id=0,
                    min_id=0,
                    add_offset=0,
                    hash=0
                ))

                channel_count = 0
                for msg in history.messages:
                    if msg.date and msg.date.replace(tzinfo=timezone.utc) > since and msg.message:
                        messages.append({
                            'title': msg.message[:200],
                            'url': f'https://t.me/{channel}/{msg.id}',
                            'published': msg.date.replace(tzinfo=timezone.utc).isoformat(),
                            'query': f'telegram_{channel}',
                            'source': f'Telegram @{channel}',
                            'views': getattr(msg, 'views', 0) or 0,
                            'forwards': getattr(msg, 'forwards', 0) or 0,
                        })
                        channel_count += 1

                print(f"[Telegram Asia] @{channel}: {channel_count} messages (last {hours_back}h)")

            except Exception as e:
                print(f"[Telegram Asia] @{channel} error: {str(e)[:100]}")
                continue

        await client.disconnect()
        print(f"[Telegram Asia] ✅ Total: {len(messages)} messages from {len(channels)} channels")

    except Exception as e:
        print(f"[Telegram Asia] ❌ Connection error: {str(e)[:200]}")
        try:
            await client.disconnect()
        except Exception:
            pass

    return messages


def fetch_asia_telegram_signals(hours_back=24, include_extended=True):
    """
    Synchronous wrapper to fetch Asia-Pacific Telegram messages.

    Args:
        hours_back: How many hours back to fetch (default 24)
        include_extended: Whether to include extended channel list

    Returns:
        List of dicts with keys: title, url, published, query, source, views, forwards
    """
    if not _telegram_available():
        print("[Telegram Asia] Signals unavailable — skipping")
        return []

    channels = ASIA_CHANNELS.copy()
    if include_extended:
        channels.extend(EXTENDED_ASIA_CHANNELS)

    # Bridge async to sync
    try:
        try:
            loop = asyncio.get_running_loop()
            print("[Telegram Asia] ⚠️ Event loop already running — using thread")
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _async_fetch_messages(channels, hours_back))
                return future.result(timeout=120)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_async_fetch_messages(channels, hours_back))
            finally:
                loop.close()
    except Exception as e:
        print(f"[Telegram Asia] ❌ fetch error: {str(e)[:200]}")
        return []


def get_asia_telegram_status():
    """Return status info for health check / debugging."""
    return {
        'telethon_installed': TELETHON_AVAILABLE,
        'api_configured': bool(TELEGRAM_API_ID and TELEGRAM_API_HASH),
        'phone_configured': bool(TELEGRAM_PHONE),
        'session_available': os.path.exists(f'{SESSION_NAME}.session') or bool(os.environ.get('TELEGRAM_SESSION_BASE64')),
        'core_channels': ASIA_CHANNELS,
        'extended_channels': EXTENDED_ASIA_CHANNELS,
        'ready': _telegram_available() and (
            os.path.exists(f'{SESSION_NAME}.session') or
            bool(os.environ.get('TELEGRAM_SESSION_BASE64'))
        )
    }
