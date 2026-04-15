#!/usr/bin/env python3
"""
========================================================
  Zerodha Kite Daily Token Refresh Script
  Run this every morning BEFORE 9:45 AM
  Stores token locally with date stamp
  Auto-updates n8n CONFIG file
========================================================
  Usage:
    python3 kite_token_refresh.py

  First-time setup:
    pip install kiteconnect requests
========================================================
"""

import os
import sys
import json
import hashlib
import datetime
import webbrowser
import urllib.parse
from pathlib import Path

# ── Try importing kiteconnect ──────────────────────────
try:
    from kiteconnect import KiteConnect
    KITE_AVAILABLE = True
except ImportError:
    KITE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ══════════════════════════════════════════════════════
#   PATHS  (all relative to script location)
# ══════════════════════════════════════════════════════
BASE_DIR      = Path(__file__).parent
TOKENS_DIR    = BASE_DIR / "kite_tokens"
CONFIG_FILE   = BASE_DIR / "kite_config.json"          # stores API key + secret permanently
N8N_ENV_FILE  = BASE_DIR / "n8n_autotrader.env"        # loaded by n8n workflow
LOG_FILE      = BASE_DIR / "token_refresh.log"

TOKENS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════
#   HELPERS
# ══════════════════════════════════════════════════════
def log(msg: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def today_str() -> str:
    return datetime.date.today().strftime("%Y-%m-%d")


def token_file_for_today() -> Path:
    return TOKENS_DIR / f"token_{today_str()}.json"


def load_config() -> dict:
    """Load stored API key + secret from config file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    log(f"Config saved to {CONFIG_FILE}")


def save_token(api_key: str, access_token: str):
    """Save today's token as dated JSON file."""
    data = {
        "date":          today_str(),
        "api_key":       api_key,
        "access_token":  access_token,
        "generated_at":  datetime.datetime.now().isoformat()
    }
    path = token_file_for_today()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    log(f"Token saved → {path}")
    return path


def load_today_token() -> dict | None:
    """Return today's token if already generated."""
    path = token_file_for_today()
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def update_n8n_env(api_key: str, access_token: str):
    """
    Write/update the .env file that n8n CONFIG node reads.
    Format: KEY=VALUE  (one per line, no spaces around =)
    n8n reads this via: process.env.VAR_NAME in Function nodes.
    """
    # Read existing env file if present
    env_lines = {}
    if N8N_ENV_FILE.exists():
        with open(N8N_ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_lines[k.strip()] = v.strip()

    # Update Zerodha keys
    env_lines["ZERODHA_API_KEY"]      = api_key
    env_lines["ZERODHA_ACCESS_TOKEN"] = access_token
    env_lines["TOKEN_DATE"]           = today_str()

    # Write back
    with open(N8N_ENV_FILE, "w") as f:
        f.write("# ═══════════════════════════════════════════════════\n")
        f.write("# n8n Auto-Trader Environment Variables\n")
        f.write(f"# Last updated: {datetime.datetime.now().isoformat()}\n")
        f.write("# Update values to the RIGHT of = only. Do NOT add spaces.\n")
        f.write("# ═══════════════════════════════════════════════════\n\n")
        f.write("# ── ZERODHA (auto-updated by kite_token_refresh.py) ──\n")
        f.write(f"ZERODHA_API_KEY={env_lines['ZERODHA_API_KEY']}\n")
        f.write(f"ZERODHA_ACCESS_TOKEN={env_lines['ZERODHA_ACCESS_TOKEN']}\n")
        f.write(f"TOKEN_DATE={env_lines['TOKEN_DATE']}\n\n")

        f.write("# ── AI ADVISORS (edit once, stays permanent) ────────\n")
        f.write(f"CLAUDE_API_KEY={env_lines.get('CLAUDE_API_KEY', 'YOUR_ANTHROPIC_API_KEY')}\n")
        f.write(f"GEMINI_API_KEY={env_lines.get('GEMINI_API_KEY', 'YOUR_GEMINI_API_KEY')}\n")
        f.write(f"GROK_API_KEY={env_lines.get('GROK_API_KEY', 'YOUR_GROK_API_KEY')}\n")
        f.write(f"PERPLEXITY_API_KEY={env_lines.get('PERPLEXITY_API_KEY', 'YOUR_PERPLEXITY_API_KEY')}\n\n")

        f.write("# ── NEWS ────────────────────────────────────────────\n")
        f.write(f"NEWSAPI_KEY={env_lines.get('NEWSAPI_KEY', 'YOUR_NEWSAPI_KEY')}\n\n")

        f.write("# ── TWILIO / WHATSAPP ───────────────────────────────\n")
        f.write(f"TWILIO_ACCOUNT_SID={env_lines.get('TWILIO_ACCOUNT_SID', 'YOUR_TWILIO_SID')}\n")
        f.write(f"TWILIO_AUTH_TOKEN={env_lines.get('TWILIO_AUTH_TOKEN', 'YOUR_TWILIO_AUTH_TOKEN')}\n")
        f.write(f"TWILIO_WHATSAPP_FROM={env_lines.get('TWILIO_WHATSAPP_FROM', 'whatsapp:+14155238886')}\n")
        f.write(f"ALERT_PHONE={env_lines.get('ALERT_PHONE', 'whatsapp:+91XXXXXXXXXX')}\n\n")

        f.write("# ── TRADING SETTINGS ────────────────────────────────\n")
        f.write(f"DAILY_BUDGET={env_lines.get('DAILY_BUDGET', '1000')}\n")
        f.write(f"PROFIT_TARGET_PCT={env_lines.get('PROFIT_TARGET_PCT', '20')}\n")
        f.write(f"STOPLOSS_PCT={env_lines.get('STOPLOSS_PCT', '2')}\n")
        f.write(f"MAX_STOCKS={env_lines.get('MAX_STOCKS', '5')}\n")
        f.write(f"ORDER_TYPE={env_lines.get('ORDER_TYPE', 'MIS')}\n")
        f.write(f"WATCHLIST={env_lines.get('WATCHLIST', 'RELIANCE,TCS,INFY,HDFCBANK,ICICIBANK,SBIN,WIPRO,AXISBANK,LT,MARUTI')}\n")

    log(f".env file updated → {N8N_ENV_FILE}")


def cleanup_old_tokens(keep_days: int = 7):
    """Delete token files older than keep_days."""
    cutoff = datetime.date.today() - datetime.timedelta(days=keep_days)
    deleted = 0
    for f in TOKENS_DIR.glob("token_*.json"):
        try:
            date_str = f.stem.replace("token_", "")
            file_date = datetime.date.fromisoformat(date_str)
            if file_date < cutoff:
                f.unlink()
                deleted += 1
        except Exception:
            pass
    if deleted:
        log(f"Cleaned up {deleted} old token file(s)")


# ══════════════════════════════════════════════════════
#   KITE TOKEN FLOW
# ══════════════════════════════════════════════════════
def generate_checksum(api_key: str, request_token: str, api_secret: str) -> str:
    raw = api_key + request_token + api_secret
    return hashlib.sha256(raw.encode()).hexdigest()


def get_access_token_via_kiteconnect(api_key: str, api_secret: str) -> str:
    """
    Full Kite Connect OAuth flow using the kiteconnect library.
    Opens browser for login, waits for request_token paste.
    """
    kite = KiteConnect(api_key=api_key)
    login_url = kite.login_url()

    print("\n" + "═"*55)
    print("  STEP 1: Browser will open for Zerodha login")
    print("  STEP 2: After login, copy the URL from browser")
    print("  STEP 3: Paste it here when prompted")
    print("═"*55)
    print(f"\n  Login URL:\n  {login_url}\n")

    input("  Press ENTER to open browser... ")
    webbrowser.open(login_url)

    print("\n  After login, the browser redirects to a URL like:")
    print("  https://127.0.0.1/?request_token=XXXXXXXX&action=login&status=success")
    print()
    redirect_url = input("  Paste the full redirect URL here: ").strip()

    # Extract request_token from URL
    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)
    request_token = params.get("request_token", [None])[0]

    if not request_token:
        raise ValueError("Could not find request_token in the URL. Check the pasted URL.")

    log(f"Got request_token: {request_token[:8]}...")

    # Exchange for access token
    data = kite.generate_session(request_token, api_secret=api_secret)
    access_token = data["access_token"]
    log(f"Access token generated: {access_token[:8]}...")
    return access_token


def get_access_token_manual(api_key: str, api_secret: str) -> str:
    """
    Fallback: manual flow using requests (no kiteconnect library needed).
    """
    login_url = (
        f"https://kite.trade/connect/login"
        f"?api_key={api_key}&v=3"
    )

    print("\n" + "═"*55)
    print("  STEP 1: Open this URL in your browser:")
    print(f"\n  {login_url}\n")
    print("  STEP 2: Login with Zerodha credentials")
    print("  STEP 3: Copy the redirected URL from browser bar")
    print("═"*55)
    input("\n  Press ENTER when ready to paste the redirect URL... ")

    redirect_url = input("  Paste full redirect URL: ").strip()
    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)
    request_token = params.get("request_token", [None])[0]

    if not request_token:
        raise ValueError("request_token not found in URL.")

    checksum = generate_checksum(api_key, request_token, api_secret)

    if REQUESTS_AVAILABLE:
        resp = requests.post(
            "https://api.kite.trade/session/token",
            data={
                "api_key":       api_key,
                "request_token": request_token,
                "checksum":      checksum
            },
            headers={"X-Kite-Version": "3"}
        )
        if resp.status_code == 200:
            return resp.json()["data"]["access_token"]
        else:
            raise ValueError(f"Token exchange failed: {resp.text}")
    else:
        # Pure stdlib fallback using urllib
        import urllib.request
        data = urllib.parse.urlencode({
            "api_key":       api_key,
            "request_token": request_token,
            "checksum":      checksum
        }).encode()
        req = urllib.request.Request(
            "https://api.kite.trade/session/token",
            data=data,
            headers={"X-Kite-Version": "3"},
            method="POST"
        )
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
            return result["data"]["access_token"]


# ══════════════════════════════════════════════════════
#   INTERACTIVE PROMPTS
# ══════════════════════════════════════════════════════
def prompt_api_credentials(existing: dict) -> tuple[str, str]:
    """
    Prompt for API key and secret.
    Shows existing values masked — press ENTER to keep.
    """
    print("\n" + "═"*55)
    print("  Zerodha Kite API Credentials")
    print("  (Press ENTER to keep existing value)")
    print("═"*55)

    existing_key    = existing.get("api_key", "")
    existing_secret = existing.get("api_secret", "")

    if existing_key:
        masked_key = existing_key[:4] + "*" * (len(existing_key) - 4)
        api_key = input(f"\n  API Key [{masked_key}]: ").strip()
        if not api_key:
            api_key = existing_key
            print(f"  → Using saved key: {masked_key}")
    else:
        api_key = input("\n  API Key: ").strip()

    if existing_secret:
        masked_secret = existing_secret[:4] + "*" * (len(existing_secret) - 4)
        api_secret = input(f"  API Secret [{masked_secret}]: ").strip()
        if not api_secret:
            api_secret = existing_secret
            print(f"  → Using saved secret: {masked_secret}")
    else:
        api_secret = input("  API Secret: ").strip()

    if not api_key or not api_secret:
        raise ValueError("API key and secret cannot be empty.")

    return api_key, api_secret


# ══════════════════════════════════════════════════════
#   MAIN
# ══════════════════════════════════════════════════════
def main():
    print("\n" + "█"*55)
    print("  ZERODHA KITE DAILY TOKEN REFRESH")
    print(f"  Date: {today_str()}")
    print("█"*55)

    # Check if token already generated today
    existing_today = load_today_token()
    if existing_today:
        print(f"\n  ✅ Token already generated today ({today_str()})")
        print(f"  Access token: {existing_today['access_token'][:8]}...")
        reuse = input("\n  Use existing token? [Y/n]: ").strip().lower()
        if reuse != "n":
            log("Reusing existing today's token.")
            update_n8n_env(existing_today["api_key"], existing_today["access_token"])
            print("\n  ✅ .env file updated with today's token. Ready to trade!\n")
            return

    # Load saved API key/secret
    config = load_config()

    try:
        api_key, api_secret = prompt_api_credentials(config)
    except ValueError as e:
        print(f"\n  ❌ Error: {e}")
        sys.exit(1)

    # Save key+secret for next time
    save_config({"api_key": api_key, "api_secret": api_secret})

    # Generate access token
    print("\n  Generating access token...")
    try:
        if KITE_AVAILABLE:
            access_token = get_access_token_via_kiteconnect(api_key, api_secret)
        else:
            print("  (kiteconnect library not installed — using manual flow)")
            access_token = get_access_token_manual(api_key, api_secret)
    except Exception as e:
        log(f"ERROR generating token: {e}")
        print(f"\n  ❌ Failed: {e}")
        sys.exit(1)

    # Save dated token file
    token_path = save_token(api_key, access_token)

    # Update n8n .env file
    update_n8n_env(api_key, access_token)

    # Cleanup tokens older than 7 days
    cleanup_old_tokens(keep_days=7)

    print("\n" + "═"*55)
    print("  ✅ ALL DONE — Ready to trade!")
    print(f"  Token file : {token_path.name}")
    print(f"  .env file  : {N8N_ENV_FILE.name}")
    print("═"*55)
    print("\n  n8n workflow will auto-read today's token at 9:45 AM.\n")
    log("Token refresh complete.")


if __name__ == "__main__":
    main()
