"""
Zerodha Kite Browser-Based Stock Analyzer
==========================================
- No API key needed — uses your logged-in Kite browser session
- Scrapes live quotes for multiple stocks
- Applies RSI, MA crossover, volume spike analysis
- Generates HTML report every 5 minutes (auto-opens in browser)

PREREQUISITE:
  Launch Chrome with remote debugging BEFORE running this script:

  Windows:
    "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="C:\ChromeKite"

  Mac:
    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 --user-data-dir="/tmp/chrome_kite"

  Linux:
    google-chrome --remote-debugging-port=9222 --user-data-dir="/tmp/chrome_kite"

  Then log in to https://kite.zerodha.com manually in that window, then run this script.
"""

import time
import json
import math
import os
import webbrowser
from datetime import datetime
from collections import deque
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# ─────────────────────────────────────────────
#  CONFIGURE YOUR STOCKS HERE
# ─────────────────────────────────────────────
STOCKS = [
    {"symbol": "RELIANCE", "exchange": "NSE"},
    {"symbol": "TCS",      "exchange": "NSE"},
    {"symbol": "INFY",     "exchange": "NSE"},
    {"symbol": "HDFCBANK", "exchange": "NSE"},
    {"symbol": "ICICIBANK","exchange": "NSE"},
    {"symbol": "SBIN",     "exchange": "NSE"},
    {"symbol": "WIPRO",    "exchange": "NSE"},
    {"symbol": "BAJFINANCE","exchange": "NSE"},
]

INTERVAL_SECONDS = 300        # 5 minutes
REPORT_FILE      = "kite_report.html"
HISTORY_LEN      = 20         # price history ticks kept per stock
RSI_PERIOD       = 14
SHORT_MA         = 5
LONG_MA          = 14
# ─────────────────────────────────────────────


# ── Price history store ──
price_history: dict[str, deque] = {s["symbol"]: deque(maxlen=HISTORY_LEN) for s in STOCKS}
volume_history: dict[str, deque] = {s["symbol"]: deque(maxlen=HISTORY_LEN) for s in STOCKS}


def connect_to_browser() -> webdriver.Chrome:
    """Attach Selenium to the already-running Chrome session."""
    opts = Options()
    opts.add_experimental_option("debuggerAddress", "127.0.0.1:9222")
    driver = webdriver.Chrome(options=opts)
    print(f"[✓] Connected to Chrome. Current URL: {driver.current_url}")
    return driver


def fetch_quote_via_kite_api(driver: webdriver.Chrome, exchange: str, symbol: str) -> dict | None:
    """
    Use Kite's internal quote API (same endpoint the web app uses).
    Returns dict with last_price, volume, ohlc etc., or None on failure.
    """
    url = f"https://kite.zerodha.com/oms/quote?i={exchange}%3A{symbol}"
    try:
        driver.execute_script(f"window.__kite_quote_result = null;")
        driver.execute_script(f"""
            fetch('{url}', {{credentials: 'include'}})
              .then(r => r.json())
              .then(d => {{ window.__kite_quote_result = d; }})
              .catch(e => {{ window.__kite_quote_result = {{'error': e.toString()}}; }});
        """)
        # Wait up to 5 s for fetch to complete
        for _ in range(50):
            result = driver.execute_script("return window.__kite_quote_result;")
            if result is not None:
                break
            time.sleep(0.1)

        if result and result.get("status") == "success":
            key = f"{exchange}:{symbol}"
            return result["data"].get(key)
        return None
    except Exception as e:
        print(f"  [!] fetch_quote error for {symbol}: {e}")
        return None


# ── Technical Indicators ──

def compute_rsi(prices: list[float], period: int = 14) -> float | None:
    if len(prices) < period + 1:
        return None
    gains, losses = [], []
    for i in range(1, len(prices)):
        delta = prices[i] - prices[i - 1]
        gains.append(max(delta, 0))
        losses.append(max(-delta, 0))
    avg_gain = sum(gains[-period:]) / period
    avg_loss = sum(losses[-period:]) / period
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return round(100 - (100 / (1 + rs)), 2)


def compute_ma(prices: list[float], period: int) -> float | None:
    if len(prices) < period:
        return None
    return round(sum(prices[-period:]) / period, 2)


def compute_volume_ratio(volumes: list[float]) -> float | None:
    """Current volume vs average of past ticks."""
    if len(volumes) < 2:
        return None
    avg = sum(list(volumes)[:-1]) / (len(volumes) - 1)
    if avg == 0:
        return None
    return round(volumes[-1] / avg, 2)


def generate_signal(rsi, short_ma, long_ma, vol_ratio, last_price, prev_price) -> tuple[str, str, list[str]]:
    """
    Returns (signal, confidence, reasons[])
    signal: BUY / SELL / HOLD
    confidence: HIGH / MEDIUM / LOW
    """
    score = 0
    reasons = []

    # RSI
    if rsi is not None:
        if rsi < 30:
            score += 2
            reasons.append(f"RSI {rsi} → oversold (bullish)")
        elif rsi < 45:
            score += 1
            reasons.append(f"RSI {rsi} → approaching oversold")
        elif rsi > 70:
            score -= 2
            reasons.append(f"RSI {rsi} → overbought (bearish)")
        elif rsi > 55:
            score -= 1
            reasons.append(f"RSI {rsi} → approaching overbought")
        else:
            reasons.append(f"RSI {rsi} → neutral zone")

    # MA crossover
    if short_ma and long_ma:
        if short_ma > long_ma:
            score += 1
            reasons.append(f"MA{SHORT_MA} ({short_ma}) > MA{LONG_MA} ({long_ma}) → bullish cross")
        else:
            score -= 1
            reasons.append(f"MA{SHORT_MA} ({short_ma}) < MA{LONG_MA} ({long_ma}) → bearish cross")

    # Price momentum
    if prev_price and last_price:
        chg = ((last_price - prev_price) / prev_price) * 100
        if chg > 1:
            score += 1
            reasons.append(f"Price up {chg:.2f}% this session")
        elif chg < -1:
            score -= 1
            reasons.append(f"Price down {abs(chg):.2f}% this session")

    # Volume
    if vol_ratio:
        if vol_ratio > 1.5:
            reasons.append(f"Volume spike ×{vol_ratio} vs avg → confirms move")
            score = score + 1 if score > 0 else score - 1  # amplifies existing signal
        else:
            reasons.append(f"Volume ratio ×{vol_ratio} → normal")

    # Verdict
    if score >= 3:
        return "BUY", "HIGH", reasons
    elif score == 2:
        return "BUY", "MEDIUM", reasons
    elif score == 1:
        return "BUY", "LOW", reasons
    elif score <= -3:
        return "SELL", "HIGH", reasons
    elif score == -2:
        return "SELL", "MEDIUM", reasons
    elif score == -1:
        return "SELL", "LOW", reasons
    else:
        return "HOLD", "—", reasons


# ── HTML Report Generator ──

def build_report(results: list[dict], timestamp: str) -> str:
    rows_html = ""
    for r in results:
        sig = r["signal"]
        sig_color = {"BUY": "#22c55e", "SELL": "#ef4444", "HOLD": "#f59e0b"}.get(sig, "#888")
        conf_color = {"HIGH": "#22c55e", "MEDIUM": "#f59e0b", "LOW": "#94a3b8"}.get(r["confidence"], "#888")
        change_color = "#22c55e" if r.get("change_pct", 0) >= 0 else "#ef4444"
        change_arrow = "▲" if r.get("change_pct", 0) >= 0 else "▼"
        reasons_html = "".join(f"<li>{x}</li>" for x in r["reasons"])
        rsi_bar = ""
        if r["rsi"] is not None:
            rsi_val = r["rsi"]
            rsi_color = "#22c55e" if rsi_val < 40 else "#ef4444" if rsi_val > 60 else "#f59e0b"
            rsi_bar = f"""
              <div style="display:flex;align-items:center;gap:6px;">
                <div style="flex:1;height:6px;background:#1e293b;border-radius:3px;overflow:hidden;">
                  <div style="width:{rsi_val}%;height:100%;background:{rsi_color};transition:width 0.5s;"></div>
                </div>
                <span style="font-size:11px;color:#94a3b8;min-width:28px;">{rsi_val}</span>
              </div>"""

        rows_html += f"""
        <tr class="stock-row">
          <td style="font-weight:600;color:#f1f5f9;font-size:15px;">{r['symbol']}
            <span style="font-size:10px;color:#475569;margin-left:4px;">{r['exchange']}</span>
          </td>
          <td style="color:#f1f5f9;font-size:16px;font-weight:700;">₹{r['ltp']:,.2f}</td>
          <td style="color:{change_color};">{change_arrow} {abs(r.get('change_pct',0)):.2f}%</td>
          <td>
            <span style="background:{sig_color}22;color:{sig_color};padding:4px 12px;border-radius:20px;font-weight:700;font-size:13px;border:1px solid {sig_color}55;">
              {sig}
            </span>
          </td>
          <td><span style="color:{conf_color};font-size:12px;font-weight:600;">{r['confidence']}</span></td>
          <td style="color:#94a3b8;font-size:12px;">{r.get('volume_ratio') or '—'}</td>
          <td>{rsi_bar}</td>
          <td style="color:#64748b;font-size:11px;max-width:280px;">
            <ul style="margin:0;padding-left:14px;">{reasons_html}</ul>
          </td>
        </tr>"""

    buy_count  = sum(1 for r in results if r["signal"] == "BUY")
    sell_count = sum(1 for r in results if r["signal"] == "SELL")
    hold_count = sum(1 for r in results if r["signal"] == "HOLD")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta http-equiv="refresh" content="{INTERVAL_SECONDS}"/>
  <title>Kite Analyzer — {timestamp}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0f172a; color: #94a3b8; font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
    h1 {{ color: #f8fafc; font-size: 22px; font-weight: 700; }}
    .badge {{ display:inline-block; padding:4px 14px; border-radius:20px; font-size:13px; font-weight:600; }}
    .buy  {{ background:#22c55e22; color:#22c55e; border:1px solid #22c55e55; }}
    .sell {{ background:#ef444422; color:#ef4444; border:1px solid #ef444455; }}
    .hold {{ background:#f59e0b22; color:#f59e0b; border:1px solid #f59e0b55; }}
    table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
    th {{ background:#1e293b; color:#64748b; font-size:11px; text-transform:uppercase; letter-spacing:.08em; padding:10px 12px; text-align:left; }}
    .stock-row td {{ padding:12px; border-bottom:1px solid #1e293b; vertical-align:top; }}
    .stock-row:hover {{ background:#1e293b44; }}
    .summary {{ display:flex; gap:16px; margin-top:16px; flex-wrap:wrap; }}
    .scard {{ background:#1e293b; border-radius:10px; padding:14px 20px; min-width:120px; }}
    .scard .num {{ font-size:28px; font-weight:700; }}
    .scard .lbl {{ font-size:11px; color:#475569; margin-top:2px; }}
    .refresh-bar {{ height:4px; background:#1e293b; border-radius:2px; margin-top:20px; overflow:hidden; }}
    .refresh-fill {{ height:100%; background:linear-gradient(90deg,#6366f1,#22d3ee); animation: fillbar {INTERVAL_SECONDS}s linear forwards; border-radius:2px; }}
    @keyframes fillbar {{ from{{width:0%}} to{{width:100%}} }}
  </style>
</head>
<body>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <div>
      <h1>📊 Kite Stock Analyzer</h1>
      <div style="font-size:12px;color:#475569;margin-top:4px;">
        Last updated: {timestamp} &nbsp;·&nbsp; Auto-refreshes every {INTERVAL_SECONDS//60} min
      </div>
    </div>
    <div style="display:flex;gap:8px;">
      <span class="badge buy">▲ {buy_count} BUY</span>
      <span class="badge sell">▼ {sell_count} SELL</span>
      <span class="badge hold">◆ {hold_count} HOLD</span>
    </div>
  </div>

  <div class="refresh-bar"><div class="refresh-fill"></div></div>

  <table>
    <thead>
      <tr>
        <th>Symbol</th><th>LTP</th><th>Change</th>
        <th>Signal</th><th>Confidence</th>
        <th>Vol Ratio</th><th>RSI ({RSI_PERIOD})</th><th>Analysis</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

  <p style="margin-top:28px;font-size:11px;color:#334155;text-align:center;">
    ⚠️ For educational/informational purposes only. Not financial advice.
    Signals based on {HISTORY_LEN}-tick rolling window · MA{SHORT_MA}/MA{LONG_MA} crossover · RSI{RSI_PERIOD} · Volume spike detection.
  </p>
</body>
</html>"""


# ── Main Loop ──

def run():
    print("=" * 55)
    print("  Zerodha Kite Browser Stock Analyzer")
    print("=" * 55)
    print(f"  Stocks   : {', '.join(s['symbol'] for s in STOCKS)}")
    print(f"  Interval : {INTERVAL_SECONDS}s")
    print(f"  Report   : {os.path.abspath(REPORT_FILE)}")
    print("=" * 55)

    driver = connect_to_browser()

    # Make sure we're on kite
    if "kite.zerodha.com" not in driver.current_url:
        print("[→] Navigating to Kite...")
        driver.get("https://kite.zerodha.com/")
        time.sleep(3)

    report_opened = False
    cycle = 0

    while True:
        cycle += 1
        ts = datetime.now().strftime("%d %b %Y, %I:%M:%S %p")
        print(f"\n[Cycle {cycle}] {ts}")
        results = []

        for stock in STOCKS:
            sym = stock["symbol"]
            exch = stock["exchange"]
            print(f"  Fetching {sym}...", end=" ", flush=True)

            quote = fetch_quote_via_kite_api(driver, exch, sym)
            if not quote:
                print("FAILED")
                continue

            ltp    = quote.get("last_price", 0)
            volume = quote.get("volume", 0)
            ohlc   = quote.get("ohlc", {})
            close  = ohlc.get("close", ltp)

            price_history[sym].append(ltp)
            volume_history[sym].append(volume)

            prices  = list(price_history[sym])
            volumes = list(volume_history[sym])

            rsi      = compute_rsi(prices, RSI_PERIOD)
            short_ma = compute_ma(prices, SHORT_MA)
            long_ma  = compute_ma(prices, LONG_MA)
            vol_ratio= compute_volume_ratio(volumes)
            chg_pct  = round(((ltp - close) / close) * 100, 2) if close else 0

            signal, confidence, reasons = generate_signal(
                rsi, short_ma, long_ma, vol_ratio, ltp, prices[-2] if len(prices) > 1 else None
            )

            results.append({
                "symbol": sym, "exchange": exch,
                "ltp": ltp, "change_pct": chg_pct,
                "rsi": rsi, "short_ma": short_ma, "long_ma": long_ma,
                "volume_ratio": vol_ratio,
                "signal": signal, "confidence": confidence,
                "reasons": reasons
            })
            print(f"₹{ltp:,.2f}  [{signal} / {confidence}]")

        # Write report
        html = build_report(results, ts)
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write(html)

        if not report_opened:
            webbrowser.open(f"file://{os.path.abspath(REPORT_FILE)}")
            report_opened = True
            print(f"  [✓] Report opened: {REPORT_FILE}")
        else:
            print(f"  [✓] Report updated: {REPORT_FILE}")

        print(f"  Sleeping {INTERVAL_SECONDS}s until next cycle...")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
