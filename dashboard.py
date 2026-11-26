"""
PhoneBridge Relay — Dashboard module
====================================

Serves the admin dashboard (HTML) and the JSON snapshot endpoint the
dashboard fetches (`GET /v1/dashboard/snapshot`).

Integration — add these 2 lines to your relay server, *after* the
`app`, `ws_hub`, `discovery_hub`, and `rate_limiter` are defined:

    from dashboard import mount_dashboard
    mount_dashboard(app, ws_hub, discovery_hub, rate_limiter)

Then open:  http://<host>:<port>/dashboard

Environment variables
---------------------
  PHONEBRIDGE_DB      SQLite path (default: phonebridge_relay.db)
  DASHBOARD_TOKEN     If set, requests must send x-dashboard-token: <token>
  DASHBOARD_ENABLED   Set to 0/false to disable the dashboard entirely
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

DB_PATH = os.getenv("PHONEBRIDGE_DB", "phonebridge_relay.db")
DASHBOARD_TOKEN = os.getenv("DASHBOARD_TOKEN", "").strip()
DASHBOARD_ENABLED = os.getenv("DASHBOARD_ENABLED", "1").lower() not in ("0", "false", "no", "off")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


@contextmanager
def _db_read():
    """Read-only connection — safe alongside the relay's WAL writers."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        yield conn
    finally:
        conn.close()


def _fingerprint(pub_key_b64: str) -> str:
    try:
        raw = base64.b64decode(pub_key_b64, validate=True)
        digest = hashlib.sha256(raw).digest()[:12].hex().upper()
        return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
    except Exception:
        return ""


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Return [] instead of raising if the table doesn't exist yet (fresh DB)."""
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------

def build_snapshot(
    ws_hub=None,
    discovery_hub=None,
    rate_limiter=None,
) -> dict[str, Any]:
    current = _now_ms()
    devices: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    pending_pairings: list[dict[str, Any]] = []
    pending_events: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []

    with _db_read() as conn:
        # ---- Devices -------------------------------------------------------
        merged: dict[str, dict[str, Any]] = {}

        for r in _rows(
            conn,
            """
            SELECT device_id, device_name, role, identity_public_key,
                   fingerprint, online, last_seen_at
            FROM discovered_devices
            ORDER BY online DESC, last_seen_at DESC
            """,
        ):
            live = bool(r["online"]) and (current - r["last_seen_at"] <= 90_000)
            if discovery_hub is not None:
                live = live or discovery_hub.is_online(r["device_id"])
            merged[r["device_id"]] = {
                "device_id": r["device_id"],
                "device_name": r["device_name"],
                "role": r["role"],
                "fingerprint": r["fingerprint"] or _fingerprint(r["identity_public_key"]),
                "online": live,
                "last_seen_at": r["last_seen_at"],
            }

        for r in _rows(
            conn,
            """
            SELECT device_id, device_name, role, identity_public_key,
                   created_at, revoked_at
            FROM devices
            WHERE revoked_at IS NULL
            """,
        ):
            if r["device_id"] in merged:
                continue
            online = bool(discovery_hub and discovery_hub.is_online(r["device_id"]))
            merged[r["device_id"]] = {
                "device_id": r["device_id"],
                "device_name": r["device_name"],
                "role": r["role"],
                "fingerprint": _fingerprint(r["identity_public_key"]),
                "online": online,
                "last_seen_at": r["created_at"],
            }

        devices = sorted(merged.values(), key=lambda d: (not d["online"], -d["last_seen_at"]))

        # ---- Relationships -------------------------------------------------
        for r in _rows(
            conn,
            """
            SELECT relationship_id, primary_device_id, secondary_device_id,
                   key_epoch, status, created_at
            FROM device_relationships
            ORDER BY created_at DESC
            LIMIT 100
            """,
        ):
            relationships.append(dict(r))

        # ---- Pending pairings (discovery requests) -------------------------
        for r in _rows(
            conn,
            """
            SELECT request_id, initiator_device_id, initiator_device_name,
                   initiator_role, target_device_id, pairing_pin,
                   expires_at, created_at
            FROM discovery_pair_requests
            WHERE status = 'PENDING' AND expires_at > ?
            ORDER BY created_at DESC
            """,
            (current,),
        ):
            pending_pairings.append(dict(r))

        # ---- Pending encrypted events --------------------------------------
        for r in _rows(
            conn,
            """
            SELECT event_id, relationship_id, sequence_number, payload_type,
                   key_epoch, ciphertext, nonce, authentication_tag,
                   ciphertext_hash, created_at, expires_at
            FROM encrypted_events
            WHERE status = 'SERVER_ACCEPTED' AND expires_at > ?
            ORDER BY sequence_number DESC
            LIMIT 100
            """,
            (current,),
        ):
            pending_events.append(dict(r))

        # ---- Delivery receipts ---------------------------------------------
        for r in _rows(
            conn,
            """
            SELECT event_id, sequence_number, received_at, recorded_at
            FROM delivery_receipts
            ORDER BY recorded_at DESC
            LIMIT 50
            """,
        ):
            receipts.append(dict(r))

    # ---- Live counters from the hubs --------------------------------------
    active_ws = ws_hub.active_count() if ws_hub is not None else 0
    disc_conns = len(discovery_hub.clients) if discovery_hub is not None else 0
    rate_rej = getattr(rate_limiter, "rejected_count", 0) if rate_limiter is not None else 0

    return {
        "devices": devices,
        "relationships": relationships,
        "pending_pairings": pending_pairings,
        "pending_events": pending_events,
        "receipts": receipts,
        "active_ws_connections": active_ws,
        "discovery_connections": disc_conns,
        "rate_limit_rejections": rate_rej,
        "server_time": current,
    }


# ---------------------------------------------------------------------------
# FastAPI mounting
# ---------------------------------------------------------------------------

def mount_dashboard(
    app: FastAPI,
    ws_hub=None,
    discovery_hub=None,
    rate_limiter=None,
) -> None:
    if not DASHBOARD_ENABLED:
        return

    @app.get("/dashboard", response_class=HTMLResponse)
    async def _dashboard_html() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/v1/dashboard/snapshot")
    async def _dashboard_snapshot(request: Request) -> JSONResponse:
        if DASHBOARD_TOKEN:
            provided = request.headers.get("x-dashboard-token", "")
            if not secrets.compare_digest(provided, DASHBOARD_TOKEN):
                raise HTTPException(status_code=401, detail="Invalid dashboard token")
        try:
            return JSONResponse(build_snapshot(ws_hub, discovery_hub, rate_limiter))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"snapshot error: {exc}")

    @app.get("/v1/dashboard/health")
    async def _dashboard_health() -> JSONResponse:
        return JSONResponse({
            "enabled": True,
            "token_required": bool(DASHBOARD_TOKEN),
            "server_time": _now_ms(),
        })


# ---------------------------------------------------------------------------
# Embedded dashboard HTML — Apple-style minimal monochrome
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>PhoneBridge Relay</title>
<style>
  :root {
    --bg: #fafafa;
    --surface: #ffffff;
    --surface-2: #f5f5f7;
    --surface-3: #efeff1;
    --border: #e5e5e7;
    --border-strong: #d2d2d7;
    --text: #1d1d1f;
    --text-secondary: #6e6e73;
    --text-tertiary: #86868b;
    --radius: 14px;
    --radius-sm: 8px;
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", Helvetica, Arial, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  html, body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.5;
    letter-spacing: -0.01em;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  /* --- Header ----------------------------------------------------------- */
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    padding: 18px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
    background: rgba(255, 255, 255, 0.72);
    backdrop-filter: saturate(180%) blur(20px);
    -webkit-backdrop-filter: saturate(180%) blur(20px);
    border-bottom: 1px solid var(--border);
  }
  header h1 {
    font-size: 15px;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  header h1 .dim { color: var(--text-tertiary); font-weight: 400; }
  header .spacer { flex: 1; }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 500;
    line-height: 1;
  }
  .status-pill::before {
    content: "";
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }
  .status-pill.live {
    background: var(--text);
    color: #fff;
  }
  .status-pill.loading {
    background: var(--surface-2);
    color: var(--text-tertiary);
  }
  .status-pill.loading::before { animation: pulse 1.2s ease-in-out infinite; }
  .status-pill.error {
    background: transparent;
    color: var(--text);
    box-shadow: inset 0 0 0 1px var(--text);
  }
  @keyframes pulse {
    0%, 100% { opacity: 0.35; }
    50%      { opacity: 1; }
  }

  header input {
    width: 220px;
    background: var(--surface-2);
    border: 1px solid transparent;
    color: var(--text);
    font: 12px var(--mono);
    padding: 8px 12px;
    border-radius: 999px;
    outline: none;
    transition: all 0.15s ease;
  }
  header input::placeholder { color: var(--text-tertiary); }
  header input:focus {
    background: var(--surface);
    border-color: var(--border-strong);
    box-shadow: 0 0 0 4px rgba(0, 0, 0, 0.04);
  }

  button.primary {
    background: var(--text);
    color: var(--surface);
    border: 0;
    padding: 8px 18px;
    border-radius: 999px;
    font-family: var(--sans);
    font-size: 13px;
    font-weight: 500;
    letter-spacing: -0.01em;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  button.primary:hover  { background: #333336; }
  button.primary:active { transform: scale(0.98); }
  button.primary:disabled { opacity: 0.4; cursor: default; }

  /* --- Layout ----------------------------------------------------------- */
  main {
    max-width: 1280px;
    margin: 0 auto;
    padding: 32px;
    display: grid;
    gap: 20px;
    grid-template-columns: repeat(12, 1fr);
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 22px 24px;
    min-width: 0;
  }

  .card h2 {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-tertiary);
    margin-bottom: 16px;
  }
  .card h2 .count {
    background: var(--surface-2);
    color: var(--text);
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0;
  }

  .full  { grid-column: span 12; }
  .half  { grid-column: span 6; }
  .third { grid-column: span 4; }

  /* --- Tables ----------------------------------------------------------- */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    letter-spacing: -0.005em;
  }
  th, td {
    text-align: left;
    padding: 10px 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 280px;
  }
  th {
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-tertiary);
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
  }
  td {
    border-bottom: 1px solid var(--surface-3);
    color: var(--text);
  }
  tr:last-child td { border-bottom: 0; }
  th:first-child, td:first-child { padding-left: 0; }
  th:last-child,  td:last-child  { padding-right: 0; }

  /* --- Utilities -------------------------------------------------------- */
  .mono {
    font-family: var(--mono);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }
  .muted { color: var(--text-tertiary); }

  /* --- Pills / tags ----------------------------------------------------- */
  .pill {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.02em;
    line-height: 1.6;
  }
  .pill-solid {
    background: var(--text);
    color: var(--surface);
  }
  .pill-outline {
    background: transparent;
    color: var(--text);
    box-shadow: inset 0 0 0 1px var(--border-strong);
  }
  .pill-subtle {
    background: var(--surface-2);
    color: var(--text);
  }

  /* --- Inline status dot ------------------------------------------------ */
  .status-inline {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: 13px;
  }
  .status-inline .dot {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--text);
    flex-shrink: 0;
  }
  .status-inline.off { color: var(--text-tertiary); }
  .status-inline.off .dot {
    background: transparent;
    box-shadow: inset 0 0 0 1.5px var(--border-strong);
  }

  /* --- Empty state ------------------------------------------------------ */
  .empty {
    padding: 32px 0;
    text-align: center;
    color: var(--text-tertiary);
    font-size: 13px;
  }

  /* --- Small "Load" button inside events table -------------------------- */
  .load-btn {
    background: transparent;
    border: 1px solid var(--border-strong);
    color: var(--text);
    padding: 3px 12px;
    border-radius: 999px;
    font-family: var(--sans);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    line-height: 1.5;
    transition: all 0.15s ease;
  }
  .load-btn:hover {
    background: var(--text);
    color: var(--surface);
    border-color: var(--text);
  }

  /* --- Key/value grid --------------------------------------------------- */
  .kv {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 10px 16px;
    font-size: 13px;
  }
  .kv .k { color: var(--text-tertiary); }
  .kv .v { color: var(--text); font-family: var(--mono); font-size: 12px; font-variant-numeric: tabular-nums; }

  /* --- Decrypt panel ---------------------------------------------------- */
  details.decrypt { grid-column: span 12; padding: 20px 24px; }
  details.decrypt summary {
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    color: var(--text);
    list-style: none;
    display: flex;
    align-items: center;
    gap: 10px;
    user-select: none;
  }
  details.decrypt summary::-webkit-details-marker { display: none; }
  details.decrypt summary::before {
    content: "›";
    display: inline-block;
    font-size: 18px;
    line-height: 1;
    color: var(--text-tertiary);
    transition: transform 0.18s ease;
  }
  details.decrypt[open] summary::before { transform: rotate(90deg); }

  .decrypt-grid {
    display: grid;
    gap: 16px;
    margin-top: 18px;
    grid-template-columns: 1fr 1fr;
  }
  .decrypt-grid label {
    display: block;
    font-size: 11px;
    font-weight: 500;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 6px;
  }
  .decrypt-grid textarea,
  .decrypt-grid input {
    width: 100%;
    background: var(--surface-2);
    border: 1px solid transparent;
    color: var(--text);
    font: 12px var(--mono);
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    resize: vertical;
    outline: none;
    transition: all 0.15s ease;
  }
  .decrypt-grid textarea:focus,
  .decrypt-grid input:focus {
    background: var(--surface);
    border-color: var(--border-strong);
    box-shadow: 0 0 0 4px rgba(0, 0, 0, 0.04);
  }
  .decrypt-grid textarea { min-height: 76px; }

  .decrypt-out {
    margin-top: 16px;
    background: var(--surface-2);
    border-radius: var(--radius-sm);
    padding: 16px;
    min-height: 60px;
    font: 12px/1.6 var(--mono);
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text);
    transition: box-shadow 0.15s ease;
  }
  .decrypt-out.err {
    box-shadow: inset 3px 0 0 var(--text);
  }

  /* --- Responsive ------------------------------------------------------- */
  @media (max-width: 900px) {
    header { padding: 14px 20px; gap: 10px; }
    header input { width: 140px; }
    header h1 { font-size: 14px; }
    main { padding: 20px; gap: 16px; }
    .half, .third { grid-column: span 12; }
    .card { padding: 18px 20px; }
    .decrypt-grid { grid-template-columns: 1fr; }
    th, td { padding: 8px 8px; max-width: 160px; }
  }
</style>
</head>
<body>

<header>
  <h1>PhoneBridge <span class="dim">Relay</span></h1>
  <span class="status-pill loading" id="status-pill">Connecting</span>
  <span class="muted mono" id="server-time">—</span>
  <div class="spacer"></div>
  <input id="token" type="password" placeholder="Dashboard token" autocomplete="off" />
  <button id="refresh" class="primary">Refresh</button>
</header>

<main>
  <section class="card full">
    <h2>Devices <span class="count" id="dev-count">0</span></h2>
    <div id="devices"></div>
  </section>

  <section class="card half">
    <h2>Relationships <span class="count" id="rel-count">0</span></h2>
    <div id="relationships"></div>
  </section>

  <section class="card half">
    <h2>Pending Pairings <span class="count" id="pr-count">0</span></h2>
    <div id="pairings"></div>
  </section>

  <section class="card full">
    <h2>Pending Events <span class="count" id="ev-count">0</span></h2>
    <div id="events"></div>
  </section>

  <section class="card half">
    <h2>Recent Receipts <span class="count" id="rc-count">0</span></h2>
    <div id="receipts"></div>
  </section>

  <section class="card half">
    <h2>Server</h2>
    <div class="kv" id="server-kv"></div>
  </section>

  <details class="card decrypt">
    <summary>Decrypt an event — key stays in this browser</summary>
    <div class="decrypt-grid">
      <div>
        <label for="ciphertext">Ciphertext (base64)</label>
        <textarea id="ciphertext" spellcheck="false" placeholder="Paste from pending events…"></textarea>
      </div>
      <div>
        <label for="nonce">Nonce (base64, 12 bytes)</label>
        <input id="nonce" spellcheck="false" placeholder="12-byte base64" />
        <label for="key" style="margin-top:14px">AES-256 key (base64, 32 bytes)</label>
        <input id="key" type="password" spellcheck="false" placeholder="32-byte base64" />
        <button id="decrypt" class="primary" style="margin-top:14px">Decrypt</button>
      </div>
    </div>
    <div class="decrypt-out" id="decrypt-out">—</div>
  </details>
</main>

<script>
"use strict";

const $ = (id) => document.getElementById(id);
const tokenInput = $("token");
const refreshBtn = $("refresh");
const statusPill = $("status-pill");
const serverTime = $("server-time");

tokenInput.value = sessionStorage.getItem("pb_token") || "";
tokenInput.addEventListener("input", () => {
  sessionStorage.setItem("pb_token", tokenInput.value);
});
refreshBtn.addEventListener("click", () => refresh());

function fmtTime(ms) {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false }) + "  ·  " + d.toLocaleDateString();
}
function ago(ms) {
  if (!ms) return "—";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
  }[c]));
}
function shortId(s) {
  if (!s) return "—";
  return s.length > 18 ? s.slice(0, 10) + "…" + s.slice(-6) : s;
}
function setStatus(text, cls) {
  statusPill.textContent = text;
  statusPill.className = "status-pill " + cls;
}
function table(headers, rows, emptyMsg) {
  if (!rows.length) return `<div class="empty">${esc(emptyMsg)}</div>`;
  const th = headers.map(h => `<th>${esc(h)}</th>`).join("");
  const tr = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("");
  return `<table><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}

function render(snap) {
  serverTime.textContent = fmtTime(snap.server_time);

  // Devices
  const devRows = (snap.devices || []).map(d => {
    const online = d.online
      ? `<span class="status-inline"><span class="dot"></span>Online</span>`
      : `<span class="status-inline off"><span class="dot"></span>Offline</span>`;
    return [
      `<span class="mono" title="${esc(d.device_id)}">${esc(shortId(d.device_id))}</span>`,
      esc(d.device_name),
      `<span class="pill ${d.role === 'PRIMARY' ? 'pill-solid' : 'pill-outline'}">${esc(d.role)}</span>`,
      `<span class="mono muted" title="${esc(d.fingerprint)}">${esc(d.fingerprint || '—')}</span>`,
      online,
      `<span class="muted">${esc(ago(d.last_seen_at))}</span>`,
    ];
  });
  $("devices").innerHTML = table(
    ["Device", "Name", "Role", "Fingerprint", "Status", "Last seen"],
    devRows, "No devices have announced yet."
  );
  $("dev-count").textContent = (snap.devices || []).length;

  // Relationships
  const relRows = (snap.relationships || []).map(r => [
    `<span class="mono" title="${esc(r.relationship_id)}">${esc(shortId(r.relationship_id))}</span>`,
    `<span class="mono">${esc(shortId(r.primary_device_id))}</span>`,
    `<span class="mono">${esc(shortId(r.secondary_device_id))}</span>`,
    `<span class="mono">${esc(r.key_epoch)}</span>`,
    `<span class="pill ${r.status === 'ACTIVE' ? 'pill-solid' : 'pill-outline'}">${esc(r.status)}</span>`,
    `<span class="muted">${esc(ago(r.created_at))}</span>`,
  ]);
  $("relationships").innerHTML = table(
    ["Relationship", "Primary", "Secondary", "Epoch", "Status", "Created"],
    relRows, "No relationships yet."
  );
  $("rel-count").textContent = (snap.relationships || []).length;

  // Pending pairings
  const prRows = (snap.pending_pairings || []).map(p => [
    `<span class="mono" title="${esc(p.request_id)}">${esc(shortId(p.request_id))}</span>`,
    `${esc(p.initiator_device_name)} <span class="muted mono">(${esc(p.initiator_role)})</span>`,
    `<span class="mono">${esc(p.pairing_pin)}</span>`,
    `<span class="muted">expires ${esc(ago(p.expires_at))}</span>`,
  ]);
  $("pairings").innerHTML = table(
    ["Request", "Initiator", "PIN", "TTL"],
    prRows, "No pairing requests pending."
  );
  $("pr-count").textContent = (snap.pending_pairings || []).length;

  // Pending events
  const evRows = (snap.pending_events || []).map(e => [
    `<span class="mono" title="${esc(e.event_id)}">${esc(shortId(e.event_id))}</span>`,
    `<span class="mono">${esc(e.sequence_number)}</span>`,
    `<span class="pill pill-subtle">${esc(e.payload_type)}</span>`,
    `<span class="mono">${esc(e.key_epoch)}</span>`,
    `<span class="muted">${esc(ago(e.created_at))}</span>`,
    `<span class="muted">${esc(ago(e.expires_at))}</span>`,
    `<button data-cipher="${esc(e.ciphertext)}" data-nonce="${esc(e.nonce)}" class="load-btn">Load</button>`,
  ]);
  $("events").innerHTML = table(
    ["Event", "Seq", "Type", "Epoch", "Created", "Expires", ""],
    evRows, "No pending events — the queue is empty."
  );
  $("ev-count").textContent = (snap.pending_events || []).length;

  document.querySelectorAll(".load-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $("ciphertext").value = btn.dataset.cipher;
      $("nonce").value = btn.dataset.nonce;
      document.querySelector("details.decrypt").open = true;
      $("ciphertext").scrollIntoView({ behavior: "smooth", block: "center" });
    });
  });

  // Receipts
  const rcRows = (snap.receipts || []).map(r => [
    `<span class="mono" title="${esc(r.event_id)}">${esc(shortId(r.event_id))}</span>`,
    `<span class="mono">${esc(r.sequence_number)}</span>`,
    `<span class="muted">${esc(fmtTime(r.received_at))}</span>`,
    `<span class="muted">${esc(ago(r.recorded_at))}</span>`,
  ]);
  $("receipts").innerHTML = table(
    ["Event", "Seq", "Received", "Recorded"],
    rcRows, "No delivery receipts yet."
  );
  $("rc-count").textContent = (snap.receipts || []).length;

  // Server KV
  $("server-kv").innerHTML = `
    <div class="k">Active WebSockets</div><div class="v">${esc(snap.active_ws_connections)}</div>
    <div class="k">Discovery sockets</div><div class="v">${esc(snap.discovery_connections)}</div>
    <div class="k">Rate-limit rejections</div><div class="v">${esc(snap.rate_limit_rejections)}</div>
    <div class="k">Server time</div><div class="v">${esc(fmtTime(snap.server_time))}</div>
  `;
}

async function refresh() {
  const token = tokenInput.value.trim();
  setStatus("Loading", "loading");
  try {
    const headers = {};
    if (token) headers["x-dashboard-token"] = token;
    const res = await fetch("/v1/dashboard/snapshot", { headers, cache: "no-store" });
    if (res.status === 401) { setStatus("Bad token", "error"); return; }
    if (res.status === 404) { setStatus("Disabled", "error"); return; }
    if (!res.ok)            { setStatus("HTTP " + res.status, "error"); return; }
    const snap = await res.json();
    render(snap);
    setStatus("Live", "live");
    clearTimeout(refresh._t);
    refresh._t = setTimeout(() => {
      if (!document.hidden) refresh();
    }, 5000);
  } catch (e) {
    setStatus("Unreachable", "error");
  }
}

// --- Decrypt panel -------------------------------------------------------
function b64(s) {
  const norm = String(s).replace(/\s+/g, "");
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

$("decrypt").addEventListener("click", async () => {
  const out = $("decrypt-out");
  out.className = "decrypt-out";
  out.textContent = "…";
  try {
    const keyBytes = b64($("key").value);
    if (keyBytes.length !== 32) throw new Error("Key must be 32 bytes (AES-256).");
    const nonceBytes = b64($("nonce").value);
    if (nonceBytes.length !== 12) throw new Error("Nonce must be 12 bytes.");
    const ct = b64($("ciphertext").value);
    const cryptoKey = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
    );
    let plain;
    try {
      plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
        cryptoKey, ct
      );
    } catch (_) {
      throw new Error("Decryption failed — wrong key, nonce, or ciphertext.");
    }
    const text = new TextDecoder().decode(plain);
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
    out.className = "decrypt-out";
    out.textContent = pretty;
  } catch (e) {
    out.className = "decrypt-out err";
    out.textContent = String(e.message || e);
  }
});

refresh();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    _app = FastAPI(title="PhoneBridge Relay — Dashboard only")
    mount_dashboard(_app)
    uvicorn.run(_app, host="0.0.0.0", port=8080)
