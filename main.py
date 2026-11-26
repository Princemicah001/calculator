"""
PhoneBridge Relay Server (Python / FastAPI / SQLite WAL / WebSockets)
Protocol Version: 1 — 100% compatible with the PhoneBridge Android Client.

Zero-knowledge store-and-forward relay:
- Primary (Tecno) submits AES-256-GCM encrypted envelopes via POST /v1/events.
- Relay durably persists ciphertexts, pushes realtime frames over WSS /v1/ws,
  and serves paginated cursor sync via POST /v1/sync or GET /v1/events/pending.
- Secondary (Samsung) decrypts locally and sends authenticated ACKs back.
- Relay NEVER sees plaintext notification content or the 6-digit SPAKE2 pairing PIN.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

PROTOCOL_VERSION = 1
MAX_ENCRYPTED_PAYLOAD_BYTES = 65_536
MAX_SYNC_BATCH_SIZE = 50
PAIRING_TTL_MS = 300_000
MAX_PAIRING_ATTEMPTS = 5
CREDENTIAL_TTL_MS = 90 * 86_400_000
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
MAX_WS_PER_DEVICE = int(os.getenv("MAX_WS_PER_DEVICE", "2"))
DB_PATH = os.getenv("PHONEBRIDGE_DB", "phonebridge_relay.db")


def now_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_ecdsa_signature(pub_key_b64: str, canonical: bytes, signature_b64: str) -> bool:
    try:
        pub_bytes = base64.b64decode(pub_key_b64, validate=True)
        pub_key = serialization.load_der_public_key(pub_bytes)
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            return False
        sig_bytes = base64.b64decode(signature_b64, validate=True)
        pub_key.verify(sig_bytes, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# SQLite Durable Persistence (WAL Mode)
# ---------------------------------------------------------------------------

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH, timeout=15.0, isolation_level=None)
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('PRIMARY', 'SECONDARY')),
                identity_public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS device_relationships (
                relationship_id TEXT PRIMARY KEY,
                primary_device_id TEXT NOT NULL REFERENCES devices(device_id),
                secondary_device_id TEXT NOT NULL REFERENCES devices(device_id),
                key_epoch INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS device_credentials (
                credential_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                relationship_id TEXT,
                token_hash_sha256 TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pairing_sessions (
                pairing_session_id TEXT PRIMARY KEY,
                primary_device_id TEXT NOT NULL,
                primary_device_name TEXT NOT NULL,
                primary_identity_public_key TEXT NOT NULL,
                spake2_message_a TEXT NOT NULL,
                spake2_message_b TEXT,
                key_confirmation_mac_b TEXT,
                identity_signature_b TEXT,
                secondary_device_id TEXT,
                secondary_device_name TEXT,
                secondary_identity_public_key TEXT,
                relationship_id TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 5,
                completed INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS encrypted_events (
                event_id TEXT NOT NULL,
                relationship_id TEXT NOT NULL REFERENCES device_relationships(relationship_id),
                source_device_id TEXT NOT NULL,
                destination_device_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                protocol_version INTEGER NOT NULL DEFAULT 1,
                key_epoch INTEGER NOT NULL DEFAULT 1,
                payload_type TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                authentication_tag TEXT NOT NULL,
                ciphertext_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                accepted_at INTEGER NOT NULL,
                recipient_received_at INTEGER,
                status TEXT NOT NULL CHECK (status IN ('SERVER_ACCEPTED', 'DEVICE_RECEIVED', 'EXPIRED')),
                PRIMARY KEY (relationship_id, event_id),
                UNIQUE (relationship_id, sequence_number)
            );

            CREATE INDEX IF NOT EXISTS idx_events_pending
                ON encrypted_events(relationship_id, status, sequence_number);

            CREATE INDEX IF NOT EXISTS idx_events_exp
                ON encrypted_events(expires_at);

            CREATE TABLE IF NOT EXISTS delivery_receipts (
                receipt_id TEXT PRIMARY KEY,
                relationship_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                ack_mac TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                recorded_at INTEGER NOT NULL,
                UNIQUE (relationship_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS sync_metadata (
                relationship_id TEXT PRIMARY KEY,
                highest_accepted_sequence INTEGER NOT NULL DEFAULT 0,
                expired_sequence_floor INTEGER NOT NULL DEFAULT 0,
                last_sync_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS device_revocations (
                revocation_id TEXT PRIMARY KEY,
                relationship_id TEXT NOT NULL,
                revoked_device_id TEXT NOT NULL,
                initiated_by_device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                revoked_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_nonces (
                nonce TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovered_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('PRIMARY', 'SECONDARY')),
                identity_public_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                online INTEGER NOT NULL DEFAULT 1,
                last_seen_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovery_pair_requests (
                request_id TEXT PRIMARY KEY,
                initiator_device_id TEXT NOT NULL,
                initiator_device_name TEXT NOT NULL,
                initiator_role TEXT NOT NULL CHECK (initiator_role IN ('PRIMARY', 'SECONDARY')),
                initiator_identity_public_key TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                target_device_name TEXT NOT NULL,
                target_role TEXT NOT NULL CHECK (target_role IN ('PRIMARY', 'SECONDARY')),
                assigned_primary_device_id TEXT NOT NULL,
                assigned_secondary_device_id TEXT NOT NULL,
                pairing_session_id TEXT NOT NULL,
                pairing_pin TEXT NOT NULL,
                spake2_message_a TEXT,
                spake2_message_b TEXT,
                key_confirmation_mac_a TEXT,
                key_confirmation_mac_b TEXT,
                identity_signature_a TEXT,
                identity_signature_b TEXT,
                relationship_id TEXT,
                initiator_token_once TEXT,
                status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'DECLINED', 'EXPIRED')),
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
    finally:
        conn.close()


@contextmanager
def db_tx():
    conn = sqlite3.connect(DB_PATH, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Protocol DTOs
# ---------------------------------------------------------------------------

class RelayError(Exception):
    def __init__(self, status_code: int, code: str, message: str, retry_after_seconds: int | None = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after_seconds = retry_after_seconds


class EventEnvelope(BaseModel):
    protocol_version: int = 1
    event_id: str
    relationship_id: str
    sequence_number: int
    key_epoch: int = 1
    created_at: int
    expires_at: int
    payload_type: Literal["NOTIFICATION", "CALENDAR_EVENT", "HEARTBEAT_TEST"]
    ciphertext: str
    nonce: str
    authentication_tag: str
    ciphertext_hash: str


class PairingInitiateRequest(BaseModel):
    protocol_version: int = 1
    device_id: str
    device_name: str
    identity_public_key: str
    spake2_message_a: str
    pairing_session_id: str


class PairingCompleteRequest(BaseModel):
    protocol_version: int = 1
    pairing_session_id: str
    secondary_device_id: str
    secondary_device_name: str
    secondary_identity_public_key: str
    spake2_message_b: str
    key_confirmation_mac_b: str
    identity_signature_b: str


class SyncRequest(BaseModel):
    protocol_version: int = 1
    relationship_id: str
    after_sequence: int = 0
    limit: int = Field(default=50, ge=1, le=50)


class AckItem(BaseModel):
    event_id: str
    sequence_number: int
    received_at: int
    ack_mac: str


class AcknowledgeEventsRequest(BaseModel):
    protocol_version: int = 1
    relationship_id: str
    acknowledgements: list[AckItem]


class RevokeDeviceRequest(BaseModel):
    relationship_id: str
    target_device_id: str
    reason: str


class DiscoveryAnnounceRequest(BaseModel):
    protocol_version: int = 1
    device_id: str
    device_name: str
    role: Literal["PRIMARY", "SECONDARY"]
    identity_public_key: str


class DiscoveryPairRequestPayload(BaseModel):
    protocol_version: int = 1
    request_id: str
    initiator_device_id: str
    initiator_device_name: str
    initiator_role: Literal["PRIMARY", "SECONDARY"]
    initiator_identity_public_key: str
    target_device_id: str
    assigned_primary_device_id: str
    assigned_secondary_device_id: str
    pairing_session_id: str
    pairing_pin: str
    spake2_message_a: str | None = None
    spake2_message_b: str | None = None


class DiscoveryPairAcceptPayload(BaseModel):
    protocol_version: int = 1
    request_id: str
    acceptor_device_id: str
    acceptor_device_name: str
    acceptor_identity_public_key: str
    spake2_message_a: str | None = None
    spake2_message_b: str | None = None
    key_confirmation_mac_a: str | None = None
    key_confirmation_mac_b: str | None = None
    identity_signature_a: str | None = None
    identity_signature_b: str | None = None


class DiscoveryPairDeclinePayload(BaseModel):
    protocol_version: int = 1
    request_id: str
    device_id: str


# ---------------------------------------------------------------------------
# Rate Limiter & WebSocket Hub
# ---------------------------------------------------------------------------

class SlidingRateLimiter:
    def __init__(self, max_per_min: int):
        self.max_per_min = max_per_min
        self.buckets: dict[str, deque[float]] = defaultdict(deque)
        self.rejected_count = 0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.buckets[key]
        while q and now - q[0] >= 60.0:
            q.popleft()
        if len(q) >= self.max_per_min:
            self.rejected_count += 1
            return False
        q.append(now)
        return True


class WebSocketHub:
    def __init__(self):
        # relationship_id -> list[(device_id, role, WebSocket)]
        self.rooms: dict[str, list[tuple[str, str, WebSocket]]] = defaultdict(list)

    def register(self, relationship_id: str, device_id: str, role: str, ws: WebSocket) -> bool:
        peers = self.rooms[relationship_id]
        if sum(1 for d, _, _ in peers if d == device_id) >= MAX_WS_PER_DEVICE:
            return False
        peers.append((device_id, role, ws))
        return True

    def unregister(self, relationship_id: str, ws: WebSocket) -> None:
        peers = self.rooms.get(relationship_id)
        if not peers:
            return
        self.rooms[relationship_id] = [item for item in peers if item[2] is not ws]
        if not self.rooms[relationship_id]:
            self.rooms.pop(relationship_id, None)

    def active_count(self) -> int:
        return sum(len(v) for v in self.rooms.values())

    async def _safe_send(self, relationship_id: str, ws: WebSocket, frame: str) -> None:
        try:
            await ws.send_text(frame)
        except Exception:
            self.unregister(relationship_id, ws)

    async def push_event_to_secondary(self, relationship_id: str, envelope: dict[str, Any]) -> None:
        frame = json.dumps(
            {
                "type": "EVENT",
                "relationship_id": relationship_id,
                "event_id": envelope["event_id"],
                "envelope": envelope,
                "timestamp": now_ms(),
            }
        )
        for _, role, ws in list(self.rooms.get(relationship_id, [])):
            if role == "SECONDARY":
                await self._safe_send(relationship_id, ws, frame)

    async def push_receipt_to_primary(self, relationship_id: str, ack: dict[str, Any]) -> None:
        frame = json.dumps(
            {
                "type": "RECEIPT",
                "relationship_id": relationship_id,
                "event_id": ack["event_id"],
                "ack": ack,
                "status": "DEVICE_RECEIVED",
                "timestamp": now_ms(),
            }
        )
        for _, role, ws in list(self.rooms.get(relationship_id, [])):
            if role == "PRIMARY":
                await self._safe_send(relationship_id, ws, frame)

    async def close_relationship(self, relationship_id: str) -> None:
        for _, _, ws in self.rooms.pop(relationship_id, []):
            try:
                await ws.close(code=4403, reason="Relationship revoked")
            except Exception:
                pass


def fingerprint_from_pubkey(pub_key_b64: str) -> str:
    try:
        raw = base64.b64decode(pub_key_b64, validate=True)
        digest = hashlib.sha256(raw).digest()[:12].hex().upper()
        return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
    except Exception:
        return "0000 0000 0000"


class DiscoveryHub:
    def __init__(self):
        self.clients: dict[str, list[WebSocket]] = defaultdict(list)

    def register(self, device_id: str, ws: WebSocket) -> None:
        conns = self.clients[device_id]
        if len(conns) >= MAX_WS_PER_DEVICE:
            old = conns.pop(0)
            asyncio.create_task(self._close_quietly(old))
        conns.append(ws)

    def unregister(self, device_id: str, ws: WebSocket) -> bool:
        conns = self.clients.get(device_id)
        if not conns:
            return False
        self.clients[device_id] = [c for c in conns if c is not ws]
        if not self.clients[device_id]:
            self.clients.pop(device_id, None)
            return True
        return False

    def is_online(self, device_id: str) -> bool:
        return bool(self.clients.get(device_id))

    async def _close_quietly(self, ws: WebSocket) -> None:
        try:
            await ws.close(code=1000, reason="Replaced by newer discovery connection")
        except Exception:
            pass

    async def send_to_device(self, device_id: str, payload: dict[str, Any]) -> None:
        frame = json.dumps(payload)
        for ws in list(self.clients.get(device_id, [])):
            try:
                await ws.send_text(frame)
            except Exception:
                self.unregister(device_id, ws)

    def list_devices(self, exclude_device_id: str | None = None) -> list[dict[str, Any]]:
        current = now_ms()
        cutoff = current - 90_000
        with db_tx() as conn:
            rows = conn.execute(
                """
                SELECT device_id, device_name, role, identity_public_key, fingerprint, online, last_seen_at
                FROM discovered_devices
                WHERE (online = 1 OR last_seen_at >= ?)
                ORDER BY online DESC, last_seen_at DESC
                """,
                (cutoff,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            dev_id = r["device_id"]
            if exclude_device_id and dev_id == exclude_device_id:
                continue
            is_live = self.is_online(dev_id) or (bool(r["online"]) and (current - r["last_seen_at"] <= 35_000))
            if not is_live:
                continue
            result.append(
                {
                    "device_id": dev_id,
                    "device_name": r["device_name"],
                    "role": r["role"],
                    "identity_public_key": r["identity_public_key"],
                    "fingerprint": r["fingerprint"],
                    "online": True,
                    "last_seen_at": r["last_seen_at"],
                }
            )
        return result

    def list_pending_incoming(self, target_device_id: str) -> list[dict[str, Any]]:
        current = now_ms()
        with db_tx() as conn:
            rows = conn.execute(
                """
                SELECT * FROM discovery_pair_requests
                WHERE target_device_id = ? AND status = 'PENDING' AND expires_at > ?
                ORDER BY created_at DESC
                """,
                (target_device_id, current),
            ).fetchall()
        return [_format_incoming_pair_request(r) for r in rows]

    async def broadcast_devices_to_all(self) -> None:
        current = now_ms()
        for dev_id in list(self.clients.keys()):
            devices = self.list_devices(exclude_device_id=dev_id)
            await self.send_to_device(
                dev_id,
                {
                    "type": "DISCOVERY_UPDATE",
                    "devices": devices,
                    "timestamp": current,
                },
            )


def _format_incoming_pair_request(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "request_id": row["request_id"],
        "initiator_device_id": row["initiator_device_id"],
        "initiator_device_name": row["initiator_device_name"],
        "initiator_role": row["initiator_role"],
        "initiator_identity_public_key": row["initiator_identity_public_key"],
        "initiator_fingerprint": fingerprint_from_pubkey(row["initiator_identity_public_key"]),
        "target_device_id": row["target_device_id"],
        "assigned_primary_device_id": row["assigned_primary_device_id"],
        "assigned_secondary_device_id": row["assigned_secondary_device_id"],
        "pairing_session_id": row["pairing_session_id"],
        "pairing_pin": row["pairing_pin"],
        "spake2_message_a": row["spake2_message_a"],
        "spake2_message_b": row["spake2_message_b"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
    }


rate_limiter = SlidingRateLimiter(RATE_LIMIT_PER_MIN)
ws_hub = WebSocketHub()
discovery_hub = DiscoveryHub()


# ---------------------------------------------------------------------------
# Auth & Expiration Helpers
# ---------------------------------------------------------------------------

def authenticate_headers(
    headers: dict[str, str],
    method: str,
    path_only: str,
    body_bytes: bytes,
    require_token: bool = True,
    inline_pubkey: str | None = None,
) -> dict[str, Any]:
    h = {k.lower(): v for k, v in headers.items()}
    device_id = h.get("x-device-id", "").strip()
    ts_raw = h.get("x-timestamp", "").strip()
    nonce = h.get("x-nonce", "").strip()
    sig_b64 = h.get("x-signature", "").strip()

    if not device_id or not ts_raw.isdigit() or not (8 <= len(nonce) <= 120) or not sig_b64:
        raise RelayError(401, "UNAUTHORIZED_DEVICE", "Missing signed device headers")

    ts = int(ts_raw)
    current = now_ms()
    if abs(current - ts) > 300_000:
        raise RelayError(401, "UNAUTHORIZED_DEVICE", "Request timestamp outside allowed window")

    canonical = f"{method}|{path_only}|{ts}|{nonce}|{sha256_hex(body_bytes)}".encode("utf-8")

    if not require_token:
        if not inline_pubkey or not verify_ecdsa_signature(inline_pubkey, canonical, sig_b64):
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Invalid ECDSA request signature")
        result: dict[str, Any] = {"device_id": device_id, "role": "UNBOUND", "relationship_id": None}
    else:
        auth_header = h.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Missing Bearer token")
        bearer = auth_header.removeprefix("Bearer ").strip()
        token_hash = sha256_hex(bearer.encode("utf-8"))

        with db_tx() as conn:
            row = conn.execute(
                """
                SELECT d.role, d.identity_public_key, d.revoked_at AS dev_revoked,
                       c.relationship_id, c.expires_at, c.revoked_at AS cred_revoked
                FROM device_credentials c
                JOIN devices d ON d.device_id = c.device_id
                WHERE c.device_id = ? AND c.token_hash_sha256 = ?
                """,
                (device_id, token_hash),
            ).fetchone()

        if not row:
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Invalid device credential")
        if row["dev_revoked"] is not None or row["cred_revoked"] is not None:
            raise RelayError(403, "REVOKED_PAIRING", "Device credential revoked")
        if current > row["expires_at"]:
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Device credential expired")
        if not verify_ecdsa_signature(row["identity_public_key"], canonical, sig_b64):
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Invalid ECDSA request signature")

        result = {
            "device_id": device_id,
            "role": row["role"],
            "relationship_id": row["relationship_id"],
        }

    with db_tx() as conn:
        try:
            conn.execute(
                "INSERT INTO auth_nonces (nonce, device_id, expires_at) VALUES (?, ?, ?)",
                (nonce, device_id, current + 600_000),
            )
        except sqlite3.IntegrityError:
            raise RelayError(401, "UNAUTHORIZED_DEVICE", "Replay nonce rejected")

    return result


def purge_expired_records() -> int:
    current = now_ms()
    with db_tx() as conn:
        conn.execute(
            """
            UPDATE sync_metadata
            SET expired_sequence_floor = COALESCE(
                (SELECT MAX(e.sequence_number) FROM encrypted_events e
                 WHERE e.relationship_id = sync_metadata.relationship_id AND e.expires_at <= ?),
                expired_sequence_floor
            )
            """,
            (current,),
        )
        cur = conn.execute("DELETE FROM encrypted_events WHERE expires_at <= ?", (current,))
        conn.execute("DELETE FROM pairing_sessions WHERE expires_at <= ?", (current,))
        conn.execute("DELETE FROM discovery_pair_requests WHERE expires_at <= ?", (current,))
        conn.execute("DELETE FROM auth_nonces WHERE expires_at <= ?", (current,))
        return cur.rowcount


# ---------------------------------------------------------------------------
# FastAPI Lifespan & App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()

    async def cleanup_loop():
        while True:
            try:
                purge_expired_records()
            except Exception:
                pass
            await asyncio.sleep(60)

    task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="PhoneBridge Relay", version="1.0.0", lifespan=lifespan)


@app.exception_handler(RelayError)
async def relay_error_handler(_: Request, exc: RelayError):
    headers = {"Retry-After": str(exc.retry_after_seconds)} if exc.retry_after_seconds else {}
    return JSONResponse(
        status_code=exc.status_code,
        headers=headers,
        content={
            "code": exc.code,
            "message": exc.message,
            "retry_after_seconds": exc.retry_after_seconds,
        },
    )


@app.exception_handler(ValidationError)
async def validation_error_handler(_: Request, exc: ValidationError):
    return JSONResponse(
        status_code=400,
        content={
            "code": "INVALID_PAYLOAD",
            "message": "Invalid request payload",
            "retry_after_seconds": None,
        },
    )


@app.get("/v1/health")
async def health():
    db_ok = True
    try:
        with db_tx() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception:
        db_ok = False
    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status": "OK" if db_ok else "DEGRADED",
            "protocol_version": PROTOCOL_VERSION,
            "database_ok": db_ok,
            "active_ws_connections": ws_hub.active_count(),
            "server_time": now_ms(),
        },
    )


@app.get("/v1/metrics")
async def metrics():
    with db_tx() as conn:
        rels = conn.execute("SELECT COUNT(*) FROM device_relationships WHERE status = 'ACTIVE'").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM encrypted_events WHERE status = 'SERVER_ACCEPTED'").fetchone()[0]
    return {
        "active_relationships": rels,
        "pending_encrypted_events": pending,
        "active_ws_connections": ws_hub.active_count(),
        "expired_events_purged": 0,
        "rate_limit_rejections": rate_limiter.rejected_count,
    }


@app.post("/v1/pairing/initiate")
async def initiate_pairing(request: Request):
    caller = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "local")
    if not rate_limiter.allow(f"pair:{caller}"):
        raise RelayError(429, "RATE_LIMITED", "Too many pairing attempts", 60)

    raw = await request.body()
    req = PairingInitiateRequest.model_validate_json(raw)
    if req.protocol_version != PROTOCOL_VERSION:
        raise RelayError(426, "UNSUPPORTED_PROTOCOL", "Unsupported protocol version")

    authenticate_headers(
        dict(request.headers), "POST", "/v1/pairing/initiate", raw,
        require_token=False, inline_pubkey=req.identity_public_key,
    )

    current = now_ms()
    expires_at = current + PAIRING_TTL_MS
    token = secrets.token_urlsafe(32)
    token_hash = sha256_hex(token.encode("utf-8"))

    with db_tx() as conn:
        conn.execute(
            """
            INSERT INTO devices (device_id, device_name, role, identity_public_key, created_at, revoked_at)
            VALUES (?, ?, 'PRIMARY', ?, ?, NULL)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                identity_public_key=excluded.identity_public_key,
                revoked_at=NULL
            """,
            (req.device_id, req.device_name, req.identity_public_key, current),
        )
        conn.execute(
            """
            INSERT INTO pairing_sessions (
                pairing_session_id, primary_device_id, primary_device_name,
                primary_identity_public_key, spake2_message_a,
                attempt_count, max_attempts, completed, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, ?)
            """,
            (
                req.pairing_session_id,
                req.device_id,
                req.device_name,
                req.identity_public_key,
                req.spake2_message_a,
                MAX_PAIRING_ATTEMPTS,
                expires_at,
                current,
            ),
        )
        conn.execute(
            """
            INSERT INTO device_credentials (credential_id, device_id, relationship_id, token_hash_sha256, expires_at, created_at)
            VALUES (?, ?, NULL, ?, ?, ?)
            """,
            (str(uuid.uuid4()), req.device_id, token_hash, current + CREDENTIAL_TTL_MS, current),
        )

    return {
        "pairing_session_id": req.pairing_session_id,
        "expires_at": expires_at,
        "device_token": token,
    }


@app.post("/v1/pairing/complete")
async def complete_pairing(request: Request):
    caller = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "local")
    if not rate_limiter.allow(f"pair:{caller}"):
        raise RelayError(429, "RATE_LIMITED", "Too many pairing attempts", 60)

    raw = await request.body()
    req = PairingCompleteRequest.model_validate_json(raw)
    authenticate_headers(
        dict(request.headers), "POST", "/v1/pairing/complete", raw,
        require_token=False, inline_pubkey=req.secondary_identity_public_key,
    )

    current = now_ms()
    sec_token = secrets.token_urlsafe(32)
    sec_token_hash = sha256_hex(sec_token.encode("utf-8"))

    with db_tx() as conn:
        sess = conn.execute(
            "SELECT * FROM pairing_sessions WHERE pairing_session_id = ?",
            (req.pairing_session_id,),
        ).fetchone()
        if not sess:
            raise RelayError(404, "INVALID_EVENT", "Pairing session not found")
        if current > sess["expires_at"]:
            raise RelayError(410, "EXPIRED_EVENT", "Pairing session expired")
        if sess["attempt_count"] >= sess["max_attempts"]:
            raise RelayError(429, "RATE_LIMITED", "Pairing attempt limit exceeded", 60)
        if sess["completed"]:
            raise RelayError(409, "INVALID_EVENT", "Pairing session already completed")

        conn.execute(
            """
            INSERT INTO devices (device_id, device_name, role, identity_public_key, created_at, revoked_at)
            VALUES (?, ?, 'SECONDARY', ?, ?, NULL)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                identity_public_key=excluded.identity_public_key,
                revoked_at=NULL
            """,
            (req.secondary_device_id, req.secondary_device_name, req.secondary_identity_public_key, current),
        )

        relationship_id = "rel_" + uuid.uuid4().hex[:24]
        conn.execute(
            """
            INSERT INTO device_relationships (
                relationship_id, primary_device_id, secondary_device_id, key_epoch, status, created_at
            ) VALUES (?, ?, ?, 1, 'ACTIVE', ?)
            """,
            (relationship_id, sess["primary_device_id"], req.secondary_device_id, current),
        )
        conn.execute(
            "INSERT INTO sync_metadata (relationship_id, highest_accepted_sequence, expired_sequence_floor) VALUES (?, 0, 0)",
            (relationship_id,),
        )
        conn.execute(
            "UPDATE device_credentials SET relationship_id = ? WHERE device_id = ? AND relationship_id IS NULL AND revoked_at IS NULL",
            (relationship_id, sess["primary_device_id"]),
        )
        conn.execute(
            """
            INSERT INTO device_credentials (credential_id, device_id, relationship_id, token_hash_sha256, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), req.secondary_device_id, relationship_id, sec_token_hash, current + CREDENTIAL_TTL_MS, current),
        )
        conn.execute(
            """
            UPDATE pairing_sessions
            SET spake2_message_b = ?, key_confirmation_mac_b = ?, identity_signature_b = ?,
                secondary_device_id = ?, secondary_device_name = ?, secondary_identity_public_key = ?,
                relationship_id = ?, attempt_count = attempt_count + 1, completed = 1
            WHERE pairing_session_id = ?
            """,
            (
                req.spake2_message_b,
                req.key_confirmation_mac_b,
                req.identity_signature_b,
                req.secondary_device_id,
                req.secondary_device_name,
                req.secondary_identity_public_key,
                relationship_id,
                req.pairing_session_id,
            ),
        )

    return {
        "relationship_id": relationship_id,
        "primary_device_id": sess["primary_device_id"],
        "primary_device_name": sess["primary_device_name"],
        "primary_identity_public_key": sess["primary_identity_public_key"],
        "spake2_message_a": sess["spake2_message_a"],
        "secondary_token": sec_token,
        "key_epoch": 1,
    }


@app.get("/v1/pairing/session/{session_id}")
async def lookup_pairing_session(session_id: str, request: Request):
    caller = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "local")
    if not rate_limiter.allow(f"pair:{caller}"):
        raise RelayError(429, "RATE_LIMITED", "Too many pairing attempts", 60)

    current = now_ms()
    with db_tx() as conn:
        row = conn.execute(
            "SELECT pairing_session_id, primary_device_id, primary_device_name, spake2_message_a, completed, expires_at FROM pairing_sessions WHERE pairing_session_id = ?",
            (session_id,),
        ).fetchone()
        if not row:
            raise RelayError(404, "INVALID_EVENT", "Pairing session not found")
        if current > row["expires_at"]:
            raise RelayError(410, "EXPIRED_EVENT", "Pairing session expired")
        if row["completed"]:
            raise RelayError(409, "INVALID_EVENT", "Pairing session already completed")
        return {
            "pairing_session_id": row["pairing_session_id"],
            "primary_device_id": row["primary_device_id"],
            "primary_device_name": row["primary_device_name"],
            "spake2_message_a": row["spake2_message_a"],
            "expires_at": row["expires_at"],
        }


@app.get("/v1/pairing/status/{session_id}")
async def poll_pairing_status(session_id: str, request: Request):
    device = authenticate_headers(
        dict(request.headers), "GET", f"/v1/pairing/status/{session_id}", b""
    )
    with db_tx() as conn:
        row = conn.execute(
            "SELECT * FROM pairing_sessions WHERE pairing_session_id = ? AND primary_device_id = ?",
            (session_id, device["device_id"]),
        ).fetchone()
        if not row:
            raise RelayError(404, "INVALID_EVENT", "Pairing session not found")
        return {
            "pairing_session_id": session_id,
            "completed": bool(row["completed"]),
            "relationship_id": row["relationship_id"],
            "secondary_device_id": row["secondary_device_id"],
            "secondary_device_name": row["secondary_device_name"],
            "secondary_identity_public_key": row["secondary_identity_public_key"],
            "spake2_message_b": row["spake2_message_b"],
            "key_confirmation_mac_b": row["key_confirmation_mac_b"],
            "identity_signature_b": row["identity_signature_b"],
        }


@app.post("/v1/events")
async def submit_event(request: Request):
    raw = await request.body()
    device = authenticate_headers(dict(request.headers), "POST", "/v1/events", raw)
    if not rate_limiter.allow(f"dev:{device['device_id']}"):
        raise RelayError(429, "RATE_LIMITED", "Device rate limit exceeded", 15)

    env = EventEnvelope.model_validate_json(raw)
    if env.protocol_version != PROTOCOL_VERSION:
        raise RelayError(426, "UNSUPPORTED_PROTOCOL", "Unsupported protocol version")
    if len(env.ciphertext.encode("utf-8")) > MAX_ENCRYPTED_PAYLOAD_BYTES * 2:
        raise RelayError(413, "INVALID_PAYLOAD", "Ciphertext exceeds payload limit")

    current = now_ms()
    if current >= env.expires_at:
        raise RelayError(410, "EXPIRED_EVENT", "Event already expired")

    with db_tx() as conn:
        rel = conn.execute(
            "SELECT primary_device_id, secondary_device_id, status FROM device_relationships WHERE relationship_id = ?",
            (env.relationship_id,),
        ).fetchone()
        if not rel:
            raise RelayError(404, "INVALID_DESTINATION", "Relationship not found")
        if rel["status"] != "ACTIVE":
            raise RelayError(403, "REVOKED_PAIRING", "Relationship revoked")
        if rel["primary_device_id"] != device["device_id"]:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Only Primary may submit events")

        existing = conn.execute(
            "SELECT accepted_at, sequence_number FROM encrypted_events WHERE relationship_id = ? AND event_id = ?",
            (env.relationship_id, env.event_id),
        ).fetchone()
        if existing:
            return {
                "event_id": env.event_id,
                "relationship_id": env.relationship_id,
                "sequence_number": existing["sequence_number"],
                "accepted_at": existing["accepted_at"],
                "duplicate": True,
                "status": "SERVER_ACCEPTED",
            }

        conn.execute(
            """
            INSERT INTO encrypted_events (
                event_id, relationship_id, source_device_id, destination_device_id,
                sequence_number, protocol_version, key_epoch, payload_type,
                ciphertext, nonce, authentication_tag, ciphertext_hash,
                created_at, expires_at, accepted_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SERVER_ACCEPTED')
            """,
            (
                env.event_id,
                env.relationship_id,
                device["device_id"],
                rel["secondary_device_id"],
                env.sequence_number,
                env.protocol_version,
                env.key_epoch,
                env.payload_type,
                env.ciphertext,
                env.nonce,
                env.authentication_tag,
                env.ciphertext_hash,
                env.created_at,
                env.expires_at,
                current,
            ),
        )
        conn.execute(
            """
            UPDATE sync_metadata
            SET highest_accepted_sequence = MAX(highest_accepted_sequence, ?)
            WHERE relationship_id = ?
            """,
            (env.sequence_number, env.relationship_id),
        )

    await ws_hub.push_event_to_secondary(env.relationship_id, env.model_dump())

    return {
        "event_id": env.event_id,
        "relationship_id": env.relationship_id,
        "sequence_number": env.sequence_number,
        "accepted_at": current,
        "duplicate": False,
        "status": "SERVER_ACCEPTED",
    }


def _query_sync(device_id: str, relationship_id: str, after_sequence: int, limit: int) -> dict[str, Any]:
    bounded = max(1, min(limit, MAX_SYNC_BATCH_SIZE))
    current = now_ms()
    with db_tx() as conn:
        rel = conn.execute(
            "SELECT secondary_device_id, status FROM device_relationships WHERE relationship_id = ?",
            (relationship_id,),
        ).fetchone()
        if not rel:
            raise RelayError(404, "INVALID_DESTINATION", "Relationship not found")
        if rel["status"] != "ACTIVE":
            raise RelayError(403, "REVOKED_PAIRING", "Relationship revoked")
        if rel["secondary_device_id"] != device_id:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Only Secondary may sync events")

        rows = conn.execute(
            """
            SELECT event_id, relationship_id, sequence_number, protocol_version, key_epoch,
                   payload_type, ciphertext, nonce, authentication_tag, ciphertext_hash,
                   created_at, expires_at
            FROM encrypted_events
            WHERE relationship_id = ?
              AND sequence_number > ?
              AND status = 'SERVER_ACCEPTED'
              AND expires_at > ?
            ORDER BY sequence_number ASC
            LIMIT ?
            """,
            (relationship_id, after_sequence, current, bounded + 1),
        ).fetchall()

        has_more = len(rows) > bounded
        page_rows = rows[:bounded]
        events = [
            {
                "protocol_version": r["protocol_version"],
                "event_id": r["event_id"],
                "relationship_id": r["relationship_id"],
                "sequence_number": r["sequence_number"],
                "key_epoch": r["key_epoch"],
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "payload_type": r["payload_type"],
                "ciphertext": r["ciphertext"],
                "nonce": r["nonce"],
                "authentication_tag": r["authentication_tag"],
                "ciphertext_hash": r["ciphertext_hash"],
            }
            for r in page_rows
        ]
        next_cursor = events[-1]["sequence_number"] if events else after_sequence

        meta = conn.execute(
            "SELECT highest_accepted_sequence, expired_sequence_floor FROM sync_metadata WHERE relationship_id = ?",
            (relationship_id,),
        ).fetchone()
        conn.execute(
            "UPDATE sync_metadata SET last_sync_at = ? WHERE relationship_id = ?",
            (current, relationship_id),
        )

    return {
        "relationship_id": relationship_id,
        "events": events,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "highest_server_sequence": meta["highest_accepted_sequence"] if meta else 0,
        "expired_sequence_floor": meta["expired_sequence_floor"] if meta else 0,
        "server_time": current,
    }


@app.get("/v1/events/pending")
async def get_pending(
    request: Request,
    relationship_id: str | None = Query(default=None),
    cursor: int = Query(default=0),
    limit: int = Query(default=50),
):
    device = authenticate_headers(dict(request.headers), "GET", "/v1/events/pending", b"")
    rel_id = relationship_id or device["relationship_id"]
    if not rel_id:
        raise RelayError(400, "INVALID_EVENT", "Missing relationship_id")
    res = _query_sync(device["device_id"], rel_id, cursor, limit)
    return {
        "relationship_id": res["relationship_id"],
        "events": res["events"],
        "next_cursor": res["next_cursor"],
        "has_more": res["has_more"],
        "server_time": res["server_time"],
    }


@app.post("/v1/sync")
async def sync_events(request: Request):
    raw = await request.body()
    device = authenticate_headers(dict(request.headers), "POST", "/v1/sync", raw)
    req = SyncRequest.model_validate_json(raw)
    return _query_sync(device["device_id"], req.relationship_id, req.after_sequence, req.limit)


def _record_acks(device_id: str, relationship_id: str, acks: list[AckItem]) -> list[str]:
    if not acks:
        return []
    current = now_ms()
    acked_ids: list[str] = []
    with db_tx() as conn:
        rel = conn.execute(
            "SELECT secondary_device_id, status FROM device_relationships WHERE relationship_id = ?",
            (relationship_id,),
        ).fetchone()
        if not rel or rel["status"] != "ACTIVE":
            raise RelayError(403, "REVOKED_PAIRING", "Relationship invalid or revoked")
        if rel["secondary_device_id"] != device_id:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Only Secondary may acknowledge events")

        for ack in acks:
            row = conn.execute(
                "SELECT sequence_number FROM encrypted_events WHERE relationship_id = ? AND event_id = ?",
                (relationship_id, ack.event_id),
            ).fetchone()
            if not row or row["sequence_number"] != ack.sequence_number:
                continue

            cur = conn.execute(
                """
                UPDATE encrypted_events
                SET status = 'DEVICE_RECEIVED',
                    recipient_received_at = COALESCE(recipient_received_at, ?)
                WHERE relationship_id = ? AND event_id = ?
                """,
                (ack.received_at, relationship_id, ack.event_id),
            )
            if cur.rowcount == 1:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO delivery_receipts
                        (receipt_id, relationship_id, event_id, sequence_number, ack_mac, received_at, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), relationship_id, ack.event_id, ack.sequence_number, ack.ack_mac, ack.received_at, current),
                )
                acked_ids.append(ack.event_id)
    return acked_ids


@app.post("/v1/events/acknowledge")
async def acknowledge_events(request: Request):
    raw = await request.body()
    device = authenticate_headers(dict(request.headers), "POST", "/v1/events/acknowledge", raw)
    req = AcknowledgeEventsRequest.model_validate_json(raw)
    acked = _record_acks(device["device_id"], req.relationship_id, req.acknowledgements)
    for item in req.acknowledgements:
        if item.event_id in acked:
            await ws_hub.push_receipt_to_primary(req.relationship_id, item.model_dump())
    return {"acknowledged_event_ids": acked, "server_time": now_ms()}


@app.post("/v1/devices/revoke")
async def revoke_device(request: Request):
    raw = await request.body()
    device = authenticate_headers(dict(request.headers), "POST", "/v1/devices/revoke", raw)
    req = RevokeDeviceRequest.model_validate_json(raw)
    current = now_ms()
    with db_tx() as conn:
        rel = conn.execute(
            "SELECT primary_device_id, secondary_device_id, status FROM device_relationships WHERE relationship_id = ?",
            (req.relationship_id,),
        ).fetchone()
        if not rel or rel["status"] != "ACTIVE":
            raise RelayError(403, "REVOKED_PAIRING", "Relationship not active")
        if device["device_id"] not in (rel["primary_device_id"], rel["secondary_device_id"]):
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Caller not in relationship")

        conn.execute(
            "UPDATE device_relationships SET status = 'REVOKED', revoked_at = ? WHERE relationship_id = ?",
            (current, req.relationship_id),
        )
        conn.execute(
            "UPDATE device_credentials SET revoked_at = ? WHERE relationship_id = ?",
            (current, req.relationship_id),
        )
        conn.execute(
            """
            INSERT INTO device_revocations (revocation_id, relationship_id, revoked_device_id, initiated_by_device_id, reason, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), req.relationship_id, req.target_device_id, device["device_id"], req.reason[:250], current),
        )

    await ws_hub.close_relationship(req.relationship_id)
    return {"status": "REVOKED"}


@app.get("/v1/devices/status")
async def device_status(request: Request):
    device = authenticate_headers(dict(request.headers), "GET", "/v1/devices/status", b"")
    current = now_ms()
    rel_id = device["relationship_id"]
    with db_tx() as conn:
        pending = 0
        status = "UNBOUND"
        if rel_id:
            pending = conn.execute(
                "SELECT COUNT(*) FROM encrypted_events WHERE relationship_id = ? AND status = 'SERVER_ACCEPTED' AND expires_at > ?",
                (rel_id, current),
            ).fetchone()[0]
            row = conn.execute(
                "SELECT status FROM device_relationships WHERE relationship_id = ?",
                (rel_id,),
            ).fetchone()
            if row:
                status = row["status"]
    return {
        "device_id": device["device_id"],
        "relationship_id": rel_id,
        "status": status,
        "pending_count": pending,
        "server_time": current,
    }


@app.websocket("/v1/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        device = authenticate_headers(dict(websocket.headers), "GET", "/v1/ws", b"")
    except RelayError as err:
        await websocket.close(code=4401, reason=err.code)
        return

    rel_id = websocket.query_params.get("relationship_id") or device["relationship_id"]
    if not rel_id:
        await websocket.close(code=4403, reason="No relationship")
        return

    await websocket.accept()
    if not ws_hub.register(rel_id, device["device_id"], device["role"], websocket):
        await websocket.close(code=4429, reason="Too many concurrent WebSocket connections")
        return

    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                frame = json.loads(raw_text)
            except json.JSONDecodeError:
                continue

            frame_type = frame.get("type")
            if frame_type == "PING":
                await websocket.send_text(json.dumps({"type": "PONG", "relationship_id": rel_id, "timestamp": now_ms()}))
            elif frame_type == "ACK" and device["role"] == "SECONDARY":
                ack_dict = frame.get("ack")
                if ack_dict:
                    ack_obj = AckItem(**ack_dict)
                    acked = _record_acks(device["device_id"], rel_id, [ack_obj])
                    if acked:
                        await ws_hub.push_receipt_to_primary(rel_id, ack_dict)
    except WebSocketDisconnect:
        pass
    finally:
        ws_hub.unregister(rel_id, websocket)


# ---------------------------------------------------------------------------
# Auto-Discovery & Instant Tap-to-Pair Endpoints
# ---------------------------------------------------------------------------

def _resolve_inline_pubkey(headers: dict[str, str], device_id: str) -> str | None:
    h = {k.lower(): v for k, v in headers.items()}
    inline = h.get("x-identity-public-key", "").strip()
    if inline:
        return inline
    if device_id:
        with db_tx() as conn:
            row = conn.execute(
                "SELECT identity_public_key FROM discovered_devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row:
                return row["identity_public_key"]
            row2 = conn.execute(
                "SELECT identity_public_key FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row2:
                return row2["identity_public_key"]
    return None


@app.post("/v1/discovery/announce")
async def discovery_announce(request: Request):
    raw = await request.body()
    req = DiscoveryAnnounceRequest.model_validate_json(raw)
    if req.protocol_version != PROTOCOL_VERSION:
        raise RelayError(426, "UNSUPPORTED_PROTOCOL", "Unsupported protocol version")

    authenticate_headers(
        dict(request.headers), "POST", "/v1/discovery/announce", raw,
        require_token=False, inline_pubkey=req.identity_public_key,
    )

    current = now_ms()
    fp = fingerprint_from_pubkey(req.identity_public_key)
    with db_tx() as conn:
        conn.execute(
            """
            INSERT INTO discovered_devices (
                device_id, device_name, role, identity_public_key, fingerprint, online, last_seen_at, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                role=excluded.role,
                identity_public_key=excluded.identity_public_key,
                fingerprint=excluded.fingerprint,
                online=1,
                last_seen_at=excluded.last_seen_at
            """,
            (req.device_id, req.device_name[:48], req.role, req.identity_public_key, fp, current, current),
        )

    await discovery_hub.broadcast_devices_to_all()
    return {
        "status": "OK",
        "devices": discovery_hub.list_devices(exclude_device_id=req.device_id),
        "pending_requests": discovery_hub.list_pending_incoming(req.device_id),
        "server_time": current,
    }


@app.get("/v1/discovery/devices")
async def discovery_list_devices(request: Request):
    headers = dict(request.headers)
    h = {k.lower(): v for k, v in headers.items()}
    device_id = h.get("x-device-id", "").strip()
    pubkey = _resolve_inline_pubkey(headers, device_id)
    device = authenticate_headers(
        headers, "GET", "/v1/discovery/devices", b"",
        require_token=False, inline_pubkey=pubkey,
    )
    current = now_ms()
    with db_tx() as conn:
        conn.execute(
            "UPDATE discovered_devices SET online = 1, last_seen_at = ? WHERE device_id = ?",
            (current, device["device_id"]),
        )
    return {
        "devices": discovery_hub.list_devices(exclude_device_id=device["device_id"]),
        "pending_requests": discovery_hub.list_pending_incoming(device["device_id"]),
        "server_time": current,
    }


@app.post("/v1/discovery/pair/request")
async def discovery_pair_request(request: Request):
    raw = await request.body()
    req = DiscoveryPairRequestPayload.model_validate_json(raw)
    if req.protocol_version != PROTOCOL_VERSION:
        raise RelayError(426, "UNSUPPORTED_PROTOCOL", "Unsupported protocol version")

    authenticate_headers(
        dict(request.headers), "POST", "/v1/discovery/pair/request", raw,
        require_token=False, inline_pubkey=req.initiator_identity_public_key,
    )

    current = now_ms()
    expires_at = current + PAIRING_TTL_MS

    with db_tx() as conn:
        # Check for simultaneous reverse request -> auto-match cleanly
        reverse = conn.execute(
            """
            SELECT * FROM discovery_pair_requests
            WHERE initiator_device_id = ? AND target_device_id = ? AND status = 'PENDING' AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (req.target_device_id, req.initiator_device_id, current),
        ).fetchone()
        if reverse:
            return {
                "status": "AUTO_MATCHED",
                "request_id": reverse["request_id"],
                "assigned_primary_device_id": reverse["assigned_primary_device_id"],
                "assigned_secondary_device_id": reverse["assigned_secondary_device_id"],
                "expires_at": reverse["expires_at"],
                "matched_request": _format_incoming_pair_request(reverse),
            }

        target = conn.execute(
            "SELECT device_id, device_name, role FROM discovered_devices WHERE device_id = ?",
            (req.target_device_id,),
        ).fetchone()
        if not target:
            raise RelayError(404, "INVALID_DESTINATION", "Target device is not connected to discovery")

        # Mark any older pending request between same pair as expired
        conn.execute(
            """
            UPDATE discovery_pair_requests SET status = 'EXPIRED'
            WHERE initiator_device_id = ? AND target_device_id = ? AND status = 'PENDING'
            """,
            (req.initiator_device_id, req.target_device_id),
        )
        conn.execute(
            """
            INSERT INTO discovery_pair_requests (
                request_id, initiator_device_id, initiator_device_name, initiator_role,
                initiator_identity_public_key, target_device_id, target_device_name, target_role,
                assigned_primary_device_id, assigned_secondary_device_id,
                pairing_session_id, pairing_pin, spake2_message_a, spake2_message_b,
                status, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """,
            (
                req.request_id,
                req.initiator_device_id,
                req.initiator_device_name[:48],
                req.initiator_role,
                req.initiator_identity_public_key,
                req.target_device_id,
                target["device_name"],
                target["role"],
                req.assigned_primary_device_id,
                req.assigned_secondary_device_id,
                req.pairing_session_id,
                req.pairing_pin,
                req.spake2_message_a,
                req.spake2_message_b,
                expires_at,
                current,
            ),
        )
        created_row = conn.execute(
            "SELECT * FROM discovery_pair_requests WHERE request_id = ?",
            (req.request_id,),
        ).fetchone()

    if created_row:
        await discovery_hub.send_to_device(
            req.target_device_id,
            {
                "type": "PAIR_INCOMING",
                "request": _format_incoming_pair_request(created_row),
                "timestamp": current,
            },
        )

    return {
        "status": "PENDING",
        "request_id": req.request_id,
        "assigned_primary_device_id": req.assigned_primary_device_id,
        "assigned_secondary_device_id": req.assigned_secondary_device_id,
        "expires_at": expires_at,
        "matched_request": None,
    }


@app.post("/v1/discovery/pair/accept")
async def discovery_pair_accept(request: Request):
    raw = await request.body()
    req = DiscoveryPairAcceptPayload.model_validate_json(raw)
    if req.protocol_version != PROTOCOL_VERSION:
        raise RelayError(426, "UNSUPPORTED_PROTOCOL", "Unsupported protocol version")

    authenticate_headers(
        dict(request.headers), "POST", "/v1/discovery/pair/accept", raw,
        require_token=False, inline_pubkey=req.acceptor_identity_public_key,
    )

    current = now_ms()
    primary_token = secrets.token_urlsafe(32)
    secondary_token = secrets.token_urlsafe(32)
    primary_token_hash = sha256_hex(primary_token.encode("utf-8"))
    secondary_token_hash = sha256_hex(secondary_token.encode("utf-8"))
    relationship_id = "rel_" + uuid.uuid4().hex[:24]

    with db_tx() as conn:
        row = conn.execute(
            "SELECT * FROM discovery_pair_requests WHERE request_id = ?",
            (req.request_id,),
        ).fetchone()
        if not row:
            raise RelayError(404, "INVALID_EVENT", "Pairing request not found")
        if row["target_device_id"] != req.acceptor_device_id:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Only target device may accept")
        if current > row["expires_at"]:
            raise RelayError(410, "EXPIRED_EVENT", "Pairing request expired")
        if row["status"] != "PENDING":
            raise RelayError(409, "INVALID_EVENT", f"Pairing request already {row['status']}")

        assigned_primary = row["assigned_primary_device_id"]
        assigned_secondary = row["assigned_secondary_device_id"]
        initiator_is_primary = row["initiator_device_id"] == assigned_primary

        primary_name = row["initiator_device_name"] if initiator_is_primary else req.acceptor_device_name
        primary_pub = row["initiator_identity_public_key"] if initiator_is_primary else req.acceptor_identity_public_key
        secondary_name = req.acceptor_device_name if initiator_is_primary else row["initiator_device_name"]
        secondary_pub = req.acceptor_identity_public_key if initiator_is_primary else row["initiator_identity_public_key"]

        # Upsert both devices with their assigned roles
        conn.execute(
            """
            INSERT INTO devices (device_id, device_name, role, identity_public_key, created_at, revoked_at)
            VALUES (?, ?, 'PRIMARY', ?, ?, NULL)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                role='PRIMARY',
                identity_public_key=excluded.identity_public_key,
                revoked_at=NULL
            """,
            (assigned_primary, primary_name[:48], primary_pub, current),
        )
        conn.execute(
            """
            INSERT INTO devices (device_id, device_name, role, identity_public_key, created_at, revoked_at)
            VALUES (?, ?, 'SECONDARY', ?, ?, NULL)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                role='SECONDARY',
                identity_public_key=excluded.identity_public_key,
                revoked_at=NULL
            """,
            (assigned_secondary, secondary_name[:48], secondary_pub, current),
        )
        conn.execute(
            "UPDATE discovered_devices SET role = 'PRIMARY', device_name = ? WHERE device_id = ?",
            (primary_name[:48], assigned_primary),
        )
        conn.execute(
            "UPDATE discovered_devices SET role = 'SECONDARY', device_name = ? WHERE device_id = ?",
            (secondary_name[:48], assigned_secondary),
        )

        # Revoke any stale active relationships involving either device
        stale_rels = conn.execute(
            """
            SELECT relationship_id FROM device_relationships
            WHERE status = 'ACTIVE' AND (
                primary_device_id IN (?, ?) OR secondary_device_id IN (?, ?)
            )
            """,
            (assigned_primary, assigned_secondary, assigned_primary, assigned_secondary),
        ).fetchall()
        for sr in stale_rels:
            conn.execute(
                "UPDATE device_relationships SET status = 'REVOKED', revoked_at = ? WHERE relationship_id = ?",
                (current, sr["relationship_id"]),
            )
            conn.execute(
                "UPDATE device_credentials SET revoked_at = ? WHERE relationship_id = ?",
                (current, sr["relationship_id"]),
            )

        conn.execute(
            """
            INSERT INTO device_relationships (
                relationship_id, primary_device_id, secondary_device_id, key_epoch, status, created_at
            ) VALUES (?, ?, ?, 1, 'ACTIVE', ?)
            """,
            (relationship_id, assigned_primary, assigned_secondary, current),
        )
        conn.execute(
            "INSERT INTO sync_metadata (relationship_id, highest_accepted_sequence, expired_sequence_floor) VALUES (?, 0, 0)",
            (relationship_id,),
        )
        conn.execute(
            """
            INSERT INTO device_credentials (credential_id, device_id, relationship_id, token_hash_sha256, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), assigned_primary, relationship_id, primary_token_hash, current + CREDENTIAL_TTL_MS, current),
        )
        conn.execute(
            """
            INSERT INTO device_credentials (credential_id, device_id, relationship_id, token_hash_sha256, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), assigned_secondary, relationship_id, secondary_token_hash, current + CREDENTIAL_TTL_MS, current),
        )

        initiator_token = primary_token if initiator_is_primary else secondary_token
        acceptor_token = secondary_token if initiator_is_primary else primary_token
        final_msg_a = row["spake2_message_a"] or req.spake2_message_a
        final_msg_b = req.spake2_message_b or row["spake2_message_b"]

        conn.execute(
            """
            UPDATE discovery_pair_requests
            SET spake2_message_a = ?, spake2_message_b = ?,
                key_confirmation_mac_a = ?, key_confirmation_mac_b = ?,
                identity_signature_a = ?, identity_signature_b = ?,
                relationship_id = ?, initiator_token_once = ?, status = 'COMPLETED'
            WHERE request_id = ?
            """,
            (
                final_msg_a,
                final_msg_b,
                req.key_confirmation_mac_a,
                req.key_confirmation_mac_b,
                req.identity_signature_a,
                req.identity_signature_b,
                relationship_id,
                initiator_token,
                req.request_id,
            ),
        )

    initiator_assigned_role = "PRIMARY" if initiator_is_primary else "SECONDARY"
    acceptor_assigned_role = "SECONDARY" if initiator_is_primary else "PRIMARY"

    await discovery_hub.send_to_device(
        row["initiator_device_id"],
        {
            "type": "PAIR_COMPLETED",
            "request_id": req.request_id,
            "relationship_id": relationship_id,
            "assigned_role": initiator_assigned_role,
            "peer_device_id": req.acceptor_device_id,
            "peer_device_name": req.acceptor_device_name[:48],
            "peer_identity_public_key": req.acceptor_identity_public_key,
            "spake2_message_a": final_msg_a,
            "spake2_message_b": final_msg_b,
            "key_confirmation_mac_a": req.key_confirmation_mac_a,
            "key_confirmation_mac_b": req.key_confirmation_mac_b,
            "identity_signature_a": req.identity_signature_a,
            "identity_signature_b": req.identity_signature_b,
            "auth_token": initiator_token,
            "key_epoch": 1,
            "timestamp": current,
        },
    )
    await discovery_hub.broadcast_devices_to_all()

    return {
        "relationship_id": relationship_id,
        "assigned_role": acceptor_assigned_role,
        "peer_device_id": row["initiator_device_id"],
        "peer_device_name": row["initiator_device_name"],
        "peer_identity_public_key": row["initiator_identity_public_key"],
        "auth_token": acceptor_token,
        "key_epoch": 1,
    }


@app.post("/v1/discovery/pair/decline")
async def discovery_pair_decline(request: Request):
    raw = await request.body()
    req = DiscoveryPairDeclinePayload.model_validate_json(raw)
    pubkey = _resolve_inline_pubkey(dict(request.headers), req.device_id)
    device = authenticate_headers(
        dict(request.headers), "POST", "/v1/discovery/pair/decline", raw,
        require_token=False, inline_pubkey=pubkey,
    )

    current = now_ms()
    with db_tx() as conn:
        row = conn.execute(
            "SELECT * FROM discovery_pair_requests WHERE request_id = ?",
            (req.request_id,),
        ).fetchone()
        if not row:
            raise RelayError(404, "INVALID_EVENT", "Pairing request not found")
        if device["device_id"] not in (row["target_device_id"], row["initiator_device_id"]):
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Not a participant in pairing request")
        conn.execute(
            "UPDATE discovery_pair_requests SET status = 'DECLINED' WHERE request_id = ? AND status = 'PENDING'",
            (req.request_id,),
        )

    await discovery_hub.send_to_device(
        row["initiator_device_id"],
        {
            "type": "PAIR_DECLINED",
            "request_id": req.request_id,
            "target_device_id": row["target_device_id"],
            "target_device_name": row["target_device_name"],
            "timestamp": current,
        },
    )
    return {"status": "DECLINED"}


@app.get("/v1/discovery/pair/status/{request_id}")
async def discovery_pair_status(request_id: str, request: Request):
    headers = dict(request.headers)
    h = {k.lower(): v for k, v in headers.items()}
    device_id = h.get("x-device-id", "").strip()
    pubkey = _resolve_inline_pubkey(headers, device_id)
    device = authenticate_headers(
        headers, "GET", f"/v1/discovery/pair/status/{request_id}", b"",
        require_token=False, inline_pubkey=pubkey,
    )

    with db_tx() as conn:
        row = conn.execute(
            "SELECT * FROM discovery_pair_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if not row:
            raise RelayError(404, "INVALID_EVENT", "Pairing request not found")
        if row["initiator_device_id"] != device["device_id"]:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Only initiator may poll request status")

        initiator_is_primary = row["initiator_device_id"] == row["assigned_primary_device_id"]
        assigned_role = "PRIMARY" if initiator_is_primary else "SECONDARY"
        return {
            "request_id": request_id,
            "status": row["status"],
            "relationship_id": row["relationship_id"],
            "assigned_role": assigned_role,
            "peer_device_id": row["target_device_id"],
            "peer_device_name": row["target_device_name"],
            "peer_identity_public_key": _resolve_inline_pubkey({}, row["target_device_id"]),
            "spake2_message_a": row["spake2_message_a"],
            "spake2_message_b": row["spake2_message_b"],
            "key_confirmation_mac_a": row["key_confirmation_mac_a"],
            "key_confirmation_mac_b": row["key_confirmation_mac_b"],
            "identity_signature_a": row["identity_signature_a"],
            "identity_signature_b": row["identity_signature_b"],
            "auth_token": row["initiator_token_once"] if row["status"] == "COMPLETED" else None,
            "key_epoch": 1,
        }


@app.websocket("/v1/discovery/ws")
async def discovery_websocket_endpoint(websocket: WebSocket):
    headers = dict(websocket.headers)
    h = {k.lower(): v for k, v in headers.items()}
    device_id = h.get("x-device-id", "").strip()
    pubkey = _resolve_inline_pubkey(headers, device_id)
    try:
        device = authenticate_headers(
            headers, "GET", "/v1/discovery/ws", b"",
            require_token=False, inline_pubkey=pubkey,
        )
    except RelayError as err:
        await websocket.close(code=4401, reason=err.code)
        return

    if not pubkey:
        await websocket.close(code=4401, reason="Missing identity public key")
        return

    dev_id = device["device_id"]
    device_name = (websocket.query_params.get("device_name") or "PhoneBridge Device")[:48]
    role = websocket.query_params.get("role") or "PRIMARY"
    if role not in ("PRIMARY", "SECONDARY"):
        role = "PRIMARY"

    await websocket.accept()
    current = now_ms()
    fp = fingerprint_from_pubkey(pubkey)
    with db_tx() as conn:
        conn.execute(
            """
            INSERT INTO discovered_devices (
                device_id, device_name, role, identity_public_key, fingerprint, online, last_seen_at, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name=excluded.device_name,
                role=excluded.role,
                identity_public_key=excluded.identity_public_key,
                fingerprint=excluded.fingerprint,
                online=1,
                last_seen_at=excluded.last_seen_at
            """,
            (dev_id, device_name, role, pubkey, fp, current, current),
        )

    discovery_hub.register(dev_id, websocket)

    # Immediately push snapshot + any pending incoming pair requests to this device
    await discovery_hub.send_to_device(
        dev_id,
        {
            "type": "DISCOVERY_SNAPSHOT",
            "devices": discovery_hub.list_devices(exclude_device_id=dev_id),
            "pending_requests": discovery_hub.list_pending_incoming(dev_id),
            "timestamp": current,
        },
    )
    # Broadcast updated device list to all other connected peers immediately
    await discovery_hub.broadcast_devices_to_all()

    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                frame = json.loads(raw_text)
            except json.JSONDecodeError:
                continue

            frame_type = frame.get("type")
            now = now_ms()
            if frame_type == "PING":
                with db_tx() as conn:
                    conn.execute(
                        "UPDATE discovered_devices SET online = 1, last_seen_at = ? WHERE device_id = ?",
                        (now, dev_id),
                    )
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": now}))
            elif frame_type == "ANNOUNCE":
                new_name = str(frame.get("device_name") or device_name)[:48]
                new_role = str(frame.get("role") or role)
                if new_role not in ("PRIMARY", "SECONDARY"):
                    new_role = role
                device_name = new_name
                role = new_role
                with db_tx() as conn:
                    conn.execute(
                        "UPDATE discovered_devices SET device_name = ?, role = ?, online = 1, last_seen_at = ? WHERE device_id = ?",
                        (new_name, new_role, now, dev_id),
                    )
                await discovery_hub.broadcast_devices_to_all()
    except WebSocketDisconnect:
        pass
    finally:
        last_socket_closed = discovery_hub.unregister(dev_id, websocket)
        if last_socket_closed:
            with db_tx() as conn:
                conn.execute(
                    "UPDATE discovered_devices SET online = 0 WHERE device_id = ?",
                    (dev_id,),
                )
            await discovery_hub.broadcast_devices_to_all()
