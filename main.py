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
import hmac
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
from fastapi.responses import HTMLResponse, JSONResponse
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

            CREATE TABLE IF NOT EXISTS secondary_shared_events (
                event_id TEXT NOT NULL,
                relationship_id TEXT NOT NULL REFERENCES device_relationships(relationship_id),
                source_device_id TEXT NOT NULL,
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
                PRIMARY KEY (relationship_id, event_id),
                UNIQUE (relationship_id, sequence_number)
            );

            CREATE INDEX IF NOT EXISTS idx_secondary_shared_rel_seq
                ON secondary_shared_events(relationship_id, sequence_number);

            CREATE INDEX IF NOT EXISTS idx_secondary_shared_exp
                ON secondary_shared_events(expires_at);

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

            CREATE TABLE IF NOT EXISTS monitor_admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                passcode_salt TEXT NOT NULL,
                passcode_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                direction TEXT NOT NULL,
                method_or_type TEXT NOT NULL,
                device_id TEXT,
                device_name TEXT,
                device_role TEXT,
                relationship_id TEXT,
                event_id TEXT,
                sequence_number INTEGER,
                payload_type TEXT,
                status TEXT NOT NULL,
                summary TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_logs_ts
                ON traffic_logs(timestamp DESC, id DESC);
            """
        )
        monitor_cols = [
            ("monitor_title", "TEXT"),
            ("monitor_body", "TEXT"),
            ("monitor_source_package", "TEXT"),
            ("monitor_source_category", "TEXT"),
            ("monitor_captured_at", "INTEGER"),
            ("monitor_calendar_start_at", "INTEGER"),
            ("monitor_calendar_end_at", "INTEGER"),
            ("monitor_calendar_location", "TEXT"),
            ("monitor_priority", "INTEGER"),
        ]
        for table_name in ("encrypted_events", "secondary_shared_events"):
            existing_cols = {
                row[1]
                for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            }
            for col_name, col_type in monitor_cols:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
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


class MonitorPayload(BaseModel):
    title: str = ""
    body: str = ""
    source_package: str = ""
    source_category: str = "notification"
    captured_at_epoch_ms: int | None = None
    calendar_start_at_epoch_ms: int | None = None
    calendar_end_at_epoch_ms: int | None = None
    calendar_location: str | None = None
    priority: int = 0


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
    monitor_payload: MonitorPayload | None = None


class MonitorPasscodeRequest(BaseModel):
    passcode: str = Field(min_length=4, max_length=128)


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


MONITOR_SESSION_TTL_MS = 12 * 3_600_000
MONITOR_WS_TICKET_TTL_MS = 30_000
MAX_TRAFFIC_LOG_ROWS = 500


class MonitorAuthManager:
    def __init__(self):
        self.sessions: dict[str, int] = {}
        self.ws_tickets: dict[str, int] = {}

    @staticmethod
    def _env_passcode() -> str:
        return os.getenv("MONITOR_PASSCODE", "").strip()

    @staticmethod
    def _hash_passcode(passcode: str, salt_hex: str) -> str:
        derived = hashlib.scrypt(
            passcode.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=16384,
            r=8,
            p=1,
            dklen=32,
        )
        return derived.hex()

    def is_env_managed(self) -> bool:
        return bool(self._env_passcode())

    def is_configured(self) -> bool:
        if self.is_env_managed():
            return True
        with db_tx() as conn:
            row = conn.execute("SELECT id FROM monitor_admin WHERE id = 1").fetchone()
            return row is not None

    def setup_passcode(self, passcode: str) -> None:
        if self.is_env_managed():
            raise RelayError(409, "ALREADY_CONFIGURED", "Monitor passcode is configured by server environment")
        salt_hex = secrets.token_hex(16)
        pw_hash = self._hash_passcode(passcode, salt_hex)
        current = now_ms()
        with db_tx() as conn:
            existing = conn.execute("SELECT id FROM monitor_admin WHERE id = 1").fetchone()
            if existing:
                raise RelayError(409, "ALREADY_CONFIGURED", "Monitor passcode already configured")
            conn.execute(
                "INSERT INTO monitor_admin (id, passcode_salt, passcode_hash, created_at) VALUES (1, ?, ?, ?)",
                (salt_hex, pw_hash, current),
            )

    def verify_passcode(self, passcode: str) -> bool:
        env_code = self._env_passcode()
        if env_code:
            return hmac.compare_digest(passcode.encode("utf-8"), env_code.encode("utf-8"))
        with db_tx() as conn:
            row = conn.execute(
                "SELECT passcode_salt, passcode_hash FROM monitor_admin WHERE id = 1"
            ).fetchone()
        if not row:
            return False
        candidate = self._hash_passcode(passcode, row["passcode_salt"])
        return hmac.compare_digest(candidate, row["passcode_hash"])

    def _prune(self, current: int) -> None:
        self.sessions = {k: exp for k, exp in self.sessions.items() if exp > current}
        self.ws_tickets = {k: exp for k, exp in self.ws_tickets.items() if exp > current}

    def issue_session(self) -> tuple[str, int]:
        current = now_ms()
        self._prune(current)
        token = secrets.token_urlsafe(32)
        expires_at = current + MONITOR_SESSION_TTL_MS
        self.sessions[sha256_hex(token.encode("utf-8"))] = expires_at
        return token, expires_at

    def validate_request(self, request: Request) -> None:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise RelayError(401, "UNAUTHORIZED_MONITOR", "Missing monitor Bearer token")
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            raise RelayError(401, "UNAUTHORIZED_MONITOR", "Missing monitor Bearer token")
        current = now_ms()
        self._prune(current)
        token_hash = sha256_hex(token.encode("utf-8"))
        exp = self.sessions.get(token_hash)
        if not exp or current > exp:
            raise RelayError(401, "UNAUTHORIZED_MONITOR", "Monitor session expired or invalid")

    def revoke_request(self, request: Request) -> None:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth.removeprefix("Bearer ").strip()
            if token:
                self.sessions.pop(sha256_hex(token.encode("utf-8")), None)

    def issue_ws_ticket(self) -> str:
        current = now_ms()
        self._prune(current)
        ticket = secrets.token_urlsafe(24)
        self.ws_tickets[sha256_hex(ticket.encode("utf-8"))] = current + MONITOR_WS_TICKET_TTL_MS
        return ticket

    def consume_ws_ticket(self, ticket: str) -> bool:
        if not ticket:
            return False
        current = now_ms()
        self._prune(current)
        ticket_hash = sha256_hex(ticket.encode("utf-8"))
        exp = self.ws_tickets.pop(ticket_hash, None)
        return bool(exp and current <= exp)


class MonitorHub:
    def __init__(self):
        self.clients: list[WebSocket] = []

    def register(self, ws: WebSocket) -> None:
        self.clients.append(ws)

    def unregister(self, ws: WebSocket) -> None:
        self.clients = [c for c in self.clients if c is not ws]

    async def broadcast(self, payload: dict[str, Any]) -> None:
        if not self.clients:
            return
        frame = json.dumps(payload)
        for ws in list(self.clients):
            try:
                await ws.send_text(frame)
            except Exception:
                self.unregister(ws)


def record_traffic_event(
    *,
    direction: str,
    method_or_type: str,
    status: str,
    summary: str,
    device_id: str | None = None,
    device_name: str | None = None,
    device_role: str | None = None,
    relationship_id: str | None = None,
    event_id: str | None = None,
    sequence_number: int | None = None,
    payload_type: str | None = None,
    ts: int | None = None,
) -> dict[str, Any]:
    timestamp = ts or now_ms()
    resolved_name = device_name
    resolved_role = device_role
    with db_tx() as conn:
        if device_id and (not resolved_name or not resolved_role):
            row = conn.execute(
                "SELECT device_name, role FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                row = conn.execute(
                    "SELECT device_name, role FROM discovered_devices WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
            if row:
                resolved_name = resolved_name or row["device_name"]
                resolved_role = resolved_role or row["role"]

        cur = conn.execute(
            """
            INSERT INTO traffic_logs (
                timestamp, direction, method_or_type, device_id, device_name, device_role,
                relationship_id, event_id, sequence_number, payload_type, status, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                direction[:40],
                method_or_type[:48],
                device_id,
                (resolved_name or "")[:48] or None,
                resolved_role,
                relationship_id,
                event_id,
                sequence_number,
                payload_type,
                status[:32],
                summary[:240],
            ),
        )
        row_id = cur.lastrowid
        conn.execute(
            """
            DELETE FROM traffic_logs
            WHERE id <= (
                SELECT id FROM traffic_logs ORDER BY id DESC LIMIT 1 OFFSET ?
            )
            """,
            (MAX_TRAFFIC_LOG_ROWS,),
        )
    return {
        "id": row_id,
        "timestamp": timestamp,
        "direction": direction,
        "method_or_type": method_or_type,
        "device_id": device_id,
        "device_name": resolved_name,
        "device_role": resolved_role,
        "relationship_id": relationship_id,
        "event_id": event_id,
        "sequence_number": sequence_number,
        "payload_type": payload_type,
        "status": status,
        "summary": summary,
    }


rate_limiter = SlidingRateLimiter(RATE_LIMIT_PER_MIN)
ws_hub = WebSocketHub()
discovery_hub = DiscoveryHub()
monitor_auth = MonitorAuthManager()
monitor_hub = MonitorHub()


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
        conn.execute("DELETE FROM secondary_shared_events WHERE expires_at <= ?", (current,))
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
        secondary_shared = conn.execute("SELECT COUNT(*) FROM secondary_shared_events").fetchone()[0]
    return {
        "active_relationships": rels,
        "pending_encrypted_events": pending,
        "secondary_shared_events": secondary_shared,
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

    is_primary_sender = False
    mp = env.monitor_payload
    mp_title = mp.title[:256] if mp else None
    mp_body = mp.body[:4096] if mp else None
    mp_pkg = mp.source_package[:128] if mp else None
    mp_cat = mp.source_category[:64] if mp else None
    mp_cap = mp.captured_at_epoch_ms if mp else None
    mp_cal_start = mp.calendar_start_at_epoch_ms if mp else None
    mp_cal_end = mp.calendar_end_at_epoch_ms if mp else None
    mp_cal_loc = mp.calendar_location[:256] if (mp and mp.calendar_location) else None
    mp_priority = mp.priority if mp else None

    source_device_name: str | None = None
    destination_device_id: str | None = None
    destination_device_name: str | None = None

    with db_tx() as conn:
        rel = conn.execute(
            "SELECT primary_device_id, secondary_device_id, status FROM device_relationships WHERE relationship_id = ?",
            (env.relationship_id,),
        ).fetchone()
        if not rel:
            raise RelayError(404, "INVALID_DESTINATION", "Relationship not found")
        if rel["status"] != "ACTIVE":
            raise RelayError(403, "REVOKED_PAIRING", "Relationship revoked")

        src_row = conn.execute("SELECT device_name FROM devices WHERE device_id = ?", (device["device_id"],)).fetchone()
        source_device_name = src_row["device_name"] if src_row else device["device_id"]

        if rel["primary_device_id"] == device["device_id"]:
            is_primary_sender = True
            destination_device_id = rel["secondary_device_id"]
            dst_row = conn.execute("SELECT device_name FROM devices WHERE device_id = ?", (destination_device_id,)).fetchone()
            destination_device_name = dst_row["device_name"] if dst_row else destination_device_id
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
                    created_at, expires_at, accepted_at, status,
                    monitor_title, monitor_body, monitor_source_package, monitor_source_category,
                    monitor_captured_at, monitor_calendar_start_at, monitor_calendar_end_at,
                    monitor_calendar_location, monitor_priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SERVER_ACCEPTED', ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    mp_title,
                    mp_body,
                    mp_pkg,
                    mp_cat,
                    mp_cap,
                    mp_cal_start,
                    mp_cal_end,
                    mp_cal_loc,
                    mp_priority,
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
        elif rel["secondary_device_id"] == device["device_id"]:
            # Secondary data is archived strictly in the Python server and never forwarded to Primary.
            existing = conn.execute(
                "SELECT accepted_at, sequence_number FROM secondary_shared_events WHERE relationship_id = ? AND event_id = ?",
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
                INSERT INTO secondary_shared_events (
                    event_id, relationship_id, source_device_id, sequence_number,
                    protocol_version, key_epoch, payload_type,
                    ciphertext, nonce, authentication_tag, ciphertext_hash,
                    created_at, expires_at, accepted_at,
                    monitor_title, monitor_body, monitor_source_package, monitor_source_category,
                    monitor_captured_at, monitor_calendar_start_at, monitor_calendar_end_at,
                    monitor_calendar_location, monitor_priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    env.event_id,
                    env.relationship_id,
                    device["device_id"],
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
                    mp_title,
                    mp_body,
                    mp_pkg,
                    mp_cat,
                    mp_cap,
                    mp_cal_start,
                    mp_cal_end,
                    mp_cal_loc,
                    mp_priority,
                ),
            )
        else:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Device is not part of this relationship")

    if is_primary_sender:
        wire_envelope = env.model_dump(exclude={"monitor_payload"})
        await ws_hub.push_event_to_secondary(env.relationship_id, wire_envelope)

    traffic_log = record_traffic_event(
        direction="PRIMARY -> SECONDARY" if is_primary_sender else "SECONDARY -> PYTHON",
        method_or_type="POST /v1/events",
        status="SERVER_ACCEPTED",
        summary=f"seq={env.sequence_number} type={env.payload_type}" + (f" · {mp_title}" if mp_title else ""),
        device_id=device["device_id"],
        device_name=source_device_name,
        device_role="PRIMARY" if is_primary_sender else "SECONDARY",
        relationship_id=env.relationship_id,
        event_id=env.event_id,
        sequence_number=env.sequence_number,
        payload_type=env.payload_type,
        ts=current,
    )
    monitor_item = {
        "stream": "PRIMARY_TO_SECONDARY" if is_primary_sender else "SECONDARY_ARCHIVE",
        "event_id": env.event_id,
        "relationship_id": env.relationship_id,
        "source_device_id": device["device_id"],
        "source_device_name": source_device_name,
        "source_role": "PRIMARY" if is_primary_sender else "SECONDARY",
        "destination_device_id": destination_device_id,
        "destination_device_name": destination_device_name,
        "sequence_number": env.sequence_number,
        "payload_type": env.payload_type,
        "status": "SERVER_ACCEPTED" if is_primary_sender else "ARCHIVED_SERVER_ONLY",
        "created_at": env.created_at,
        "accepted_at": current,
        "recipient_received_at": None,
        "expires_at": env.expires_at,
        "ciphertext_hash": env.ciphertext_hash,
        "readable": mp is not None,
        "title": mp_title,
        "body": mp_body,
        "source_package": mp_pkg,
        "source_category": mp_cat,
        "captured_at": mp_cap,
        "calendar_start_at": mp_cal_start,
        "calendar_end_at": mp_cal_end,
        "calendar_location": mp_cal_loc,
        "priority": mp_priority,
    }
    await monitor_hub.broadcast({"type": "NOTIFICATION", "item": monitor_item, "timestamp": current})
    await monitor_hub.broadcast({"type": "TRAFFIC", "log": traffic_log, "timestamp": current})

    return {
        "event_id": env.event_id,
        "relationship_id": env.relationship_id,
        "sequence_number": env.sequence_number,
        "accepted_at": current,
        "duplicate": False,
        "status": "SERVER_ACCEPTED",
    }


@app.get("/v1/secondary/events")
async def list_secondary_shared_events(
    request: Request,
    relationship_id: str = Query(...),
    after_sequence: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=50),
):
    device = authenticate_headers(dict(request.headers), "GET", "/v1/secondary/events", b"")
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
        if rel["secondary_device_id"] != device["device_id"]:
            raise RelayError(403, "UNAUTHORIZED_DEVICE", "Primary cannot access Secondary server archive")

        rows = conn.execute(
            """
            SELECT event_id, relationship_id, source_device_id, sequence_number, protocol_version,
                   key_epoch, payload_type, ciphertext, nonce, authentication_tag, ciphertext_hash,
                   created_at, expires_at, accepted_at
            FROM secondary_shared_events
            WHERE relationship_id = ? AND sequence_number > ? AND expires_at > ?
            ORDER BY sequence_number ASC
            LIMIT ?
            """,
            (relationship_id, after_sequence, current, limit),
        ).fetchall()

    return {
        "relationship_id": relationship_id,
        "events": [dict(r) for r in rows],
        "server_time": current,
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
    res = _query_sync(device["device_id"], req.relationship_id, req.after_sequence, req.limit)
    if res["events"]:
        log = record_traffic_event(
            direction="RELAY -> SECONDARY",
            method_or_type="POST /v1/sync",
            status="DELIVERED_BATCH",
            summary=f"Synced {len(res['events'])} event(s) after seq={req.after_sequence}",
            device_id=device["device_id"],
            device_role=device["role"],
            relationship_id=req.relationship_id,
        )
        await monitor_hub.broadcast({"type": "TRAFFIC", "log": log, "timestamp": now_ms()})
    return res


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
            await monitor_hub.broadcast(
                {
                    "type": "RECEIPT",
                    "event_id": item.event_id,
                    "relationship_id": req.relationship_id,
                    "recipient_received_at": item.received_at,
                    "status": "DEVICE_RECEIVED",
                    "timestamp": now_ms(),
                }
            )
    if acked:
        log = record_traffic_event(
            direction="SECONDARY -> PRIMARY",
            method_or_type="POST /v1/events/acknowledge",
            status="DEVICE_RECEIVED",
            summary=f"Confirmed delivery for {len(acked)} event(s)",
            device_id=device["device_id"],
            device_role=device["role"],
            relationship_id=req.relationship_id,
        )
        await monitor_hub.broadcast({"type": "TRAFFIC", "log": log, "timestamp": now_ms()})
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
    log = record_traffic_event(
        direction="SYSTEM",
        method_or_type="POST /v1/devices/revoke",
        status="REVOKED",
        summary=f"Pairing revoked: {req.reason[:120]}",
        device_id=device["device_id"],
        device_role=device["role"],
        relationship_id=req.relationship_id,
        ts=current,
    )
    await monitor_hub.broadcast({"type": "TRAFFIC", "log": log, "timestamp": current})
    await monitor_hub.broadcast({"type": "DEVICE_UPDATE", "timestamp": current})
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

    connect_log = record_traffic_event(
        direction="WS CONNECT",
        method_or_type="WS /v1/ws",
        status="ONLINE",
        summary=f"{device['role']} connected to live relay stream",
        device_id=device["device_id"],
        device_role=device["role"],
        relationship_id=rel_id,
    )
    await monitor_hub.broadcast({"type": "TRAFFIC", "log": connect_log, "timestamp": now_ms()})
    await monitor_hub.broadcast({"type": "DEVICE_UPDATE", "timestamp": now_ms()})

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
                        await monitor_hub.broadcast(
                            {
                                "type": "RECEIPT",
                                "event_id": ack_obj.event_id,
                                "relationship_id": rel_id,
                                "recipient_received_at": ack_obj.received_at,
                                "status": "DEVICE_RECEIVED",
                                "timestamp": now_ms(),
                            }
                        )
                        ack_log = record_traffic_event(
                            direction="SECONDARY -> PRIMARY",
                            method_or_type="WS ACK",
                            status="DEVICE_RECEIVED",
                            summary=f"Confirmed delivery seq={ack_obj.sequence_number}",
                            device_id=device["device_id"],
                            device_role=device["role"],
                            relationship_id=rel_id,
                            event_id=ack_obj.event_id,
                            sequence_number=ack_obj.sequence_number,
                        )
                        await monitor_hub.broadcast({"type": "TRAFFIC", "log": ack_log, "timestamp": now_ms()})
    except WebSocketDisconnect:
        pass
    finally:
        ws_hub.unregister(rel_id, websocket)
        disconnect_log = record_traffic_event(
            direction="WS DISCONNECT",
            method_or_type="WS /v1/ws",
            status="OFFLINE",
            summary=f"{device['role']} disconnected from relay stream",
            device_id=device["device_id"],
            device_role=device["role"],
            relationship_id=rel_id,
        )
        await monitor_hub.broadcast({"type": "TRAFFIC", "log": disconnect_log, "timestamp": now_ms()})
        await monitor_hub.broadcast({"type": "DEVICE_UPDATE", "timestamp": now_ms()})


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
    pair_log = record_traffic_event(
        direction="PAIRING",
        method_or_type="POST /v1/discovery/pair/accept",
        status="ACTIVE",
        summary=f"Paired {primary_name[:24]} (PRIMARY) <-> {secondary_name[:24]} (SECONDARY)",
        device_id=req.acceptor_device_id,
        device_name=req.acceptor_device_name[:48],
        device_role=acceptor_assigned_role,
        relationship_id=relationship_id,
        ts=current,
    )
    await monitor_hub.broadcast({"type": "TRAFFIC", "log": pair_log, "timestamp": current})
    await monitor_hub.broadcast({"type": "DEVICE_UPDATE", "timestamp": current})

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
            await monitor_hub.broadcast({"type": "DEVICE_UPDATE", "timestamp": now_ms()})


# ---------------------------------------------------------------------------
# Remote Traffic & Notification Monitor API + HTML Frontend
# ---------------------------------------------------------------------------

def _query_monitor_overview() -> dict[str, Any]:
    current = now_ms()
    active_ws_device_ids = {
        dev_id
        for peers in ws_hub.rooms.values()
        for dev_id, _, _ in peers
    }
    with db_tx() as conn:
        rels = conn.execute(
            """
            SELECT r.relationship_id, r.primary_device_id, r.secondary_device_id,
                   r.key_epoch, r.status, r.created_at, r.revoked_at,
                   dp.device_name AS primary_name,
                   ds.device_name AS secondary_name
            FROM device_relationships r
            LEFT JOIN devices dp ON dp.device_id = r.primary_device_id
            LEFT JOIN devices ds ON ds.device_id = r.secondary_device_id
            ORDER BY (r.status = 'ACTIVE') DESC, r.created_at DESC
            LIMIT 20
            """
        ).fetchall()
        devs = conn.execute(
            """
            SELECT d.device_id, d.device_name, d.role, d.created_at, d.revoked_at,
                   dd.online AS disc_online, dd.last_seen_at, dd.fingerprint
            FROM devices d
            LEFT JOIN discovered_devices dd ON dd.device_id = d.device_id
            ORDER BY d.created_at DESC
            LIMIT 50
            """
        ).fetchall()
        counts = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM device_relationships WHERE status = 'ACTIVE') AS active_rels,
                (SELECT COUNT(*) FROM encrypted_events WHERE expires_at > ?) AS primary_total,
                (SELECT COUNT(*) FROM encrypted_events WHERE status = 'SERVER_ACCEPTED' AND expires_at > ?) AS primary_pending,
                (SELECT COUNT(*) FROM encrypted_events WHERE status = 'DEVICE_RECEIVED' AND expires_at > ?) AS primary_delivered,
                (SELECT COUNT(*) FROM secondary_shared_events WHERE expires_at > ?) AS secondary_archived
            """,
            (current, current, current, current),
        ).fetchone()

    return {
        "server_time": current,
        "active_ws_connections": ws_hub.active_count(),
        "metrics": dict(counts) if counts else {},
        "relationships": [
            {
                "relationship_id": r["relationship_id"],
                "primary_device_id": r["primary_device_id"],
                "primary_name": r["primary_name"] or r["primary_device_id"],
                "primary_online": r["primary_device_id"] in active_ws_device_ids or discovery_hub.is_online(r["primary_device_id"]),
                "secondary_device_id": r["secondary_device_id"],
                "secondary_name": r["secondary_name"] or r["secondary_device_id"],
                "secondary_online": r["secondary_device_id"] in active_ws_device_ids or discovery_hub.is_online(r["secondary_device_id"]),
                "key_epoch": r["key_epoch"],
                "status": r["status"],
                "created_at": r["created_at"],
                "revoked_at": r["revoked_at"],
            }
            for r in rels
        ],
        "devices": [
            {
                "device_id": d["device_id"],
                "device_name": d["device_name"],
                "role": d["role"],
                "online": d["device_id"] in active_ws_device_ids or discovery_hub.is_online(d["device_id"]),
                "last_seen_at": d["last_seen_at"],
                "fingerprint": d["fingerprint"] or "",
                "revoked": d["revoked_at"] is not None,
            }
            for d in devs
        ],
    }


def _row_to_monitor_item(row: sqlite3.Row, stream: str) -> dict[str, Any]:
    return {
        "stream": stream,
        "event_id": row["event_id"],
        "relationship_id": row["relationship_id"],
        "source_device_id": row["source_device_id"],
        "source_device_name": row["source_device_name"] or row["source_device_id"],
        "source_role": "PRIMARY" if stream == "PRIMARY_TO_SECONDARY" else "SECONDARY",
        "destination_device_id": row["destination_device_id"],
        "destination_device_name": row["destination_device_name"],
        "sequence_number": row["sequence_number"],
        "payload_type": row["payload_type"],
        "status": row["status"],
        "created_at": row["created_at"],
        "accepted_at": row["accepted_at"],
        "recipient_received_at": row["recipient_received_at"],
        "expires_at": row["expires_at"],
        "ciphertext_hash": row["ciphertext_hash"],
        "readable": bool(row["monitor_title"] is not None or row["monitor_body"] is not None),
        "title": row["monitor_title"],
        "body": row["monitor_body"],
        "source_package": row["monitor_source_package"],
        "source_category": row["monitor_source_category"],
        "captured_at": row["monitor_captured_at"],
        "calendar_start_at": row["monitor_calendar_start_at"],
        "calendar_end_at": row["monitor_calendar_end_at"],
        "calendar_location": row["monitor_calendar_location"],
        "priority": row["monitor_priority"],
    }


@app.get("/v1/monitor/auth/status")
async def monitor_auth_status():
    return {
        "configured": monitor_auth.is_configured(),
        "env_managed": monitor_auth.is_env_managed(),
        "server_time": now_ms(),
    }


@app.post("/v1/monitor/auth/setup")
async def monitor_auth_setup(req: MonitorPasscodeRequest, request: Request):
    caller = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "local")
    if not rate_limiter.allow(f"monitor_auth:{caller}"):
        raise RelayError(429, "RATE_LIMITED", "Too many monitor auth attempts", 60)
    monitor_auth.setup_passcode(req.passcode)
    token, expires_at = monitor_auth.issue_session()
    return {"token": token, "expires_at": expires_at}


@app.post("/v1/monitor/auth/login")
async def monitor_auth_login(req: MonitorPasscodeRequest, request: Request):
    caller = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "local")
    if not rate_limiter.allow(f"monitor_auth:{caller}"):
        raise RelayError(429, "RATE_LIMITED", "Too many monitor login attempts", 60)
    if not monitor_auth.is_configured():
        raise RelayError(409, "MONITOR_NOT_CONFIGURED", "Monitor passcode has not been set up yet")
    if not monitor_auth.verify_passcode(req.passcode):
        raise RelayError(401, "UNAUTHORIZED_MONITOR", "Incorrect monitor passcode")
    token, expires_at = monitor_auth.issue_session()
    return {"token": token, "expires_at": expires_at}


@app.post("/v1/monitor/auth/logout")
async def monitor_auth_logout(request: Request):
    monitor_auth.revoke_request(request)
    return {"status": "LOGGED_OUT"}


@app.post("/v1/monitor/ws-ticket")
async def monitor_ws_ticket(request: Request):
    monitor_auth.validate_request(request)
    return {"ticket": monitor_auth.issue_ws_ticket(), "expires_in_ms": MONITOR_WS_TICKET_TTL_MS}


@app.get("/v1/monitor/overview")
async def monitor_overview(request: Request):
    monitor_auth.validate_request(request)
    return _query_monitor_overview()


@app.get("/v1/monitor/feed")
async def monitor_feed(
    request: Request,
    source_role: Literal["ALL", "PRIMARY", "SECONDARY"] = Query(default="ALL"),
    payload_type: Literal["ALL", "NOTIFICATION", "CALENDAR_EVENT", "HEARTBEAT_TEST"] = Query(default="ALL"),
    q: str = Query(default="", max_length=120),
    limit: int = Query(default=100, ge=1, le=200),
):
    monitor_auth.validate_request(request)
    current = now_ms()
    items: list[dict[str, Any]] = []

    with db_tx() as conn:
        if source_role in ("ALL", "PRIMARY"):
            p_rows = conn.execute(
                """
                SELECT e.event_id, e.relationship_id, e.source_device_id, e.destination_device_id,
                       e.sequence_number, e.payload_type, e.status, e.created_at, e.accepted_at,
                       e.recipient_received_at, e.expires_at, e.ciphertext_hash,
                       e.monitor_title, e.monitor_body, e.monitor_source_package, e.monitor_source_category,
                       e.monitor_captured_at, e.monitor_calendar_start_at, e.monitor_calendar_end_at,
                       e.monitor_calendar_location, e.monitor_priority,
                       ds.device_name AS source_device_name,
                       dd.device_name AS destination_device_name
                FROM encrypted_events e
                LEFT JOIN devices ds ON ds.device_id = e.source_device_id
                LEFT JOIN devices dd ON dd.device_id = e.destination_device_id
                WHERE e.expires_at > ?
                ORDER BY e.accepted_at DESC
                LIMIT ?
                """,
                (current, limit),
            ).fetchall()
            items.extend(_row_to_monitor_item(r, "PRIMARY_TO_SECONDARY") for r in p_rows)

        if source_role in ("ALL", "SECONDARY"):
            s_rows = conn.execute(
                """
                SELECT s.event_id, s.relationship_id, s.source_device_id,
                       NULL AS destination_device_id,
                       s.sequence_number, s.payload_type, 'ARCHIVED_SERVER_ONLY' AS status,
                       s.created_at, s.accepted_at, NULL AS recipient_received_at, s.expires_at,
                       s.ciphertext_hash,
                       s.monitor_title, s.monitor_body, s.monitor_source_package, s.monitor_source_category,
                       s.monitor_captured_at, s.monitor_calendar_start_at, s.monitor_calendar_end_at,
                       s.monitor_calendar_location, s.monitor_priority,
                       ds.device_name AS source_device_name,
                       NULL AS destination_device_name
                FROM secondary_shared_events s
                LEFT JOIN devices ds ON ds.device_id = s.source_device_id
                WHERE s.expires_at > ?
                ORDER BY s.accepted_at DESC
                LIMIT ?
                """,
                (current, limit),
            ).fetchall()
            items.extend(_row_to_monitor_item(r, "SECONDARY_ARCHIVE") for r in s_rows)

    if payload_type != "ALL":
        items = [it for it in items if it["payload_type"] == payload_type]

    search = q.strip().lower()
    if search:
        items = [
            it
            for it in items
            if search in (it["title"] or "").lower()
            or search in (it["body"] or "").lower()
            or search in (it["source_package"] or "").lower()
            or search in (it["source_device_name"] or "").lower()
            or search in (it["destination_device_name"] or "").lower()
        ]

    items.sort(key=lambda it: it["accepted_at"], reverse=True)
    return {"items": items[:limit], "server_time": current}


@app.get("/v1/monitor/traffic")
async def monitor_traffic(request: Request, limit: int = Query(default=120, ge=1, le=250)):
    monitor_auth.validate_request(request)
    with db_tx() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, direction, method_or_type, device_id, device_name, device_role,
                   relationship_id, event_id, sequence_number, payload_type, status, summary
            FROM traffic_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"logs": [dict(r) for r in rows], "server_time": now_ms()}


@app.websocket("/v1/monitor/ws")
async def monitor_websocket(websocket: WebSocket):
    ticket = websocket.query_params.get("ticket", "")
    if not monitor_auth.consume_ws_ticket(ticket):
        await websocket.close(code=4401, reason="Invalid or expired monitor WS ticket")
        return
    await websocket.accept()
    monitor_hub.register(websocket)
    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                frame = json.loads(raw_text)
            except json.JSONDecodeError:
                continue
            if frame.get("type") == "PING":
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": now_ms()}))
    except WebSocketDisconnect:
        pass
    finally:
        monitor_hub.unregister(websocket)


MONITOR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Relay Traffic & Notification Monitor</title>
<style>
  :root {
    --bg: #f4f6f9;
    --surface: #ffffff;
    --surface-2: #f8fafc;
    --border: #e2e8f0;
    --text: #0f172a;
    --muted: #64748b;
    --accent: #2563eb;
    --accent-soft: #dbeafe;
    --green: #16a34a;
    --green-soft: #dcfce7;
    --amber: #d97706;
    --amber-soft: #fef3c7;
    --purple: #7c3aed;
    --purple-soft: #ede9fe;
    --red: #dc2626;
    --red-soft: #fee2e2;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b1120;
      --surface: #111827;
      --surface-2: #1e293b;
      --border: #1f2937;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --accent: #3b82f6;
      --accent-soft: rgba(59, 130, 246, 0.16);
      --green: #22c55e;
      --green-soft: rgba(34, 197, 94, 0.16);
      --amber: #f59e0b;
      --amber-soft: rgba(245, 158, 11, 0.16);
      --purple: #a78bfa;
      --purple-soft: rgba(167, 139, 250, 0.16);
      --red: #f87171;
      --red-soft: rgba(248, 113, 113, 0.16);
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    line-height: 1.45;
  }
  .hidden { display: none !important; }
  .auth-wrap {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
  }
  .auth-card {
    width: 100%;
    max-width: 420px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
  }
  .auth-card h1 {
    margin: 0 0 8px;
    font-size: 20px;
    font-weight: 700;
  }
  .auth-card p {
    margin: 0 0 20px;
    color: var(--muted);
    font-size: 14px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 16px;
  }
  .field label {
    font-size: 13px;
    font-weight: 600;
  }
  input[type="password"], input[type="search"], input[type="text"] {
    width: 100%;
    padding: 11px 13px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--surface-2);
    color: var(--text);
    font-size: 14px;
    outline: none;
  }
  input:focus { border-color: var(--accent); }
  button {
    cursor: pointer;
    border: 1px solid transparent;
    border-radius: 10px;
    font-family: inherit;
    font-weight: 600;
    font-size: 13px;
    padding: 9px 14px;
    transition: opacity 0.15s ease, background 0.15s ease;
  }
  button.primary {
    background: var(--accent);
    color: #fff;
    width: 100%;
    padding: 11px 16px;
    font-size: 14px;
  }
  button.ghost {
    background: var(--surface-2);
    color: var(--text);
    border-color: var(--border);
  }
  button:hover { opacity: 0.92; }
  .error-banner {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 10px;
    background: var(--red-soft);
    color: var(--red);
    font-size: 13px;
  }
  .topbar {
    position: sticky;
    top: 0;
    z-index: 10;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 16px;
  }
  .live-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--surface-2);
    border: 1px solid var(--border);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--muted);
  }
  .dot.online { background: var(--green); }
  .dot.warn { background: var(--amber); }
  .actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .container {
    max-width: 1360px;
    margin: 0 auto;
    padding: 18px 20px 36px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px 16px;
  }
  .stat-label {
    font-size: 12px;
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .stat-val {
    font-size: 24px;
    font-weight: 700;
    margin-top: 4px;
    font-family: var(--mono);
  }
  .devices-strip {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }
  .rel-chip {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 999px;
    letter-spacing: 0.02em;
  }
  .badge.primary { background: var(--accent-soft); color: var(--accent); }
  .badge.secondary { background: var(--purple-soft); color: var(--purple); }
  .badge.delivered { background: var(--green-soft); color: var(--green); }
  .badge.pending { background: var(--amber-soft); color: var(--amber); }
  .badge.muted { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .tab {
    background: var(--surface);
    color: var(--muted);
    border: 1px solid var(--border);
    padding: 7px 12px;
    border-radius: 999px;
    font-size: 12px;
  }
  .tab.active {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
  }
  .search-box {
    min-width: 240px;
    flex: 1;
    max-width: 360px;
  }
  .workspace {
    display: grid;
    grid-template-columns: 1.45fr 1fr;
    gap: 16px;
    align-items: start;
  }
  @media (max-width: 980px) {
    .workspace { grid-template-columns: 1fr; }
  }
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
  }
  .panel-header {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: 700;
    font-size: 14px;
  }
  .panel-sub {
    font-size: 12px;
    color: var(--muted);
    font-weight: 500;
  }
  .feed-list {
    display: flex;
    flex-direction: column;
    max-height: 74vh;
    overflow-y: auto;
  }
  .notif-card {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .notif-card:last-child { border-bottom: none; }
  .notif-top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .notif-meta-left, .notif-meta-right {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .notif-title {
    font-size: 15px;
    font-weight: 700;
    word-break: break-word;
  }
  .notif-body {
    font-size: 14px;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
  }
  .notif-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 12px;
    color: var(--muted);
  }
  .mono { font-family: var(--mono); font-size: 11.5px; }
  .traffic-list {
    max-height: 74vh;
    overflow-y: auto;
  }
  .traffic-row {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12.5px;
  }
  .traffic-row:last-child { border-bottom: none; }
  .traffic-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .empty {
    padding: 40px 20px;
    text-align: center;
    color: var(--muted);
    font-size: 14px;
  }
</style>
</head>
<body>
  <section id="authView" class="auth-wrap">
    <div class="auth-card">
      <h1 id="authHeading">Relay Traffic Monitor</h1>
      <p id="authSubtitle">Checking monitor passcode configuration...</p>
      <form id="authForm">
        <div class="field">
          <label for="passcodeInput" id="passcodeLabel">Monitor Passcode</label>
          <input id="passcodeInput" type="password" minlength="4" maxlength="128" autocomplete="current-password" required placeholder="Enter passcode (min 4 chars)" />
        </div>
        <button type="submit" class="primary" id="authSubmitBtn">Unlock Monitor</button>
      </form>
      <div id="authError" class="error-banner hidden"></div>
    </div>
  </section>

  <section id="appView" class="hidden">
    <header class="topbar">
      <div class="brand">
        <span>Relay Traffic &amp; Notification Monitor</span>
        <span class="live-pill">
          <span id="wsDot" class="dot"></span>
          <span id="wsLabel">Connecting</span>
        </span>
      </div>
      <div class="actions">
        <button id="refreshBtn" class="ghost" type="button">Refresh</button>
        <button id="logoutBtn" class="ghost" type="button">Lock</button>
      </div>
    </header>

    <main class="container">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Active Pairs</div>
          <div class="stat-val" id="statRels">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Primary &rarr; Secondary</div>
          <div class="stat-val" id="statPrimaryTotal">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Delivered (ACKed)</div>
          <div class="stat-val" id="statDelivered">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Secondary &rarr; Python</div>
          <div class="stat-val" id="statSecondaryArchived">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Device Sockets</div>
          <div class="stat-val" id="statSockets">0</div>
        </div>
      </div>

      <div id="devicesStrip" class="devices-strip"></div>

      <div class="toolbar">
        <div class="tabs" id="filterTabs">
          <button type="button" class="tab active" data-filter="ALL">All Streams</button>
          <button type="button" class="tab" data-filter="PRIMARY">Primary &rarr; Secondary</button>
          <button type="button" class="tab" data-filter="SECONDARY">Secondary &rarr; Python</button>
          <button type="button" class="tab" data-type="CALENDAR_EVENT">Calendar</button>
        </div>
        <div class="search-box">
          <input id="searchInput" type="search" placeholder="Search title, body, app package, device..." />
        </div>
      </div>

      <div class="workspace">
        <section class="panel">
          <div class="panel-header">
            <span>Notifications Feed</span>
            <span class="panel-sub" id="feedCountLabel">0 messages</span>
          </div>
          <div id="feedList" class="feed-list">
            <div class="empty">No notifications captured yet.</div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <span>Live Wire Traffic</span>
            <span class="panel-sub" id="trafficCountLabel">0 frames</span>
          </div>
          <div id="trafficList" class="traffic-list">
            <div class="empty">Waiting for device traffic...</div>
          </div>
        </section>
      </div>
    </main>
  </section>

<script>
(() => {
  const state = {
    token: null,
    configured: false,
    roleFilter: 'ALL',
    typeFilter: 'ALL',
    search: '',
    items: [],
    logs: [],
    overview: null,
    ws: null,
    reconnectTimer: null,
    pingTimer: null,
  };

  const authView = document.getElementById('authView');
  const appView = document.getElementById('appView');
  const authHeading = document.getElementById('authHeading');
  const authSubtitle = document.getElementById('authSubtitle');
  const passcodeLabel = document.getElementById('passcodeLabel');
  const passcodeInput = document.getElementById('passcodeInput');
  const authSubmitBtn = document.getElementById('authSubmitBtn');
  const authError = document.getElementById('authError');
  const authForm = document.getElementById('authForm');

  const wsDot = document.getElementById('wsDot');
  const wsLabel = document.getElementById('wsLabel');
  const refreshBtn = document.getElementById('refreshBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const searchInput = document.getElementById('searchInput');
  const filterTabs = document.getElementById('filterTabs');

  const statRels = document.getElementById('statRels');
  const statPrimaryTotal = document.getElementById('statPrimaryTotal');
  const statDelivered = document.getElementById('statDelivered');
  const statSecondaryArchived = document.getElementById('statSecondaryArchived');
  const statSockets = document.getElementById('statSockets');
  const devicesStrip = document.getElementById('devicesStrip');
  const feedList = document.getElementById('feedList');
  const feedCountLabel = document.getElementById('feedCountLabel');
  const trafficList = document.getElementById('trafficList');
  const trafficCountLabel = document.getElementById('trafficCountLabel');

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function fmtTime(ms) {
    if (!ms) return '-';
    return new Date(ms).toLocaleString();
  }

  function fmtClock(ms) {
    if (!ms) return '-';
    return new Date(ms).toLocaleTimeString();
  }

  function showAuthError(msg) {
    if (!msg) {
      authError.classList.add('hidden');
      authError.textContent = '';
      return;
    }
    authError.textContent = msg;
    authError.classList.remove('hidden');
  }

  async function apiFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (state.token) {
      headers['Authorization'] = 'Bearer ' + state.token;
    }
    const resp = await fetch(url, Object.assign({}, options, { headers }));
    if (resp.status === 401 && state.token) {
      lockSession('Session expired. Enter passcode to unlock.');
      throw new Error('Unauthorized');
    }
    return resp;
  }

  async function initAuthStatus() {
    showAuthError('');
    try {
      const resp = await fetch('/v1/monitor/auth/status');
      const data = await resp.json();
      state.configured = Boolean(data.configured);
      if (state.configured) {
        authHeading.textContent = 'Unlock Relay Monitor';
        authSubtitle.textContent = 'Enter your server monitor passcode to read live device notifications and relay traffic.';
        passcodeLabel.textContent = 'Monitor Passcode';
        authSubmitBtn.textContent = 'Unlock Monitor';
      } else {
        authHeading.textContent = 'Set Up Monitor Passcode';
        authSubtitle.textContent = 'First-time setup: create a passcode to protect remote access to your synced notifications.';
        passcodeLabel.textContent = 'Create Passcode';
        authSubmitBtn.textContent = 'Save Passcode & Open Monitor';
      }
    } catch (err) {
      showAuthError('Failed to reach relay server.');
    }
  }

  authForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showAuthError('');
    const passcode = passcodeInput.value;
    if (!passcode || passcode.length < 4) {
      showAuthError('Passcode must be at least 4 characters.');
      return;
    }
    const endpoint = state.configured ? '/v1/monitor/auth/login' : '/v1/monitor/auth/setup';
    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passcode }),
      });
      const body = await resp.json();
      if (!resp.ok) {
        if (resp.status === 409) {
          await initAuthStatus();
        }
        showAuthError(body.message || 'Authentication failed.');
        return;
      }
      state.token = body.token;
      state.configured = true;
      passcodeInput.value = '';
      authView.classList.add('hidden');
      appView.classList.remove('hidden');
      await refreshAll();
      connectWs();
    } catch (err) {
      showAuthError('Network error communicating with relay.');
    }
  });

  function lockSession(msg) {
    state.token = null;
    if (state.ws) {
      try { state.ws.close(); } catch (_) {}
      state.ws = null;
    }
    if (state.reconnectTimer) {
      clearTimeout(state.reconnectTimer);
      state.reconnectTimer = null;
    }
    if (state.pingTimer) {
      clearInterval(state.pingTimer);
      state.pingTimer = null;
    }
    appView.classList.add('hidden');
    authView.classList.remove('hidden');
    initAuthStatus().then(() => {
      if (msg) showAuthError(msg);
    });
  }

  logoutBtn.addEventListener('click', async () => {
    try {
      await apiFetch('/v1/monitor/auth/logout', { method: 'POST' });
    } catch (_) {}
    lockSession('');
  });

  refreshBtn.addEventListener('click', () => {
    refreshAll();
  });

  filterTabs.addEventListener('click', (ev) => {
    const btn = ev.target.closest('button.tab');
    if (!btn) return;
    for (const b of filterTabs.querySelectorAll('button.tab')) b.classList.remove('active');
    btn.classList.add('active');
    if (btn.dataset.filter) {
      state.roleFilter = btn.dataset.filter;
      state.typeFilter = 'ALL';
    } else if (btn.dataset.type) {
      state.roleFilter = 'ALL';
      state.typeFilter = btn.dataset.type;
    }
    loadFeed();
  });

  let searchTimer = null;
  searchInput.addEventListener('input', () => {
    state.search = searchInput.value;
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadFeed(), 180);
  });

  async function refreshAll() {
    await Promise.all([loadOverview(), loadFeed(), loadTraffic()]);
  }

  async function loadOverview() {
    const resp = await apiFetch('/v1/monitor/overview');
    if (!resp.ok) return;
    state.overview = await resp.json();
    renderOverview();
  }

  async function loadFeed() {
    const params = new URLSearchParams({
      source_role: state.roleFilter,
      payload_type: state.typeFilter,
      q: state.search,
      limit: '150',
    });
    const resp = await apiFetch('/v1/monitor/feed?' + params.toString());
    if (!resp.ok) return;
    const data = await resp.json();
    state.items = data.items || [];
    renderFeed();
  }

  async function loadTraffic() {
    const resp = await apiFetch('/v1/monitor/traffic?limit=150');
    if (!resp.ok) return;
    const data = await resp.json();
    state.logs = data.logs || [];
    renderTraffic();
  }

  function renderOverview() {
    const ov = state.overview;
    if (!ov) return;
    const m = ov.metrics || {};
    statRels.textContent = m.active_rels ?? 0;
    statPrimaryTotal.textContent = m.primary_total ?? 0;
    statDelivered.textContent = m.primary_delivered ?? 0;
    statSecondaryArchived.textContent = m.secondary_archived ?? 0;
    statSockets.textContent = ov.active_ws_connections ?? 0;

    devicesStrip.replaceChildren();
    const rels = ov.relationships || [];
    if (rels.length === 0) {
      const chip = el('div', 'rel-chip', 'No paired relationships recorded yet.');
      devicesStrip.appendChild(chip);
      return;
    }
    for (const r of rels) {
      const chip = el('div', 'rel-chip');
      const pDot = el('span', 'dot ' + (r.primary_online ? 'online' : ''));
      const pName = el('strong', '', r.primary_name + ' (PRIMARY)');
      const arrow = el('span', 'mono', '⇄');
      const sDot = el('span', 'dot ' + (r.secondary_online ? 'online' : ''));
      const sName = el('strong', '', r.secondary_name + ' (SECONDARY)');
      const st = el('span', 'badge ' + (r.status === 'ACTIVE' ? 'delivered' : 'muted'), r.status);
      chip.append(pDot, pName, arrow, sDot, sName, st);
      devicesStrip.appendChild(chip);
    }
  }

  function renderFeed() {
    feedList.replaceChildren();
    feedCountLabel.textContent = state.items.length + ' message' + (state.items.length === 1 ? '' : 's');
    if (state.items.length === 0) {
      feedList.appendChild(el('div', 'empty', 'No matching notifications found.'));
      return;
    }
    for (const item of state.items) {
      const card = el('article', 'notif-card');

      const top = el('div', 'notif-top');
      const left = el('div', 'notif-meta-left');
      const right = el('div', 'notif-meta-right');

      const isPrimary = item.stream === 'PRIMARY_TO_SECONDARY';
      left.appendChild(
        el(
          'span',
          'badge ' + (isPrimary ? 'primary' : 'secondary'),
          isPrimary ? 'PRIMARY -> SECONDARY' : 'SECONDARY -> PYTHON'
        )
      );
      left.appendChild(
        el('span', 'badge muted', (item.source_device_name || 'Device') + ' · #' + item.sequence_number)
      );
      if (item.payload_type && item.payload_type !== 'NOTIFICATION') {
        left.appendChild(el('span', 'badge muted', item.payload_type));
      }

      if (item.status === 'DEVICE_RECEIVED') {
        right.appendChild(el('span', 'badge delivered', 'DELIVERED'));
      } else if (item.status === 'ARCHIVED_SERVER_ONLY') {
        right.appendChild(el('span', 'badge secondary', 'SERVER ONLY'));
      } else {
        right.appendChild(el('span', 'badge pending', 'ON RELAY'));
      }

      top.append(left, right);
      card.appendChild(top);

      if (item.readable) {
        const titleNode = el('div', 'notif-title', item.title || '(No title)');
        card.appendChild(titleNode);
        if (item.body) {
          card.appendChild(el('div', 'notif-body', item.body));
        }
        if (item.calendar_location) {
          card.appendChild(el('div', 'panel-sub', 'Location: ' + item.calendar_location));
        }
      } else {
        card.appendChild(el('div', 'notif-title', 'Encrypted E2EE Notification Envelope'));
        card.appendChild(
          el(
            'div',
            'notif-body mono',
            'Sent by an older client build without monitor preview. Ciphertext SHA-256: ' + (item.ciphertext_hash || '').slice(0, 24) + '...'
          )
        );
      }

      const foot = el('div', 'notif-foot');
      const pkgText = item.source_package ? item.source_package : (item.source_category || 'notification');
      foot.appendChild(el('span', 'mono', pkgText));

      const rightFoot = el('div', 'notif-meta-right');
      rightFoot.appendChild(el('span', '', fmtTime(item.captured_at || item.accepted_at)));
      if (item.readable && (item.title || item.body) && navigator.clipboard) {
        const copyBtn = el('button', 'ghost', 'Copy');
        copyBtn.type = 'button';
        copyBtn.style.padding = '3px 8px';
        copyBtn.style.fontSize = '11px';
        copyBtn.addEventListener('click', async () => {
          const textToCopy = [item.title, item.body].filter(Boolean).join('\n');
          try {
            await navigator.clipboard.writeText(textToCopy);
            copyBtn.textContent = 'Copied';
            setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
          } catch (_) {}
        });
        rightFoot.appendChild(copyBtn);
      }
      foot.appendChild(rightFoot);
      card.appendChild(foot);

      feedList.appendChild(card);
    }
  }

  function renderTraffic() {
    trafficList.replaceChildren();
    trafficCountLabel.textContent = state.logs.length + ' frame' + (state.logs.length === 1 ? '' : 's');
    if (state.logs.length === 0) {
      trafficList.appendChild(el('div', 'empty', 'No relay traffic recorded yet.'));
      return;
    }
    for (const log of state.logs) {
      const row = el('div', 'traffic-row');
      const top = el('div', 'traffic-top');
      const dirBadge = el('span', 'badge ' + (log.direction.includes('SECONDARY -> PYTHON') ? 'secondary' : 'primary'), log.direction);
      const timeSpan = el('span', 'mono panel-sub', fmtClock(log.timestamp));
      top.append(dirBadge, timeSpan);
      row.appendChild(top);

      const meta = el('div', 'mono', (log.method_or_type || '') + ' · ' + (log.device_name || log.device_id || 'server') + ' · ' + (log.status || ''));
      row.appendChild(meta);
      if (log.summary) {
        row.appendChild(el('div', 'panel-sub', log.summary));
      }
      trafficList.appendChild(row);
    }
  }

  function matchesFilters(item) {
    if (state.roleFilter === 'PRIMARY' && item.stream !== 'PRIMARY_TO_SECONDARY') return false;
    if (state.roleFilter === 'SECONDARY' && item.stream !== 'SECONDARY_ARCHIVE') return false;
    if (state.typeFilter !== 'ALL' && item.payload_type !== state.typeFilter) return false;
    const q = state.search.trim().toLowerCase();
    if (!q) return true;
    return (
      (item.title || '').toLowerCase().includes(q) ||
      (item.body || '').toLowerCase().includes(q) ||
      (item.source_package || '').toLowerCase().includes(q) ||
      (item.source_device_name || '').toLowerCase().includes(q)
    );
  }

  async function connectWs() {
    if (!state.token) return;
    if (state.ws) {
      try { state.ws.close(); } catch (_) {}
      state.ws = null;
    }
    try {
      const resp = await apiFetch('/v1/monitor/ws-ticket', { method: 'POST' });
      if (!resp.ok) throw new Error('ticket failed');
      const { ticket } = await resp.json();
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = proto + '//' + window.location.host + '/v1/monitor/ws?ticket=' + encodeURIComponent(ticket);
      const ws = new WebSocket(wsUrl);
      state.ws = ws;

      ws.onopen = () => {
        wsDot.className = 'dot online';
        wsLabel.textContent = 'Live Stream';
        if (state.pingTimer) clearInterval(state.pingTimer);
        state.pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'PING' }));
          }
        }, 25000);
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'NOTIFICATION' && msg.item) {
            if (matchesFilters(msg.item)) {
              state.items = [msg.item, ...state.items.filter(x => x.event_id !== msg.item.event_id)].slice(0, 200);
              renderFeed();
            }
            loadOverview();
          } else if (msg.type === 'RECEIPT' && msg.event_id) {
            let changed = false;
            state.items = state.items.map((it) => {
              if (it.event_id === msg.event_id) {
                changed = true;
                return Object.assign({}, it, { status: 'DEVICE_RECEIVED', recipient_received_at: msg.recipient_received_at });
              }
              return it;
            });
            if (changed) renderFeed();
            loadOverview();
          } else if (msg.type === 'TRAFFIC' && msg.log) {
            state.logs = [msg.log, ...state.logs].slice(0, 250);
            renderTraffic();
          } else if (msg.type === 'DEVICE_UPDATE') {
            loadOverview();
          }
        } catch (_) {}
      };

      ws.onclose = () => {
        wsDot.className = 'dot warn';
        wsLabel.textContent = 'Reconnecting...';
        if (state.pingTimer) {
          clearInterval(state.pingTimer);
          state.pingTimer = null;
        }
        if (state.token) {
          state.reconnectTimer = setTimeout(connectWs, 3000);
        }
      };
    } catch (_) {
      wsDot.className = 'dot warn';
      wsLabel.textContent = 'Polling fallback';
      if (state.token) {
        state.reconnectTimer = setTimeout(connectWs, 5000);
      }
    }
  }

  initAuthStatus();
})();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
@app.get("/monitor", response_class=HTMLResponse)
async def monitor_frontend():
    return HTMLResponse(
        content=MONITOR_HTML,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data:;"
            ),
        },
    )
