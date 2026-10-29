from __future__ import annotations

import asyncio
import errno
import json
import os
import hashlib
import secrets
import time
import re
import socket
import ipaddress
import uuid as uuid_lib
import logging
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, APIRouter
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import httpx
import psutil
from pydantic_settings import BaseSettings, SettingsConfigDict

# ==========================================
# Settings Management (pydantic-settings)
# ==========================================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    port: int = 8000
    secret_key: str = "ren-default-secret-key"
    admin_password: str = "admin"
    # Persistence: relative paths are resolved next to this file.
    data_file: str = "data/ren_data.json"
    # Persistent-volume directory. On Render/Railway the default filesystem is
    # ephemeral, so redeploys/cold-starts wipe ren_data.json. Point DATA_DIR at
    # a mounted disk/volume (e.g. /var/data on Render, /data on Railway) and the
    # state file is stored there instead, surviving restarts. Empty = legacy
    # behaviour (data_file resolved next to main.py).
    data_dir: str = ""
    # Security hardening toggles
    allow_private_ranges: bool = False   # if True, the tunnel may reach private/loopback ranges
    login_max_attempts: int = 5
    login_window_seconds: int = 900

CONFIG = Settings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default

# ==========================================
# Static UI assets (extracted from the monolith)
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

def _load_html(name: str) -> str:
    try:
        with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as f:
            return f.read()
    except Exception as exc:
        logger.error(f"Failed to load UI asset '{name}': {exc}")
        return f"<!DOCTYPE html><html><body><h1>REN</h1><p>UI asset '{name}' is missing.</p></body></html>"

LOGIN_HTML = _load_html("login.html")
DASHBOARD_HTML = _load_html("dashboard.html")

# ==========================================
# Global State
# ==========================================
connections: dict = {}
connection_sockets: dict = {}
ip_ref_count: dict = defaultdict(lambda: defaultdict(int))

stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_DOMAIN: str = ""

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7
# A tunnel is torn down only when NEITHER direction moved a byte for this long.
# It used to be a per-direction read timeout, so a long one-way transfer (a big
# Telegram/YouTube download with a quiet uplink) was killed mid-stream.
IDLE_TIMEOUT = _env_float("REN_IDLE_TIMEOUT", 300)

# Auth state: {"salt": hex, "hash": hex, "must_change": bool}
AUTH: dict = {}
SESSIONS: dict = {}

# Login brute-force protection: ip -> [failure timestamps]
login_attempts: dict = defaultdict(list)

PBKDF2_ITERATIONS = 200_000

# ==========================================
# Network / Proxy tuning
# ==========================================
# uTLS fingerprint advertised in share links (chrome blends best with CDN traffic).
DEFAULT_FINGERPRINT = os.environ.get("REN_FINGERPRINT", "chrome").strip() or "chrome"
# WebSocket early-data budget (bytes) advertised via the `ed` path param.
EARLY_DATA_MAX = 2048
# Explicit upstream SO_RCVBUF/SO_SNDBUF. 0 (default) = leave Linux TCP
# autotuning on. Pinning the buffers (the old fixed 256 KiB) DISABLES autotuning
# and caps every connection at buffer/RTT, i.e. ~1.3 MB/s to a 200 ms-away
# destination such as a far Telegram media DC.
SOCKET_BUFFER_BYTES = int(_env_float("REN_SOCKET_BUFFER", 0))
# Downstream read buffer bounds (adaptive between these two).
DOWNSTREAM_MIN_BUF = 16384
DOWNSTREAM_MAX_BUF = 262144
# StreamReader high-water mark for upstream sockets (default asyncio is 64 KiB).
STREAM_LIMIT = 262144

# ---- Upstream connect / DNS ---------------------------------------------------
CONNECT_TIMEOUT = _env_float("REN_CONNECT_TIMEOUT", 10)
DNS_TIMEOUT = 8.0
DNS_CACHE_TTL = _env_float("REN_DNS_CACHE_TTL", 120)
DNS_NEGATIVE_TTL = 5.0
DNS_CACHE_MAX = 4096
# Dedicated resolver pool. getaddrinfo() blocks a thread per lookup; the default
# asyncio executor is min(32, cpus + 4) = 5 threads on a 1-vCPU container, so a
# page that opens 30 connections (Google, YouTube) queued every connect behind
# DNS and blew through the connect timeout.
DNS_WORKERS = max(4, int(_env_float("REN_DNS_WORKERS", 32)))
# Happy Eyeballs (RFC 8305): start the next address if the previous one has not
# connected within this delay, instead of hanging on a black-holed route.
HAPPY_EYEBALLS_DELAY = 0.25
MAX_CONNECT_ADDRESSES = 8
# IPv6 egress: "auto" probes for a global IPv6 route at first use; "on"/"off"
# force it. Many PaaS containers resolve AAAA records but cannot route IPv6, and
# asyncio then tried the IPv6 address first and stalled until timeout: that is
# exactly why Google/YouTube (dual-stack everywhere) failed while IPv4-only
# targets (e.g. speedtest servers) worked.
IPV6_MODE = (os.environ.get("REN_IPV6", "auto").strip().lower() or "auto")
PREFER_IPV6 = _env_bool("REN_PREFER_IPV6", False)

# ---- UDP over VLESS -------------------------------------------------------------
# Xray/sing-box clients send DNS (port 53) and QUIC/HTTP3 (UDP 443: YouTube,
# Google, Instagram...) as plain VLESS UDP. It used to be rejected outright, so
# remote DNS and QUIC simply broke.
UDP_ENABLED = _env_bool("REN_UDP", True)
UDP_IDLE_TIMEOUT = _env_float("REN_UDP_IDLE_TIMEOUT", 90)
UDP_DNS_IDLE_TIMEOUT = 20.0
UDP_QUEUE_MAX = 1024             # datagrams buffered toward the client
UDP_BATCH_BYTES = 65536          # coalesce queued datagrams into one client write
UDP_MAX_PENDING = 2 * 65536 + 4  # unparsed uplink bytes (a frame is <= 64 KiB)

# ---- Server ---------------------------------------------------------------------
# WebSocket ping interval (seconds, 0 = off). PaaS edges drop idle upgraded
# connections after ~60 s; pings keep an idle Telegram/WS tunnel alive instead
# of forcing a reconnect storm.
WS_PING_INTERVAL = _env_float("REN_WS_PING_INTERVAL", 20)

# ---- XHTTP ("SplitHTTP") transport tuning -----------------------------------
# XHTTP replaces the old gRPC transport. Unlike gRPC (which needs HTTP/2
# END-TO-END and therefore broke on PaaS edges that demux HTTP/2 -> HTTP/1.1,
# e.g. Railway and Render's default domain), XHTTP carries the VLESS stream over
# ORDINARY HTTP request/response, so it works over plain HTTP/1.1 straight
# through those edges. No TCP passthrough, no HTTP/2, no extra env vars: the
# links target the normal HTTPS domain on :443, exactly like WebSocket.
#
# We advertise the "packet-up" mode (one long streaming GET for the downlink +
# many short POSTs for the uplink), which has the strongest CDN / HTTP-1.1
# compatibility; a client's `auto` mode also resolves to packet-up for
# security=tls. The share-link path is "/<prefix>/<uuid>", so the link uuid
# routes per-link (like the WS path) while the VLESS header stays the source of
# truth for authentication.
XHTTP_PATH_PREFIX = (os.environ.get("REN_XHTTP_PREFIX", "xhttp").strip("/") or "xhttp")
# Cap VLESS-header accumulation so a malformed uplink can't grow it without bound.
XHTTP_HEADER_MAX = 2048
# Max bytes accepted in a single upload POST body. Must be >= the client's 1 MB
# default (scMaxEachPostBytes); larger bodies get 413, matching Xray's contract.
XHTTP_MAX_POST_BYTES = 4_000_000
# Out-of-order upload reorder bound: if more than this many packets pile up
# waiting for a missing seq, tear the session down (the client is expected to
# open a fresh session and retry).
XHTTP_MAX_BUFFERED_POSTS = 64
# Per-session uplink backpressure threshold (bytes reassembled but not yet
# written upstream) — POST handlers briefly stall above this so a slow
# destination can't balloon memory on the free tier.
XHTTP_MAX_INFLIGHT_BYTES = 4_000_000
# Seconds to wait for the downlink GET to correlate with a freshly seen session
# before reaping it (mirrors Xray-core's 30 s correlation window).
XHTTP_SESSION_GRACE = 30
# Hard cap on concurrently tracked XHTTP sessions. Every unknown sessionId in a
# request would otherwise allocate a session + reaper task, so an unauthenticated
# scanner could exhaust memory on the free tier before the grace window expires.
XHTTP_MAX_SESSIONS = 512

# VLESS server response header: version byte (0) + addon length (0). The server
# MUST emit these two bytes once, before the first downstream payload byte, on
# EVERY transport. Omitting it makes the client consume two payload bytes as the
# header and silently corrupts the whole stream (this was broken on XHTTP).
VLESS_RESPONSE_HEADER = b"\x00\x00"

# ==========================================
# Password Hashing & Authentication
# ==========================================
def hash_password(pw: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()

def make_auth(pw: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "hash": hash_password(pw, salt), "must_change": False}

def verify_password(pw: str, auth: dict) -> bool:
    try:
        salt = bytes.fromhex(auth["salt"])
    except Exception:
        return False
    candidate = hash_password(pw, salt)
    return secrets.compare_digest(candidate, auth.get("hash", ""))

async def verify_password_async(pw: str, auth: dict) -> bool:
    """PBKDF2 (200k rounds) costs ~0.1-0.3 s of pure CPU. Running it inline on
    the event loop froze EVERY tunnel for that long on each login attempt, so a
    handful of bad logins (or a bot hammering /api/login) stalled all traffic."""
    return await asyncio.to_thread(verify_password, pw, auth)

def _env_password_fingerprint(pw: str) -> str:
    """Stable, non-reversible marker for 'which ADMIN_PASSWORD produced this auth'.

    Stored alongside the hash so a restart can tell an unchanged env var from a
    rotated one without keeping the plaintext around.
    """
    return hashlib.sha256(("ren-env-fp:" + pw).encode("utf-8")).hexdigest()

def init_auth():
    global AUTH
    env_pw = CONFIG.admin_password or "admin"
    AUTH = make_auth(env_pw)
    AUTH["env_fp"] = _env_password_fingerprint(env_pw)
    # Force a change while the operator is still on the well-known default.
    AUTH["must_change"] = (env_pw == "admin")

def sync_auth_with_env():
    """Adopt a rotated ADMIN_PASSWORD, but never undo a panel-side change.

    Previously the persisted hash always won, so an operator who changed
    ADMIN_PASSWORD on Render/Railway after the first boot was locked out with no
    way back short of deleting the state file. We now compare a fingerprint of
    the current env password with the one that produced the stored hash: if they
    differ the env var was rotated and wins; if they match, the stored hash (which
    may have been changed from inside the panel) is kept.
    """
    global AUTH
    env_pw = CONFIG.admin_password or "admin"
    fp = _env_password_fingerprint(env_pw)
    if AUTH.get("env_fp") == fp:
        return False
    AUTH = make_auth(env_pw)
    AUTH["env_fp"] = fp
    AUTH["must_change"] = (env_pw == "admin")
    logger.info("ADMIN_PASSWORD changed in the environment - panel password updated.")
    return True

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    exp = SESSIONS.get(token)
    if exp is None or exp < time.time():
        SESSIONS.pop(token, None)
        return False
    return True

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window = CONFIG.login_window_seconds
    recent = [t for t in login_attempts.get(ip, []) if now - t < window]
    login_attempts[ip] = recent
    return len(recent) >= CONFIG.login_max_attempts

def record_failed_login(ip: str):
    login_attempts[ip].append(time.time())

def reset_login_attempts(ip: str):
    login_attempts.pop(ip, None)

# ==========================================
# Persistence (JSON file, stdlib only)
# ==========================================
_persist_lock = asyncio.Lock()
# Set whenever in-memory state diverges from disk; the periodic flusher only
# writes when it is set, so an idle instance stops doing pointless I/O (which on
# a free-tier container also means pointless CPU credits and disk wear).
_state_dirty = False

def mark_dirty():
    global _state_dirty
    _state_dirty = True

# Canonical shape of a link record. Anything loaded from disk or imported from a
# user-supplied backup is coerced into this shape; previously a backup missing a
# single key (e.g. "active") was accepted and then made every /api/links call
# raise KeyError -> HTTP 500, permanently bricking the panel because the broken
# record was persisted straight back to disk.
_LINK_DEFAULTS = {
    "label": "Link",
    "limit_bytes": 0,
    "used_bytes": 0,
    "max_connections": 0,
    "created_at": "",
    "active": True,
    "expiry": "",
}

def _coerce_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def normalize_link(uid: str, raw) -> dict | None:
    """Validate + normalize one link record. Returns None if it is unusable."""
    if not isinstance(raw, dict):
        return None
    try:
        uuid_bytes = uuid_lib.UUID(uid).bytes
    except (ValueError, AttributeError, TypeError):
        return None
    link = dict(_LINK_DEFAULTS)
    link.update({k: v for k, v in raw.items() if k in _LINK_DEFAULTS})
    label = str(link["label"] or "Link")[:60]
    link["label"] = label or "Link"
    link["limit_bytes"] = max(0, _coerce_int(link["limit_bytes"]))
    link["used_bytes"] = max(0, _coerce_int(link["used_bytes"]))
    link["max_connections"] = max(0, _coerce_int(link["max_connections"]))
    link["active"] = bool(link["active"])
    link["expiry"] = str(link["expiry"] or "")
    link["created_at"] = str(link["created_at"] or datetime.now().isoformat())
    link["uuid_bytes"] = uuid_bytes
    _refresh_expiry_cache(link)
    return link

def _data_path() -> str:
    # A persistent volume (DATA_DIR) always wins: the state file lives inside it
    # under its basename, so operators only have to mount a disk and set one env
    # var to get durable storage across Render/Railway restarts.
    filename = os.path.basename(CONFIG.data_file) or "ren_data.json"
    data_dir = (CONFIG.data_dir or "").strip()
    if data_dir:
        return os.path.join(data_dir, filename)
    p = CONFIG.data_file
    return p if os.path.isabs(p) else os.path.join(BASE_DIR, p)

# Runtime-only keys that must never reach the JSON file (bytes are not
# serialisable, and the expiry cache is derived state).
_VOLATILE_LINK_KEYS = ("uuid_bytes", "_expiry_ts")

def export_link(link: dict) -> dict:
    return {k: v for k, v in link.items() if k not in _VOLATILE_LINK_KEYS}

def save_state_sync():
    path = _data_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = {
        "links": {k: export_link(v) for k, v in LINKS.items()},
        "addresses": CUSTOM_ADDRESSES,
        "domain": CUSTOM_DOMAIN,
        "auth": AUTH,
        "saved_at": datetime.now().isoformat(),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    # The file holds the admin password hash + salt: keep it owner-only.
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)

async def save_state():
    global _state_dirty
    async with _persist_lock:
        _state_dirty = False
        try:
            await asyncio.to_thread(save_state_sync)
        except Exception as exc:
            _state_dirty = True
            logger.error(f"Failed to persist state: {exc}")

def load_state() -> bool:
    global CUSTOM_ADDRESSES, CUSTOM_DOMAIN, AUTH
    path = _data_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.error(f"Failed to load state from {path}: {exc}")
        return False

    for k, v in (data.get("links") or {}).items():
        link = normalize_link(k, v)
        if link is None:
            logger.warning(f"Skipping invalid link during load: {k}")
            continue
        LINKS[k] = link
    addresses = data.get("addresses")
    if isinstance(addresses, list):
        CUSTOM_ADDRESSES = [str(a) for a in addresses if isinstance(a, str) and a.strip()]
    if isinstance(data.get("domain"), str):
        CUSTOM_DOMAIN = data["domain"]
    if isinstance(data.get("auth"), dict) and data["auth"].get("hash"):
        AUTH = data["auth"]
        AUTH.setdefault("must_change", False)
    logger.info(f"State restored from {path}")
    return True

# ==========================================
# Background Tasks
# ==========================================
async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            # Reuse the shared pooled client instead of building (and tearing
            # down) a fresh TLS stack every 10 minutes.
            if domain and domain != "localhost" and http_client is not None:
                await http_client.get(f"https://{domain}/health", timeout=10.0)
        except Exception:
            pass

async def cleanup_traffic_task():
    while True:
        await asyncio.sleep(3600)
        now = datetime.now()
        keys_to_delete = []
        for k in list(hourly_traffic.keys()):
            try:
                dt = datetime.strptime(k, "%Y-%m-%d %H:00")
                if (now - dt).total_seconds() > 86400:
                    keys_to_delete.append(k)
            except Exception:
                pass
        for k in keys_to_delete:
            hourly_traffic.pop(k, None)

async def periodic_save_task():
    # Traffic/usage counters change in the hot path; flush them periodically
    # instead of on every packet to avoid I/O storms. The dirty flag means an
    # idle instance writes nothing at all.
    while True:
        await asyncio.sleep(60)
        if _state_dirty:
            await save_state()

async def prune_state_task():
    # Sessions and login-attempt buckets are only cleaned lazily on access, so
    # abandoned tokens / one-off attacker IPs would accumulate forever. Sweep them
    # hourly to keep memory flat on long-lived free-tier instances.
    while True:
        await asyncio.sleep(3600)
        now = time.time()
        for tok in [t for t, exp in list(SESSIONS.items()) if exp < now]:
            SESSIONS.pop(tok, None)
        window = CONFIG.login_window_seconds
        for ip in list(login_attempts.keys()):
            recent = [t for t in login_attempts.get(ip, []) if now - t < window]
            if recent:
                login_attempts[ip] = recent
            else:
                login_attempts.pop(ip, None)
        # Safety net for XHTTP sessions whose reaper task was lost (e.g. the
        # event loop cancelled it): anything long past its grace window with no
        # downlink attached is dead weight.
        mono = time.monotonic()
        for sid, sess in list(xhttp_sessions.items()):
            if (not sess.get_attached.is_set()
                    and mono - sess.created > XHTTP_SESSION_GRACE * 2):
                sess.closed.set()
                xhttp_sessions.pop(sid, None)
        _dns_prune()

def ensure_default_link():
    if not LINKS:
        uid = str(uuid_lib.uuid4())
        LINKS[uid] = normalize_link(uid, {"label": "Default"})
        mark_dirty()

# ==========================================
# Helpers
# ==========================================
def _clean_host(raw: str) -> str:
    """Strip scheme, path and trailing slash from a PaaS-provided URL.

    RENDER_EXTERNAL_URL is a full URL (https://x.onrender.com), and a trailing
    slash used to survive into every generated vless:// link and SNI value,
    producing configs that silently failed to connect.
    """
    host = (raw or "").strip()
    host = host.split("://", 1)[-1]
    host = host.split("/", 1)[0]
    return host.strip().rstrip(".")

def get_domain() -> str:
    raw = os.environ.get("RENDER_EXTERNAL_URL") or os.environ.get("RAILWAY_PUBLIC_DOMAIN") or "localhost"
    return _clean_host(raw) or "localhost"

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None,
                        transport: str = "ws") -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()

    if transport == "xhttp":
        # XHTTP ("SplitHTTP") rides ordinary HTTP, so — unlike the old gRPC
        # transport — it works straight through PaaS/CDN edges that only speak
        # HTTP/1.1 (Railway, Render) and needs no TCP passthrough. The client
        # opens a streaming GET for the downlink and short POSTs for the uplink
        # under /<prefix>/<uuid>/...; the VLESS request header travels in the
        # first uplink bytes, exactly like the WS first frame. It reuses the same
        # domain:443 + TLS camouflage as WebSocket and works over clean-IP/CDN
        # addresses too, so it fans out across custom addresses just like WS.
        addr = address if address else domain
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "host": domain,
            "path": f"/{XHTTP_PATH_PREFIX}/{uuid}",
            "mode": "packet-up",
            "sni": domain,
            "fp": DEFAULT_FINGERPRINT,
            "alpn": "http/1.1",
            "allowInsecure": "0",
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

    # ---- WebSocket (default) ----
    # WebSocket early-data (0-RTT): the client carries the first chunk (which
    # holds the VLESS request header) inside the `Sec-WebSocket-Protocol`
    # upgrade header. This shaves a round-trip AND blends the handshake into
    # ordinary CDN traffic, which helps under DPI. Clients that don't understand
    # `ed` simply ignore it and send data as normal frames -> the server handles
    # both paths, so it stays fully compatible with standard v2rayNG / Nekobox /
    # sing-box configs. WS works on Railway's normal HTTPS domain (HTTP/1.1).
    addr = address if address else domain
    path = f"/ws/{uuid}?ed={EARLY_DATA_MAX}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "headerType": "none",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": DEFAULT_FINGERPRINT,
        "alpn": "http/1.1",
        "allowInsecure": "0",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def _refresh_expiry_cache(link: dict) -> float:
    """Parse `expiry` once and memoise it as a POSIX timestamp on the record.

    is_expired() runs on EVERY proxied chunk via check_quota(); parsing an ISO-8601
    string there burned a surprising amount of CPU per megabyte on the free tier.
    0.0 means "never expires".
    """
    exp = link.get("expiry")
    ts = 0.0
    if exp:
        try:
            ts = datetime.fromisoformat(exp).timestamp()
        except (TypeError, ValueError):
            ts = 0.0
    link["_expiry_ts"] = ts
    return ts

def _expiry_ts(link) -> float:
    if not isinstance(link, dict):
        return 0.0
    ts = link.get("_expiry_ts")
    if ts is None:
        ts = _refresh_expiry_cache(link)
    return ts

def is_expired(link) -> bool:
    ts = _expiry_ts(link)
    return bool(ts) and time.time() >= ts

def expiry_epoch(link) -> int:
    return int(_expiry_ts(link))

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    # .get() rather than [] — ip_ref_count is a defaultdict, so the old indexing
    # created (and never removed) an empty bucket for every link on every
    # /api/links call, leaking memory in proportion to panel refreshes.
    return sum(ip_ref_count.get(uid, {}).values())

def remove_ip_from_link(uid: str, ip: str):
    if uid in ip_ref_count and ip in ip_ref_count[uid]:
        ip_ref_count[uid][ip] -= 1
        if ip_ref_count[uid][ip] <= 0:
            ip_ref_count[uid].pop(ip, None)
            if not ip_ref_count[uid]:
                ip_ref_count.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    ip_ref_count.pop(uid, None)

def record_error(message: str):
    stats["total_errors"] += 1
    error_logs.append({"error": message, "time": datetime.now().isoformat()})

def _register_connection(uid: str, client_ip: str, handle, network: str, dest: str) -> str:
    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {"uuid": uid, "ip": client_ip, "network": network, "dest": dest,
                            "connected_at": datetime.now().isoformat(), "bytes": 0}
    connection_sockets[conn_id] = handle
    ip_ref_count[uid][client_ip] += 1
    stats["total_requests"] += 1
    return conn_id

def _unregister_connection(conn_id: str | None):
    if not conn_id:
        return
    info = connections.pop(conn_id, None)
    connection_sockets.pop(conn_id, None)
    if info:
        remove_ip_from_link(info.get("uuid"), info.get("ip"))

# ==========================================
# SSRF hardening: block internal / metadata destinations
# ==========================================
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")

def _ip_is_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return False
    # ::ffff:10.0.0.1 must be judged as the IPv4 address it really is.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4 and ip in _CGNAT_V4:
        return True   # carrier-grade NAT space: PaaS-internal networks live here
    return (ip.is_loopback or ip.is_link_local or ip.is_private
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


class DestinationBlocked(ValueError):
    pass

# ==========================================
# Upstream resolver (cached) + Happy Eyeballs connect
# ==========================================
_ipv6_state: dict = {"ok": None}
_dns_cache: dict = {}      # host -> (expires_monotonic, tuple_of_ips)
_dns_inflight: dict = {}   # host -> Task resolving it (dedupes concurrent lookups)
_dns_pool: ThreadPoolExecutor | None = None


def _probe_ipv6() -> bool:
    """True if this host has a GLOBAL IPv6 source address with a default route.

    A UDP connect() sends no packet; it only asks the kernel to pick a route.
    Containers that have only link-local/ULA IPv6 (the common PaaS case) fail
    this and stay IPv4-only, which avoids black-holed IPv6 connects entirely.
    """
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect(("2001:4860:4860::8888", 53))
            src = s.getsockname()[0]
        finally:
            s.close()
        return ipaddress.ip_address(src.split("%", 1)[0]).is_global
    except (OSError, ValueError):
        return False


def ipv6_available() -> bool:
    ok = _ipv6_state["ok"]
    if ok is None:
        if IPV6_MODE in ("1", "true", "yes", "on"):
            ok = True
        elif IPV6_MODE in ("0", "false", "no", "off"):
            ok = False
        else:
            ok = _probe_ipv6()
        _ipv6_state["ok"] = ok
        logger.info("IPv6 egress %s (REN_IPV6=%s)", "enabled" if ok else "disabled", IPV6_MODE)
    return ok


def _dns_executor() -> ThreadPoolExecutor:
    global _dns_pool
    if _dns_pool is None:
        _dns_pool = ThreadPoolExecutor(max_workers=DNS_WORKERS, thread_name_prefix="ren-dns")
    return _dns_pool


def _order_addresses(addrs) -> list:
    """Dedupe and interleave address families, preferred family first (RFC 8305)."""
    v4, v6, seen = [], [], set()
    for a in addrs:
        a = str(a).split("%", 1)[0]
        if a in seen:
            continue
        seen.add(a)
        (v6 if ":" in a else v4).append(a)
    if not ipv6_available():
        v6 = []
    first, second = (v6, v4) if PREFER_IPV6 else (v4, v6)
    out = []
    for i in range(max(len(first), len(second))):
        if i < len(first):
            out.append(first[i])
        if i < len(second):
            out.append(second[i])
    return out


def _dns_store(key: str, ips: tuple):
    if len(_dns_cache) >= DNS_CACHE_MAX:
        _dns_prune()
        if len(_dns_cache) >= DNS_CACHE_MAX:
            _dns_cache.clear()
    ttl = DNS_CACHE_TTL if ips else DNS_NEGATIVE_TTL
    _dns_cache[key] = (time.monotonic() + ttl, ips)


def _dns_prune():
    now = time.monotonic()
    for k in [k for k, v in list(_dns_cache.items()) if v[0] <= now]:
        _dns_cache.pop(k, None)


def _dns_forget(host: str):
    _dns_cache.pop((host or "").strip().lower().rstrip("."), None)


async def _resolve_uncached(key: str) -> tuple:
    loop = asyncio.get_running_loop()
    family = socket.AF_UNSPEC if ipv6_available() else socket.AF_INET
    try:
        infos = await loop.run_in_executor(
            _dns_executor(), socket.getaddrinfo, key, None, family, socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        _dns_store(key, ())
        raise OSError(f"DNS lookup failed for {key}: {exc}") from None
    ips = tuple(_order_addresses(info[4][0] for info in infos))
    _dns_store(key, ips)
    if not ips:
        raise OSError(f"DNS lookup failed for {key}: no usable address")
    return ips


def _retrieve_exception(task: asyncio.Task):
    if not task.cancelled():
        task.exception()


async def resolve_host(host: str) -> list:
    """Resolve a destination to an ordered IP list (literal IPs pass straight
    through, names are cached and concurrent lookups for one name are shared)."""
    host = (host or "").strip().strip("[]")
    if not host:
        raise OSError("empty destination address")
    try:
        return [str(ipaddress.ip_address(host.split("%", 1)[0]))]
    except ValueError:
        pass
    key = host.lower().rstrip(".")
    hit = _dns_cache.get(key)
    if hit is not None and hit[0] > time.monotonic():
        if hit[1]:
            return list(hit[1])
        raise OSError(f"DNS lookup failed for {key} (cached)")
    task = _dns_inflight.get(key)
    if task is None or task.done():
        task = asyncio.ensure_future(_resolve_uncached(key))
        _dns_inflight[key] = task
        task.add_done_callback(lambda _t, k=key: _dns_inflight.pop(k, None))
        task.add_done_callback(_retrieve_exception)
    return list(await asyncio.wait_for(asyncio.shield(task), DNS_TIMEOUT))


async def resolve_destination(address: str, port: int) -> list:
    """Resolve + vet a destination. Returns the IPs that are safe to dial.

    We dial exactly the addresses we vetted (no second lookup), which also closes
    the DNS-rebinding gap the old check-then-open_connection() flow had.
    """
    ips = await resolve_host(address)
    if not ipv6_available():
        v4 = [ip for ip in ips if ":" not in ip]
        if not v4:
            raise OSError(f"{address} is IPv6-only and this host has no IPv6 egress")
        ips = v4
    if not CONFIG.allow_private_ranges:
        ips = [ip for ip in ips if not _ip_is_blocked(ip)]
        if not ips:
            raise DestinationBlocked("destination not allowed")
    return ips[:MAX_CONNECT_ADDRESSES]


async def destination_allowed(address: str, port: int) -> bool:
    try:
        await resolve_destination(address, port)
        return True
    except Exception:
        return False


async def _happy_eyeballs(ips: list, port: int):
    """Race connects across `ips`, staggered by HAPPY_EYEBALLS_DELAY.

    A fast failure starts the next address immediately; a slow (black-holed)
    attempt no longer blocks the rest. First success wins, the others are
    cancelled/closed.
    """
    queue = list(ips)
    pending: set = set()
    task_ip: dict = {}
    errors: list = []
    winner = None
    try:
        while queue or pending:
            if queue:
                ip = queue.pop(0)
                t = asyncio.ensure_future(asyncio.open_connection(ip, port, limit=STREAM_LIMIT))
                task_ip[t] = ip
                pending.add(t)
            timeout = HAPPY_EYEBALLS_DELAY if queue else None
            done, pending = await asyncio.wait(pending, timeout=timeout,
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                exc = t.exception()
                if exc is None:
                    if winner is None:
                        winner = t.result()
                    else:
                        try:
                            t.result()[1].close()
                        except Exception:
                            pass
                    continue
                errors.append(exc)
                ip = task_ip.get(t, "")
                if (":" in ip and isinstance(exc, OSError)
                        and exc.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL)):
                    if _ipv6_state["ok"]:
                        logger.warning("IPv6 route unusable (%s); continuing IPv4-only", exc)
                    _ipv6_state["ok"] = False
            if winner is not None:
                return winner
        if errors:
            raise errors[-1]
        raise OSError("no address to connect to")
    finally:
        for t in pending:
            t.cancel()


def _apply_socket_opts(writer: asyncio.StreamWriter):
    """Tune an upstream TCP socket: keepalive, no-Nagle, optional buffers."""
    try:
        sock = writer.get_extra_info("socket")
        if not sock:
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Detect dead upstreams in ~2 min instead of the kernel's ~2 h default.
        for name, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 20), ("TCP_KEEPCNT", 3)):
            opt = getattr(socket, name, None)
            if opt is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, opt, value)
                except OSError:
                    pass
        # Disable Nagle: tunnelled traffic is already framed, so coalescing
        # adds latency (esp. for interactive TLS records) with no benefit.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if SOCKET_BUFFER_BYTES > 0:
            for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, opt, SOCKET_BUFFER_BYTES)
                except OSError:
                    pass
    except Exception:
        pass


async def connect_upstream(ips: list, port: int, address: str = ""):
    try:
        reader, writer = await asyncio.wait_for(_happy_eyeballs(ips, port), CONNECT_TIMEOUT)
    except asyncio.TimeoutError:
        if address:
            _dns_forget(address)
        raise OSError(f"connect to {address or ips[0]}:{port} timed out") from None
    except OSError as exc:
        if address:
            _dns_forget(address)
        raise OSError(f"connect to {address or ips[0]}:{port} failed: {exc}") from None
    _apply_socket_opts(writer)
    return reader, writer


async def open_upstream(address: str, port: int):
    """Resolve, vet and connect to a TCP destination (shared by WS and XHTTP)."""
    ips = await resolve_destination(address, port)
    return await connect_upstream(ips, port, address)

# ==========================================
# App + Lifespan
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)

    load_state()
    if "hash" not in AUTH:
        init_auth()
    else:
        sync_auth_with_env()
    if AUTH.get("must_change"):
        logger.warning("SECURITY: admin password is the default 'admin'. "
                       "Set a strong ADMIN_PASSWORD or change it in the panel immediately.")

    ensure_default_link()
    ipv6_available()   # probe once at boot so the log shows the egress mode
    tasks = [
        asyncio.create_task(keep_alive()),
        asyncio.create_task(cleanup_traffic_task()),
        asyncio.create_task(periodic_save_task()),
        asyncio.create_task(prune_state_task()),
    ]
    logger.info(f"REN started on port {CONFIG.port} (UDP {'on' if UDP_ENABLED else 'off'})")
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await save_state()
        if http_client:
            await http_client.aclose()

app = FastAPI(title="REN", docs_url=None, redoc_url=None, lifespan=lifespan)

def _allowed_origins() -> list:
    origins = set()
    dom = get_domain()
    if dom and dom != "localhost":
        origins.add(f"https://{dom}")
    railway = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway:
        origins.add(f"https://{railway.replace('https://', '').replace('http://', '')}")
    for var in ("PUBLIC_DOMAIN", "DEPLEXO_DOMAIN"):
        value = _clean_host(os.environ.get(var) or "")
        if value:
            origins.add(f"https://{value}")
    origins.add(f"http://localhost:{CONFIG.port}")
    origins.add(f"http://127.0.0.1:{CONFIG.port}")
    return list(origins)

# Same-origin dashboard only needs its own origin(s); the previous
# wildcard + credentials combination is rejected by browsers and unsafe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# Paths that carry the raw proxy byte-stream and must NEVER be touched by
# content encoding.
_TUNNEL_PREFIXES = ("/ws/", f"/{XHTTP_PATH_PREFIX}/", f"/{XHTTP_PATH_PREFIX}")

class SelectiveGZipMiddleware(GZipMiddleware):
    """GZip for the dashboard/API only.

    Starlette's GZipMiddleware compresses ANY streaming HTTP response whose client
    advertises `Accept-Encoding: gzip` — including the long XHTTP downlink GET.
    That was actively harmful: the tunnel payload is already TLS-encrypted (so
    compression buys nothing but CPU), and gzip's internal buffering delays small
    interactive packets until enough bytes accumulate, which shows up as a laggy
    or stalled connection. Tunnel paths are now passed through untouched.
    """
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if path.startswith(_TUNNEL_PREFIXES):
                await self.app(scope, receive, send)
                return
        await super().__call__(scope, receive, send)

app.add_middleware(SelectiveGZipMiddleware, minimum_size=1000)

class SecurityHeadersMiddleware:
    """Add hardening headers to panel/API responses only.

    Deliberately pure ASGI rather than @app.middleware("http"): Starlette's
    BaseHTTPMiddleware pumps the response through an anyio stream, which defers
    `http.response.start` and buffers body chunks. On the long-lived XHTTP
    downlink that means the client never sees the response headers and the
    tunnel hangs — verified at socket level (time-to-first-header went from
    0.002 s to a hard timeout) before this was rewritten.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "").startswith(_TUNNEL_PREFIXES):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {k.lower() for k, _ in headers}
                for key, value in ((b"x-content-type-options", b"nosniff"),
                                   (b"referrer-policy", b"no-referrer"),
                                   (b"x-frame-options", b"DENY")):
                    if key not in present:
                        headers.append((key, value))
            await send(message)

        await self.app(scope, receive, send_wrapper)

app.add_middleware(SecurityHeadersMiddleware)

api_router = APIRouter(prefix="/api")

# ==========================================
# Request-body helpers (malformed input -> 400, never 500)
# ==========================================
async def read_json(request: Request) -> dict:
    """Parse a JSON object body, answering 400 instead of crashing on garbage."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object")
    return body

def body_float(body: dict, key: str, default: float = 0.0) -> float:
    value = body.get(key)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a number")

def body_int(body: dict, key: str, default: int = 0, minimum: int = 0) -> int:
    value = body.get(key)
    if value is None or value == "":
        return default
    try:
        return max(minimum, int(float(value)))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a whole number")

def _cookie_is_secure() -> bool:
    return get_domain() != "localhost"

# ==========================================
# Camouflage Routes
# ==========================================
FAKE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title><style>body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }</style></head>
<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p></body>
</html>
"""

@app.get("/")
async def root():
    return HTMLResponse(content=FAKE_HTML, status_code=200)

_JSON_ERROR_PREFIXES = ("/api/", "/stats")

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    # The camouflage page is for probes hitting unknown paths. It used to swallow
    # legitimate API 404s too, so the dashboard received `text/html` where it
    # awaited JSON and every "not found" surfaced as a generic failure.
    if request.url.path.startswith(_JSON_ERROR_PREFIXES):
        detail = getattr(exc, "detail", "not found")
        return JSONResponse({"detail": detail}, status_code=404)
    return HTMLResponse(content=FAKE_HTML, status_code=404)

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ==========================================
# API Routes
# ==========================================
@api_router.post("/login")
async def api_login(request: Request):
    ip = request_ip(request)
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    body = await read_json(request)
    password = str(body.get("password") or "")
    if not await verify_password_async(password, AUTH):
        record_failed_login(ip)
        raise HTTPException(status_code=401, detail="Invalid password")
    reset_login_attempts(ip)
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL,
                    httponly=True, samesite="lax", secure=_cookie_is_secure(), path="/")
    return resp

@api_router.post("/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    SESSIONS.pop(token, None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@api_router.get("/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    authed = await is_valid_session(token)
    return {
        "authenticated": authed,
        "must_change_password": bool(AUTH.get("must_change")) if authed else False,
    }

@api_router.post("/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global AUTH
    body = await read_json(request)
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not await verify_password_async(current, AUTH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    AUTH = await asyncio.to_thread(make_auth, new)
    AUTH["must_change"] = False
    # Preserve the fingerprint of the CURRENT env password. Without it the next
    # restart would see "env differs from stored" and silently roll this change
    # back to whatever ADMIN_PASSWORD still says.
    AUTH["env_fp"] = _env_password_fingerprint(CONFIG.admin_password or "admin")
    current_token = request.cookies.get(SESSION_COOKIE)
    SESSIONS.clear()
    if current_token:
        SESSIONS[current_token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@api_router.post("/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await read_json(request)
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label) or not label:
        raise HTTPException(status_code=400, detail="Invalid inbound name")

    limit_value = body_float(body, "limit_value")
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = body_int(body, "max_connections")
    expiry = compute_expiry(body_float(body, "expiry_days"))
    uid = str(uuid_lib.uuid4())

    LINKS[uid] = normalize_link(uid, {
        "label": label, "limit_bytes": limit_bytes, "max_connections": max_conn,
        "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry,
    })
    await save_state()
    return {
        "uuid": uid,
        "label": label,
        "vless_link": generate_vless_link(uid, remark=f"REN-{label}"),
        "vless_link_xhttp": generate_vless_link(uid, remark=f"REN-{label}-XHTTP", transport="xhttp"),
    }

@api_router.get("/links")
async def list_links(_=Depends(require_auth)):
    result = []
    for uid, data in LINKS.items():
        active_ips = list(ip_ref_count.get(uid, {}).keys())
        result.append({
            "uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"],
            "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0),
            "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data),
            "created_at": data["created_at"], "current_connections": count_connections_for_link(uid),
            "connected_ips": active_ips,
            "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}"),
            "vless_link_xhttp": generate_vless_link(uid, remark=f"REN-{data['label']}-XHTTP", transport="xhttp"),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@api_router.patch("/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await read_json(request)
    if uid not in LINKS:
        raise HTTPException(status_code=404, detail="link not found")
    link = LINKS[uid]
    if "active" in body:
        link["active"] = bool(body["active"])
    if "limit_value" in body:
        limit_value = body_float(body, "limit_value")
        limit_unit = body.get("limit_unit") or "GB"
        link["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    if body.get("reset_usage"):
        link["used_bytes"] = 0
    if "expiry_days" in body:
        link["expiry"] = compute_expiry(body_float(body, "expiry_days"))
        # Keep the memoised timestamp in step, otherwise a link stays "expired"
        # (or stays alive) until the next restart.
        _refresh_expiry_cache(link)
    if "label" in body:
        label = str(body["label"]).strip()[:60]
        if not label or not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
            raise HTTPException(status_code=400, detail="Invalid inbound name")
        link["label"] = label
    if "max_connections" in body:
        link["max_connections"] = body_int(body, "max_connections")
    await save_state()
    return {"ok": True}

@api_router.delete("/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    if LINKS.pop(uid, None) is None:
        raise HTTPException(status_code=404, detail="link not found")
    await close_connections_for_link(uid)
    await save_state()
    return {"ok": True}

@api_router.get("/domain")
async def get_custom_domain(_=Depends(require_auth)):
    return {"domain": CUSTOM_DOMAIN}

@api_router.post("/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await read_json(request)
    domain = _clean_host(str(body.get("domain") or "")).lower()
    if domain:
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    global CUSTOM_DOMAIN
    CUSTOM_DOMAIN = domain
    await save_state()
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@api_router.get("/addresses")
async def list_addresses(_=Depends(require_auth)):
    return {"addresses": list(CUSTOM_ADDRESSES)}

@api_router.post("/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await read_json(request)
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if address not in CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append(address)
    await save_state()
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.delete("/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    if 0 <= index < len(CUSTOM_ADDRESSES):
        CUSTOM_ADDRESSES.pop(index)
    else:
        raise HTTPException(status_code=404, detail="Address not found")
    await save_state()
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.get("/backup")
async def export_data(_=Depends(require_auth)):
    return {
        "links": {k: export_link(v) for k, v in LINKS.items()},
        "addresses": list(CUSTOM_ADDRESSES),
        "domain": CUSTOM_DOMAIN,
    }

@api_router.post("/backup")
async def import_data(request: Request, _=Depends(require_auth)):
    data = await read_json(request)
    global CUSTOM_ADDRESSES, CUSTOM_DOMAIN
    imported = skipped = 0
    # Every record goes through the same normalizer as the on-disk loader. A
    # hand-edited or truncated backup used to be written straight into LINKS and
    # then persisted, so one missing field turned every later /api/links call
    # into a 500 that survived restarts.
    if isinstance(data.get("links"), dict):
        for k, v in data["links"].items():
            link = normalize_link(k, v)
            if link is None:
                skipped += 1
                logger.warning(f"Skipping invalid link during import: {k}")
                continue
            LINKS[k] = link
            imported += 1
    if isinstance(data.get("addresses"), list):
        CUSTOM_ADDRESSES = [a.strip() for a in data["addresses"]
                            if isinstance(a, str) and a.strip()]
    if isinstance(data.get("domain"), str):
        CUSTOM_DOMAIN = _clean_host(data["domain"]).lower()
    await save_state()
    return {"ok": True, "imported": imported, "skipped": skipped}

app.include_router(api_router)

# ==========================================
# Subscription Route
# ==========================================
@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = LINKS.get(uid)
    if link is None:
        raise HTTPException(status_code=404, detail="link not found")
    if not link["active"] or is_expired(link):
        raise HTTPException(status_code=403, detail="link inactive or expired")

    # WebSocket and XHTTP both work on the normal HTTPS domain and over every
    # custom (clean-IP / CDN) address, so we fan BOTH transports across all of
    # them. This gives every client a working config no matter which transport
    # its app or network prefers.
    sub_links = [
        generate_vless_link(uid, remark=f"REN-{link['label']}-WS"),
        generate_vless_link(uid, remark=f"REN-{link['label']}-XHTTP", transport="xhttp"),
    ]
    for i, addr in enumerate(CUSTOM_ADDRESSES):
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-WS", address=addr))
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-XHTTP", address=addr, transport="xhttp"))

    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

# ==========================================
# Core Proxy Protocol Engine (VLESS)
# ==========================================
def decode_early_data(subprotocol_header: str | None) -> bytes:
    """Decode WebSocket 0-RTT early data from the Sec-WebSocket-Protocol header.

    Xray/sing-box carry the first stream chunk as URL-safe base64 (no padding) in
    that header when `ed=` is set. If the value isn't valid base64 (i.e. it is a
    genuine subprotocol name), we return b"" and let the normal frame path run,
    so non-early-data clients are unaffected.
    """
    if not subprotocol_header:
        return b""
    token = subprotocol_header.split(",")[0].strip()
    if not token:
        return b""
    try:
        padded = token + "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return b""


def parse_vless_header(buffer: bytes, expected_uuid_bytes: bytes):
    """Parse a VLESS request header. Returns None while more bytes are needed.

    Synchronous on purpose: it never awaits, so making it a coroutine only added
    an event-loop round-trip per connection setup.
    """
    if len(buffer) < 24:
        return None

    version = buffer[0]
    if version != 0:
        raise ValueError(f"Unsupported VLESS version: {version}")

    received_uuid_bytes = buffer[1:17]
    if expected_uuid_bytes != received_uuid_bytes:
        raise ValueError("UUID mismatch")

    addon_len = buffer[17]
    pos = 18 + addon_len
    if len(buffer) < pos + 3:
        return None

    command = buffer[pos]
    pos += 1
    port = int.from_bytes(buffer[pos:pos + 2], "big")
    pos += 2
    addr_type = buffer[pos]
    pos += 1

    if addr_type == 1:
        if len(buffer) < pos + 4:
            return None
        address = ".".join(str(b) for b in buffer[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        if len(buffer) < pos + 1:
            return None
        domain_len = buffer[pos]
        pos += 1
        if len(buffer) < pos + domain_len:
            return None
        address = buffer[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(buffer) < pos + 16:
            return None
        address = ":".join(f"{buffer[i]:02x}{buffer[i+1]:02x}" for i in range(pos, pos + 16, 2))
        pos += 16
    else:
        raise ValueError(f"Unknown address type: {addr_type}")

    return command, address, port, buffer[pos:]

# VLESS commands: 1 = TCP, 2 = UDP, 3 = MUX.
VLESS_CMD_TCP = 1
VLESS_CMD_UDP = 2
VLESS_CMD_MUX = 3
MUX_ADDRESS_SUFFIX = "mux.cool"

def unsupported_reason(command: int, address: str) -> str | None:
    """Return a human-readable reason if this request cannot be served, else None.

    TCP and plain VLESS UDP (DNS, QUIC) are bridged. Mux / XUDP (which dial the
    pseudo-host *.mux.cool) are not, and say so plainly so the panel's error log
    is actionable instead of showing an opaque DNS error.
    """
    if address and address.lower().endswith(MUX_ADDRESS_SUFFIX):
        return "multiplexing (mux/XUDP) is not supported; disable mux in the client"
    if command == VLESS_CMD_UDP:
        if not UDP_ENABLED:
            return ("UDP over VLESS is disabled on this gateway (REN_UDP=false); "
                    "set the app's DNS/routing to TCP")
        return None
    if command == VLESS_CMD_MUX:
        return "multiplexing (mux/XUDP) is not supported; disable mux in the client"
    if command != VLESS_CMD_TCP:
        return f"unsupported VLESS command: {command}"
    return None

def _quota_ok(uid: str, extra_bytes: int) -> bool:
    """Synchronous hot-path quota check (no coroutine allocation per chunk)."""
    link = LINKS.get(uid)
    if not link or not link.get("active") or is_expired(link):
        return False
    limit = link.get("limit_bytes", 0)
    if limit == 0:
        return True
    return (link.get("used_bytes", 0) + extra_bytes) <= limit

async def check_quota(uid: str, extra_bytes: int) -> bool:
    return _quota_ok(uid, extra_bytes)

_hour_bucket = {"until": 0.0, "key": ""}

def _hour_key() -> str:
    """Current "%Y-%m-%d %H:00" bucket, recomputed at most once per hour.

    account_traffic() runs for every proxied chunk, and datetime.now().strftime()
    there meant a full datetime construction + string format per packet.
    """
    now = time.time()
    if now >= _hour_bucket["until"]:
        dt = datetime.now()
        _hour_bucket["key"] = dt.strftime("%Y-%m-%d %H:00")
        # Expire at the top of the next hour.
        _hour_bucket["until"] = now + (3600 - (dt.minute * 60 + dt.second))
    return _hour_bucket["key"]

def account_traffic(conn_id: str | None, uid: str, size: int, is_request: bool = False):
    """Record byte accounting for a transferred chunk (transport-agnostic).

    Consolidates the global stats counters, per-connection byte tally, hourly
    traffic histogram and per-link usage that the WS and XHTTP pumps both need.
    `is_request` is kept for compatibility; requests are now counted once per
    tunnel in _register_connection() (it used to count every uplink CHUNK).
    """
    global _state_dirty
    stats["total_bytes"] += size
    if is_request:
        stats["total_requests"] += 1
    if conn_id:
        conn = connections.get(conn_id)
        if conn is not None:
            conn["bytes"] += size
    hourly_traffic[_hour_key()] += size
    link = LINKS.get(uid)
    if link is not None:
        link["used_bytes"] += size
        # Usage moved -> the periodic flusher has something worth writing.
        _state_dirty = True

# ==========================================
# Transport-agnostic bridges (TCP + UDP), shared by WS and XHTTP
# ==========================================
class _Activity:
    """Last time ANY byte moved in either direction (drives the idle timeout)."""
    __slots__ = ("last",)

    def __init__(self):
        self.last = time.monotonic()

    def touch(self):
        self.last = time.monotonic()


async def _idle_watchdog(activity: _Activity, timeout: float):
    while True:
        remaining = activity.last + timeout - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.sleep(remaining + 0.05)


async def _supervise(up_coro, down_coro, activity: _Activity, idle_timeout: float,
                     up_is_master: bool, stop: asyncio.Event | None):
    """Run both pumps until the tunnel is over, then cancel and reap them.

    The downlink, the idle watchdog and the optional external `stop` event always
    end the tunnel. The uplink ends it only when `up_is_master` (WebSocket: the
    uplink ending means the client is gone). On XHTTP the uplink is just a feeder
    and the client may keep the GET open after it stops POSTing.
    """
    t_up = asyncio.ensure_future(up_coro)
    t_down = asyncio.ensure_future(down_coro)
    t_idle = asyncio.ensure_future(_idle_watchdog(activity, idle_timeout))
    tasks = [t_up, t_down, t_idle]
    waiters = {t_down, t_idle}
    if up_is_master:
        waiters.add(t_up)
    if stop is not None:
        t_stop = asyncio.ensure_future(stop.wait())
        tasks.append(t_stop)
        waiters.add(t_stop)
    try:
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def bridge_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     initial_payload: bytes, recv_client, send_client,
                     conn_id: str, uid: str, *, up_is_master: bool,
                     stop: asyncio.Event | None = None):
    """Pump a VLESS TCP tunnel. recv_client() -> bytes | None (EOF);
    send_client(bytes) writes toward the client."""
    activity = _Activity()
    try:
        if initial_payload:
            writer.write(initial_payload)
            await writer.drain()

        async def up():
            try:
                while True:
                    data = await recv_client()
                    if data is None:
                        break
                    if not data:
                        continue
                    size = len(data)
                    if not _quota_ok(uid, size):
                        break
                    activity.touch()
                    account_traffic(conn_id, uid, size)
                    writer.write(data)
                    await writer.drain()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            finally:
                try:
                    if writer.can_write_eof():
                        writer.write_eof()
                except Exception:
                    pass

        async def down():
            first = True
            buf_size = DOWNSTREAM_MIN_BUF
            try:
                while True:
                    data = await reader.read(buf_size)
                    if not data:
                        break
                    size = len(data)
                    # Grow the read size while we keep filling it (bulk transfer),
                    # shrink when reads run small (interactive/idle).
                    if size == buf_size and buf_size < DOWNSTREAM_MAX_BUF:
                        buf_size = min(DOWNSTREAM_MAX_BUF, buf_size * 2)
                    elif size < buf_size // 2 and buf_size > DOWNSTREAM_MIN_BUF:
                        buf_size = max(DOWNSTREAM_MIN_BUF, buf_size // 2)
                    if not _quota_ok(uid, size):
                        break
                    activity.touch()
                    account_traffic(conn_id, uid, size)
                    if first:
                        data = VLESS_RESPONSE_HEADER + data
                        first = False
                    await send_client(data)
            except asyncio.CancelledError:
                first = False   # tearing down: don't write to a dead client
                raise
            except Exception:
                pass
            finally:
                # An upstream that closes without sending anything still owes the
                # client a well-formed (empty) VLESS response.
                if first:
                    try:
                        await send_client(VLESS_RESPONSE_HEADER)
                    except Exception:
                        pass

        await _supervise(up(), down(), activity, IDLE_TIMEOUT, up_is_master, stop)
    finally:
        try:
            writer.close()
        except Exception:
            pass


class _UdpUpstream(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data, addr):
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            pass   # UDP semantics: drop rather than balloon memory

    def error_received(self, exc):
        pass       # ICMP unreachable etc.: QUIC/DNS retransmit on their own

    def connection_lost(self, exc):
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


def _udp_split_frames(buf: bytearray) -> list:
    """Pop every complete [u16 length][payload] VLESS UDP frame from `buf`."""
    out = []
    pos = 0
    n = len(buf)
    while n - pos >= 2:
        length = (buf[pos] << 8) | buf[pos + 1]
        if n - pos - 2 < length:
            break
        if length:
            out.append(bytes(buf[pos + 2:pos + 2 + length]))
        pos += 2 + length
    if pos:
        del buf[:pos]
    return out


def _udp_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "big") + payload


async def bridge_udp(ips: list, port: int, initial_payload: bytes, recv_client, send_client,
                     conn_id: str, uid: str, *, up_is_master: bool,
                     stop: asyncio.Event | None = None):
    """Plain VLESS UDP: each packet is framed as a big-endian u16 length + bytes,
    in both directions; the VLESS response header leads the first downlink frame.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=UDP_QUEUE_MAX)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpUpstream(queue), remote_addr=(ips[0], port))
    activity = _Activity()
    pending = bytearray()

    def push(data: bytes):
        pending.extend(data)
        for pkt in _udp_split_frames(pending):
            transport.sendto(pkt)
        if len(pending) > UDP_MAX_PENDING:
            raise ValueError("malformed VLESS UDP framing")

    try:
        if initial_payload:
            push(initial_payload)

        async def up():
            while True:
                data = await recv_client()
                if data is None:
                    break
                if not data:
                    continue
                size = len(data)
                if not _quota_ok(uid, size):
                    break
                activity.touch()
                account_traffic(conn_id, uid, size)
                push(data)

        async def down():
            first = True
            eof = False
            while not eof:
                pkt = await queue.get()
                if pkt is None:
                    break
                out = bytearray(VLESS_RESPONSE_HEADER) if first else bytearray()
                first = False
                payload_bytes = 0
                while True:
                    out += _udp_frame(pkt)
                    payload_bytes += len(pkt)
                    if len(out) >= UDP_BATCH_BYTES:
                        break
                    try:
                        pkt = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if pkt is None:
                        eof = True
                        break
                if not _quota_ok(uid, payload_bytes):
                    break
                activity.touch()
                account_traffic(conn_id, uid, payload_bytes)
                await send_client(bytes(out))

        idle = UDP_DNS_IDLE_TIMEOUT if port == 53 else UDP_IDLE_TIMEOUT
        await _supervise(up(), down(), activity, idle, up_is_master, stop)
    finally:
        transport.close()


async def run_vless_tunnel(command: int, address: str, port: int, ips: list,
                           initial_payload: bytes, recv_client, send_client,
                           conn_id: str, uid: str, *, up_is_master: bool,
                           stop: asyncio.Event | None = None):
    if command == VLESS_CMD_UDP:
        await bridge_udp(ips, port, initial_payload, recv_client, send_client, conn_id, uid,
                         up_is_master=up_is_master, stop=stop)
        return
    reader, writer = await connect_upstream(ips, port, address)
    await bridge_tcp(reader, writer, initial_payload, recv_client, send_client, conn_id, uid,
                     up_is_master=up_is_master, stop=stop)

# ==========================================
# WebSocket Transport
# ==========================================
@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    # WebSocket 0-RTT: pull any early data out of the subprotocol header and echo
    # the token back on accept so strict clients/CDNs finish the handshake.
    subproto = websocket.headers.get("sec-websocket-protocol")
    early_data = decode_early_data(subproto)
    if subproto:
        await websocket.accept(subprotocol=subproto.split(",")[0].strip())
    else:
        await websocket.accept()
    conn_id = None
    client_ip = get_client_ip(websocket)
    address = ""
    try:
        link_data = LINKS.get(uuid)
        if not link_data or not link_data["active"] or is_expired(link_data):
            await websocket.close(code=1008, reason="forbidden")
            return

        max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = ip_ref_count.get(uuid, {}).get(client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="limit reached")
                return

        expected_bytes = link_data.get("uuid_bytes")
        if not expected_bytes:
            expected_bytes = uuid_lib.UUID(uuid).bytes
            link_data["uuid_bytes"] = expected_bytes

        # Seed with 0-RTT early data (may already hold the full VLESS header).
        buffer = early_data
        command = port = initial_payload = None
        while True:
            if buffer:
                parsed = parse_vless_header(buffer, expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    break
                if len(buffer) > 2048:
                    raise ValueError("Header overflow")
            try:
                first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
            except asyncio.TimeoutError:
                await websocket.close(code=1008, reason="timeout")
                return
            if first_msg["type"] == "websocket.disconnect":
                return
            chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
            if not chunk:
                continue
            buffer += chunk

        reason = unsupported_reason(command, address)
        if reason:
            record_error(f"ws: {reason}")
            await websocket.close(code=1008, reason="unsupported request")
            return

        # Resolve + SSRF-vet once; we then dial exactly these addresses.
        try:
            ips = await resolve_destination(address, port)
        except DestinationBlocked:
            await websocket.close(code=1008, reason="destination not allowed")
            return

        network = "udp" if command == VLESS_CMD_UDP else "tcp"
        conn_id = _register_connection(uuid, client_ip, websocket, network, f"{address}:{port}")
        # Header + first payload, counted exactly once (it used to be counted
        # twice: once as `buffer`, again as `initial_payload`).
        account_traffic(conn_id, uuid, len(buffer))

        async def recv_client():
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                return None
            return msg.get("bytes") or (msg.get("text") or "").encode()

        async def send_client(data: bytes):
            await websocket.send_bytes(data)

        await run_vless_tunnel(command, address, port, ips, initial_payload,
                               recv_client, send_client, conn_id, uuid, up_is_master=True)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        record_error(f"ws: {exc}")
    finally:
        _unregister_connection(conn_id)
        # Close promptly so the client app retries at once instead of waiting.
        try:
            await websocket.close()
        except Exception:
            pass

# ==========================================
# XHTTP ("SplitHTTP") Transport Engine
# ==========================================
# XHTTP carries the VLESS byte-stream over ORDINARY HTTP request/response, so it
# works through PaaS/CDN edges that only speak HTTP/1.1 (Railway, Render) — the
# very edges that demux HTTP/2 and broke gRPC. There is NO extra framing: the
# transport is a raw duplex byte stream and VLESS runs on top of it, exactly
# like the WebSocket path.
#
# packet-up mode (the mode we advertise, and where a client's `auto` lands for
# security=tls):
#   * DOWNLINK: one long-lived   GET  /<prefix>/<linkuuid>/<sessionId>
#       -> the response body streams upstream->client bytes forever (chunked,
#          flushed per write). Content-Type text/event-stream is masquerade only
#          (defeats intermediary buffering) — we never inject any bytes into it.
#   * UPLINK:  many short         POST /<prefix>/<linkuuid>/<sessionId>/<seq>
#       -> each body is one chunk of client->upstream bytes; <seq> (0,1,2,...)
#          gives ordering. POSTs may arrive out of order / before the GET, so we
#          buffer and reorder by seq, then feed the reassembled stream to the
#          VLESS parser. (A single streaming POST with no <seq> = "stream-up" is
#          also accepted.)
# The <sessionId> in the path is the sole key tying the GET and its POSTs into
# one logical connection; the <linkuuid> first segment routes per-link (like
# /ws/<uuid>), while the VLESS header stays the source of truth for auth.
#
# Reference: XTLS/Xray-core transport/internet/splithttp (hub.go, upload_queue.go)
# and RPRX's "XHTTP: Beyond REALITY" (github.com/XTLS/Xray-core/discussions/4113).

xhttp_sessions: dict = {}   # sessionId -> XhttpSession


def _xhttp_drain_inorder(pending: dict, next_seq: int):
    """Pop the contiguous run of packets from `pending` starting at next_seq.

    Mutates `pending` in place; returns (ordered_chunks, new_next_seq). Pure and
    synchronous so the reorder logic is unit-testable without an ASGI context.
    """
    chunks = []
    while next_seq in pending:
        chunks.append(pending.pop(next_seq))
        next_seq += 1
    return chunks, next_seq


class XhttpSession:
    """Correlates one downlink GET with many uplink POSTs sharing a sessionId.

    POST handlers PRODUCE ordered uplink bytes into `up_queue`; the GET handler
    CONSUMES them (parsing the VLESS header, then feeding the upstream socket)
    and writes the downlink back into its streaming response body. Stored in
    connection_sockets so close_connections_for_link() can tear it down on link
    deletion, the same way it closes a WebSocket.
    """
    def __init__(self, link_uuid: str, expected_bytes: bytes, client_ip: str):
        self.link_uuid = link_uuid
        self.expected_bytes = expected_bytes
        self.client_ip = client_ip
        self.created = time.monotonic()
        self.lock = asyncio.Lock()
        self.pending: dict = {}           # seq -> bytes held awaiting in-order delivery
        self.next_seq = 0
        self.up_queue: asyncio.Queue = asyncio.Queue()   # ordered uplink chunks (None = EOF)
        self.inflight_bytes = 0
        self.get_attached = asyncio.Event()
        self.closed = asyncio.Event()
        self.conn_id = None

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed.set()
        try:
            self.up_queue.put_nowait(None)
        except Exception:
            pass

    def consume(self, chunk: bytes):
        """Account for uplink bytes leaving the queue, never going negative."""
        self.inflight_bytes = max(0, self.inflight_bytes - len(chunk))


def _xhttp_client_ip(scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            return value.decode("latin1").split(",")[0].strip()
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"


def _xhttp_padding_header() -> tuple:
    """A random-length X-Padding response header (fingerprint camouflage)."""
    return (b"x-padding", b"X" * (100 + secrets.randbelow(901)))


async def _xhttp_send_simple(send, status: int, extra_headers=None):
    """Send a short bodyless HTTP response (acks, rejects, CORS preflight)."""
    headers = [
        (b"cache-control", b"no-store"),
        (b"access-control-allow-origin", b"*"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    try:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    except Exception:
        pass


async def _xhttp_read_body(receive, limit: int):
    """Collect a bounded request body from ASGI receive events.

    Returns (body_bytes, too_large). Once the limit is passed we stop retaining
    bytes and just drain the request: the previous version kept extending the
    buffer after setting the flag, so a client streaming an endless body could
    exhaust memory even though the response was going to be a 413 anyway.
    """
    body = bytearray()
    too_large = False
    while True:
        event = await receive()
        et = event["type"]
        if et == "http.request":
            chunk = event.get("body") or b""
            if chunk and not too_large:
                body.extend(chunk)
                if len(body) > limit:
                    too_large = True
                    body = bytearray()   # release what we already read
            if not event.get("more_body", False):
                break
        elif et == "http.disconnect":
            break
    return bytes(body), too_large


async def _xhttp_feed_packet(session: "XhttpSession", seq: int, body: bytes) -> bool:
    """Insert an uplink packet by seq, delivering any now-contiguous run in order.

    Returns False if the reorder buffer overflowed (caller must tear the session
    down), True otherwise.
    """
    async with session.lock:
        if session.closed.is_set():
            return True
        if seq < session.next_seq:
            return True  # duplicate / already delivered
        session.pending[seq] = body
        if len(session.pending) > XHTTP_MAX_BUFFERED_POSTS:
            return False
        chunks, session.next_seq = _xhttp_drain_inorder(session.pending, session.next_seq)
        for c in chunks:
            session.up_queue.put_nowait(c)
            session.inflight_bytes += len(c)
    return True


def _xhttp_get_or_create(session_id: str, link_uuid: str, expected_bytes: bytes,
                         client_ip: str) -> "XhttpSession | None":
    session = xhttp_sessions.get(session_id)
    if session is not None:
        return session
    # Bound the table: every unseen sessionId in a request would otherwise
    # allocate a session object plus a reaper task, so a scanner spraying random
    # ids could push a free-tier container out of memory inside the grace window.
    if len(xhttp_sessions) >= XHTTP_MAX_SESSIONS:
        logger.warning("XHTTP session table full (%d); rejecting new session",
                       XHTTP_MAX_SESSIONS)
        return None
    session = XhttpSession(link_uuid, expected_bytes, client_ip)
    xhttp_sessions[session_id] = session
    asyncio.create_task(_xhttp_reaper(session_id, session))
    return session


async def _xhttp_reaper(session_id: str, session: "XhttpSession"):
    """Drop a session whose downlink GET never arrives (buffered POSTs would
    otherwise linger). Mirrors Xray-core's ~30 s correlation window."""
    try:
        await asyncio.wait_for(session.get_attached.wait(), timeout=XHTTP_SESSION_GRACE)
    except asyncio.TimeoutError:
        if not session.get_attached.is_set():
            session.closed.set()
            if xhttp_sessions.get(session_id) is session:
                xhttp_sessions.pop(session_id, None)


async def _xhttp_backpressure(session: "XhttpSession"):
    """Stall an uplink request while too many bytes wait to go upstream.

    Waits on the queue draining instead of the old fixed 50 ms polling loop.
    """
    deadline = time.monotonic() + XHTTP_SESSION_GRACE
    while (session.inflight_bytes > XHTTP_MAX_INFLIGHT_BYTES
           and not session.closed.is_set() and time.monotonic() < deadline):
        await asyncio.sleep(0.02)


async def _xhttp_uplink_stream(receive, send, session: "XhttpSession"):
    """stream-up: a single long POST whose body IS the whole uplink stream."""
    try:
        while True:
            event = await receive()
            et = event["type"]
            if et == "http.request":
                chunk = event.get("body") or b""
                if chunk:
                    if session.closed.is_set():
                        break
                    session.up_queue.put_nowait(chunk)
                    session.inflight_bytes += len(chunk)
                    # Same backpressure the packet-up path applies: without it a
                    # fast client streaming into a slow destination grows the
                    # queue without bound.
                    await _xhttp_backpressure(session)
                if not event.get("more_body", False):
                    break
            elif et == "http.disconnect":
                break
    except Exception:
        pass
    await _xhttp_send_simple(send, 200, [_xhttp_padding_header()])


async def _xhttp_uplink(scope, receive, send, session, session_id, seq_str):
    """Handle one uplink request: a packet-up POST (has <seq>) or a stream-up
    POST (no <seq>)."""
    if seq_str is None:
        await _xhttp_uplink_stream(receive, send, session)
        return
    try:
        seq = int(seq_str)
    except ValueError:
        await _xhttp_send_simple(send, 400, [_xhttp_padding_header()])
        return
    # A negative or absurd seq can only be junk; accepting it would let a single
    # request wedge the reorder window forever.
    if seq < 0 or seq > 2 ** 31:
        await _xhttp_send_simple(send, 400, [_xhttp_padding_header()])
        return

    body, too_large = await _xhttp_read_body(receive, XHTTP_MAX_POST_BYTES)
    if too_large:
        await _xhttp_send_simple(send, 413, [_xhttp_padding_header()])
        return

    ok = await _xhttp_feed_packet(session, seq, body)
    if not ok:
        await session.close()
        if xhttp_sessions.get(session_id) is session:
            xhttp_sessions.pop(session_id, None)
        await _xhttp_send_simple(send, 400, [_xhttp_padding_header()])
        return

    # Coarse backpressure: if the destination is slower than the client's uplink,
    # briefly stall the POST ack so buffered bytes can drain instead of piling up.
    await _xhttp_backpressure(session)

    await _xhttp_send_simple(send, 200, [_xhttp_padding_header()])


async def _xhttp_downlink(scope, receive, send, session, session_id):
    """Handle the downlink GET: stream upstream->client, and drive the tunnel
    (VLESS header parse, upstream connect, both pumps)."""
    # Only one downlink GET per session; a duplicate would double-drive the tunnel.
    if session.get_attached.is_set():
        await _xhttp_send_simple(send, 409, [_xhttp_padding_header()])
        return
    session.get_attached.set()

    conn_id = None
    started = False
    disconnect_task = None
    try:
        # Open the streaming response immediately so the edge stops buffering and
        # the client's stream is established (flush headers with a ZERO-length
        # body chunk — no bytes enter the VLESS stream).
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/event-stream"),
                (b"cache-control", b"no-store"),
                (b"x-accel-buffering", b"no"),
                (b"access-control-allow-origin", b"*"),
                _xhttp_padding_header(),
            ],
        })
        started = True
        await send({"type": "http.response.body", "body": b"", "more_body": True})

        # Watch for the client closing the (bodyless) GET request.
        async def watch_disconnect():
            try:
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        break
            except Exception:
                pass
            session.closed.set()
        disconnect_task = asyncio.create_task(watch_disconnect())

        # Reassemble the VLESS header from the ordered uplink stream.
        buffer = b""
        command = address = port = initial_payload = None
        while True:
            if buffer:
                parsed = parse_vless_header(buffer, session.expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    break
                if len(buffer) > XHTTP_HEADER_MAX:
                    raise ValueError("Header overflow")
            try:
                chunk = await asyncio.wait_for(session.up_queue.get(),
                                               timeout=XHTTP_SESSION_GRACE)
            except asyncio.TimeoutError:
                raise ValueError("uplink header timeout")
            if chunk is None:
                raise ValueError("uplink closed before header")
            session.consume(chunk)
            buffer += chunk

        reason = unsupported_reason(command, address)
        if reason:
            raise ValueError(reason)

        # Resolve + SSRF-vet once; we then dial exactly these addresses.
        ips = await resolve_destination(address, port)

        uid = session.link_uuid
        link_data = LINKS.get(uid)
        max_conn = link_data.get("max_connections", 0) if link_data else 0
        if max_conn > 0:
            already_connected = ip_ref_count.get(uid, {}).get(session.client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uid) >= max_conn:
                raise ValueError("connection limit reached")

        network = "udp" if command == VLESS_CMD_UDP else "tcp"
        conn_id = _register_connection(uid, session.client_ip, session, network,
                                       f"{address}:{port}")
        session.conn_id = conn_id
        account_traffic(conn_id, uid, len(buffer))

        async def recv_client():
            chunk = await session.up_queue.get()
            if chunk is None:
                return None
            session.consume(chunk)
            return chunk

        async def send_client(data: bytes):
            await send({"type": "http.response.body", "body": data, "more_body": True})

        # Downlink is the master: finish when upstream EOFs, the client
        # disconnects the GET, or the link is deleted (session.closed). The uplink
        # is only a feeder — in packet-up the client may keep the GET open after
        # it stops POSTing — so uplink completion must NOT tear the tunnel down.
        await run_vless_tunnel(command, address, port, ips, initial_payload,
                               recv_client, send_client, conn_id, uid,
                               up_is_master=False, stop=session.closed)

    except Exception as exc:
        record_error(f"xhttp: {exc}")
    finally:
        await session.close()
        if disconnect_task and not disconnect_task.done():
            disconnect_task.cancel()
        if started:
            try:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            except Exception:
                pass
        _unregister_connection(conn_id)
        if xhttp_sessions.get(session_id) is session:
            xhttp_sessions.pop(session_id, None)


async def xhttp_tunnel_asgi(scope, receive, send):
    """Raw-ASGI VLESS-over-XHTTP tunnel. Mounted at /<XHTTP_PATH_PREFIX>.

    Path inside the mount: /<linkuuid>/<sessionId>[/<seq>].
      GET  /<linkuuid>/<sessionId>          -> downlink stream
      POST /<linkuuid>/<sessionId>/<seq>    -> uplink packet (packet-up)
      POST /<linkuuid>/<sessionId>          -> uplink stream (stream-up)
    """
    if scope["type"] != "http":
        return

    method = scope.get("method", "GET")
    if method == "OPTIONS":
        # CORS preflight (Xray Browser Dialer / preflighted intermediaries).
        await _xhttp_send_simple(send, 200, [
            (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
            (b"access-control-allow-headers", b"*"),
            (b"access-control-max-age", b"86400"),
            _xhttp_padding_header(),
        ])
        return

    path = scope.get("path", "")
    # Newer Starlette versions keep the full path inside a Mount; strip the
    # prefix ourselves so routing works on either behaviour.
    mount_prefix = f"/{XHTTP_PATH_PREFIX}/"
    if path.startswith(mount_prefix):
        path = path[len(mount_prefix) - 1:]
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        await _xhttp_send_simple(send, 404)
        return
    link_uuid = parts[0]
    session_id = parts[1]
    seq_str = parts[2] if len(parts) >= 3 else None

    link_data = LINKS.get(link_uuid)
    if not link_data or not link_data["active"] or is_expired(link_data):
        await _xhttp_send_simple(send, 404)
        return

    expected_bytes = link_data.get("uuid_bytes")
    if not expected_bytes:
        try:
            expected_bytes = uuid_lib.UUID(link_uuid).bytes
        except Exception:
            await _xhttp_send_simple(send, 404)
            return
        link_data["uuid_bytes"] = expected_bytes

    client_ip = _xhttp_client_ip(scope)
    session = _xhttp_get_or_create(session_id, link_uuid, expected_bytes, client_ip)
    if session is None:
        # 503 tells a legitimate client to back off and retry with a new session.
        await _xhttp_send_simple(send, 503, [_xhttp_padding_header()])
        return

    if method == "GET":
        await _xhttp_downlink(scope, receive, send, session, session_id)
    elif method == "POST":
        await _xhttp_uplink(scope, receive, send, session, session_id, seq_str)
    else:
        await _xhttp_send_simple(send, 405)


# Mount the XHTTP engine on the shared port. It only claims the /<prefix>/*
# path, leaving the REST API, subscription, WS and UI routes untouched. Because
# XHTTP is plain HTTP/1.1, no HTTP/2 or TCP passthrough is needed.
app.mount(f"/{XHTTP_PATH_PREFIX}", xhttp_tunnel_asgi)

# ==========================================
# Dashboard & Login UI
# ==========================================
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

# ==========================================
# Server bootstrap (shared by main.py and deplexo_main.py)
# ==========================================
def build_server_config():
    """Hypercorn config: REST API, WebSocket and XHTTP on one $PORT over HTTP/1.1.

    XHTTP rides ordinary HTTP requests (a streaming GET + short POSTs), so —
    unlike the old gRPC transport — no end-to-end HTTP/2 and no second/TCP-
    passthrough port are required.
    """
    from hypercorn.config import Config

    config = Config()
    config.bind = [f"0.0.0.0:{CONFIG.port}"]
    config.workers = 1
    # Long-lived tunnels: don't let idle-timeouts kill active proxy streams
    # (notably the long streaming XHTTP downlink GET).
    config.keep_alive_timeout = 3600
    # Bursty clients (a YouTube page, a Telegram media grid) open dozens of
    # sockets at once; the default backlog of 100 dropped some of them.
    config.backlog = 2048
    config.graceful_timeout = 5
    if WS_PING_INTERVAL > 0:
        config.websocket_ping_interval = WS_PING_INTERVAL
    return config


def run_event_loop(coro):
    """Run with uvloop when available (2-4x faster socket I/O than asyncio)."""
    if _env_bool("REN_UVLOOP", True):
        try:
            import uvloop  # type: ignore
        except ImportError:
            uvloop = None
        if uvloop is not None:
            logger.info("Using uvloop event loop")
            if hasattr(uvloop, "run"):
                return uvloop.run(coro)
            uvloop.install()
    return asyncio.run(coro)


def run_server(asgi_app=None):
    from hypercorn.asyncio import serve
    run_event_loop(serve(asgi_app or app, build_server_config()))


if __name__ == "__main__":
    run_server(app)
