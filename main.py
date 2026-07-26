from __future__ import annotations

import asyncio
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
IDLE_TIMEOUT = 300

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
# Upstream TCP socket buffer size; modest so we stay inside PaaS memory limits.
SOCKET_BUFFER_BYTES = 262144
# Downstream read buffer bounds (adaptive between these two).
DOWNSTREAM_MIN_BUF = 16384
DOWNSTREAM_MAX_BUF = 262144

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

# ==========================================
# SSRF hardening: block internal / metadata destinations
# ==========================================
def _ip_is_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_link_local or ip.is_private
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

async def destination_allowed(address: str, port: int) -> bool:
    if CONFIG.allow_private_ranges:
        return True
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(address, port, type=socket.SOCK_STREAM)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        if _ip_is_blocked(info[4][0]):
            return False
    return True

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
    tasks = [
        asyncio.create_task(keep_alive()),
        asyncio.create_task(cleanup_traffic_task()),
        asyncio.create_task(periodic_save_task()),
        asyncio.create_task(prune_state_task()),
    ]
    logger.info(f"REN started on port {CONFIG.port}")
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
    if not verify_password(password, AUTH):
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
    if not verify_password(current, AUTH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    AUTH = make_auth(new)
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
MUX_ADDRESS_SUFFIX = "mux.cool"

def unsupported_reason(command: int, address: str) -> str | None:
    """Return a human-readable reason if this request cannot be served, else None.

    Both tunnels only bridge TCP. Previously a UDP request (command 2) was fed to
    asyncio.open_connection() anyway, so it half-worked in confusing ways, and a
    mux-enabled client (which dials the pseudo-host *.mux.cool) failed with an
    opaque DNS error. Naming the cause makes the panel's error log actionable.
    """
    if command == VLESS_CMD_UDP:
        return ("UDP over VLESS is not supported by this gateway; "
                "set the app's DNS/routing to TCP")
    if command != VLESS_CMD_TCP:
        return f"unsupported VLESS command: {command}"
    if address and address.lower().endswith(MUX_ADDRESS_SUFFIX):
        return "multiplexing (mux) is not supported; disable mux in the client"
    return None

async def check_quota(uid: str, extra_bytes: int) -> bool:
    link = LINKS.get(uid)
    if not link or not link.get("active") or is_expired(link):
        return False
    limit = link.get("limit_bytes", 0)
    if limit == 0:
        return True
    return (link.get("used_bytes", 0) + extra_bytes) <= limit

# --- Shared transport helpers (reused by both the WS and XHTTP tunnels) ------
def _apply_socket_opts(writer: asyncio.StreamWriter):
    """Tune an upstream TCP socket: keepalive, no-Nagle, modest buffers."""
    try:
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Disable Nagle: tunnelled traffic is already framed, so coalescing
            # adds latency (esp. for interactive TLS records) with no benefit.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Modest, PaaS-friendly socket buffers for smoother bulk throughput.
            for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, opt, SOCKET_BUFFER_BYTES)
                except OSError:
                    pass
    except Exception:
        pass

async def open_upstream(address: str, port: int):
    """Open the destination TCP connection and apply socket tuning.

    Shared by the WebSocket and XHTTP engines so both transports get identical
    connect behaviour, timeouts and socket options.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port), timeout=10.0
    )
    _apply_socket_opts(writer)
    return reader, writer

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

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await asyncio.wait_for(websocket.receive(), IDLE_TIMEOUT)
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            account_traffic(conn_id, link_uid, size, is_request=True)

            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    buf_size = DOWNSTREAM_MIN_BUF
    try:
        while True:
            data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
            if not data:
                break
            size = len(data)

            # Dynamically adjust buffer based on throughput saturation: grow when we
            # keep filling the buffer (bulk transfer), shrink when reads run small
            # (interactive/idle) so we don't pin large buffers per idle connection.
            if size == buf_size and buf_size < DOWNSTREAM_MAX_BUF:
                buf_size = min(DOWNSTREAM_MAX_BUF, buf_size * 2)
            elif size < buf_size / 2 and buf_size > DOWNSTREAM_MIN_BUF:
                buf_size = max(DOWNSTREAM_MIN_BUF, buf_size // 2)

            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            account_traffic(conn_id, link_uid, size)

            await websocket.send_bytes((VLESS_RESPONSE_HEADER + data) if first else data)
            first = False
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    except Exception:
        pass

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
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
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
        command = port = address = initial_payload = None
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

        # Only TCP is bridged; say so plainly instead of half-proxying.
        reason = unsupported_reason(command, address)
        if reason:
            error_logs.append({"error": f"ws: {reason}", "time": datetime.now().isoformat()})
            await websocket.close(code=1008, reason="unsupported request")
            return

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            await websocket.close(code=1008, reason="destination not allowed")
            return

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        ip_ref_count[uuid][client_ip] += 1

        account_traffic(conn_id, uuid, len(buffer), is_request=True)

        # Reuse the shared upstream-connect helper (open_connection + socket
        # tuning) so WS and XHTTP behave identically toward the destination.
        reader, writer = await open_upstream(address, port)

        if initial_payload:
            account_traffic(conn_id, uuid, len(initial_payload))
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Await the cancelled halves so their teardown (write_eof, etc.) completes
        # and no orphaned tasks linger between connections.
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                remove_ip_from_link(info.get("uuid"), info.get("ip"))

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
                    waited = 0.0
                    while (session.inflight_bytes > XHTTP_MAX_INFLIGHT_BYTES
                           and not session.closed.is_set()
                           and waited < XHTTP_SESSION_GRACE):
                        await asyncio.sleep(0.05)
                        waited += 0.05
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
    waited = 0.0
    while (session.inflight_bytes > XHTTP_MAX_INFLIGHT_BYTES
           and not session.closed.is_set() and waited < XHTTP_SESSION_GRACE):
        await asyncio.sleep(0.05)
        waited += 0.05

    await _xhttp_send_simple(send, 200, [_xhttp_padding_header()])


async def _xhttp_downlink(scope, receive, send, session, session_id):
    """Handle the downlink GET: stream upstream->client, and drive the tunnel
    (VLESS header parse, upstream connect, both pumps)."""
    # Only one downlink GET per session; a duplicate would double-drive the tunnel.
    if session.get_attached.is_set():
        await _xhttp_send_simple(send, 409, [_xhttp_padding_header()])
        return
    session.get_attached.set()

    writer = None
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
        header_ready = False
        while not header_ready:
            if buffer:
                parsed = parse_vless_header(buffer, session.expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    header_ready = True
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

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            raise ValueError("destination not allowed")

        uid = session.link_uuid
        link_data = LINKS.get(uid)
        max_conn = link_data.get("max_connections", 0) if link_data else 0
        if max_conn > 0:
            already_connected = ip_ref_count.get(uid, {}).get(session.client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uid) >= max_conn:
                raise ValueError("connection limit reached")

        conn_id = secrets.token_urlsafe(8)
        session.conn_id = conn_id
        connections[conn_id] = {"uuid": uid, "ip": session.client_ip,
                                "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = session
        ip_ref_count[uid][session.client_ip] += 1

        account_traffic(conn_id, uid, len(buffer), is_request=True)

        reader, writer = await open_upstream(address, port)

        if initial_payload:
            account_traffic(conn_id, uid, len(initial_payload))
            writer.write(initial_payload)
            await writer.drain()

        async def uplink_pump():
            # Reassembled uplink bytes -> upstream socket.
            try:
                while True:
                    chunk = await session.up_queue.get()
                    if chunk is None:
                        break
                    session.consume(chunk)
                    size = len(chunk)
                    if not await check_quota(uid, size):
                        break
                    account_traffic(conn_id, uid, size, is_request=True)
                    writer.write(chunk)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def downlink_pump():
            # Upstream socket -> the GET response body (raw bytes, no framing).
            # The VLESS response header MUST lead the stream. This was missing:
            # the client then read the first two payload bytes as version/addon
            # length and every XHTTP connection failed at the TLS handshake. WS
            # already did this in tcp_to_ws(); both transports now agree.
            first = True
            buf_size = DOWNSTREAM_MIN_BUF
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
                    if not data:
                        break
                    size = len(data)
                    if size == buf_size and buf_size < DOWNSTREAM_MAX_BUF:
                        buf_size = min(DOWNSTREAM_MAX_BUF, buf_size * 2)
                    elif size < buf_size / 2 and buf_size > DOWNSTREAM_MIN_BUF:
                        buf_size = max(DOWNSTREAM_MIN_BUF, buf_size // 2)
                    if not await check_quota(uid, size):
                        break
                    account_traffic(conn_id, uid, size)
                    if first:
                        data = VLESS_RESPONSE_HEADER + data
                        first = False
                    await send({"type": "http.response.body",
                                "body": data, "more_body": True})
            except Exception:
                pass
            finally:
                # An upstream that closes without sending anything still owes the
                # client a well-formed (empty) VLESS response.
                if first:
                    try:
                        await send({"type": "http.response.body",
                                    "body": VLESS_RESPONSE_HEADER, "more_body": True})
                    except Exception:
                        pass

        task_up = asyncio.create_task(uplink_pump())
        task_down = asyncio.create_task(downlink_pump())
        watch = asyncio.create_task(session.closed.wait())
        # Downlink is the master: finish when upstream EOFs (task_down), the
        # client disconnects the GET, or the link is deleted (session.closed).
        # The uplink is only a feeder — in packet-up the client may keep the GET
        # open after it stops POSTing — so uplink completion must NOT tear down
        # the still-active downlink.
        await asyncio.wait({task_down, watch}, return_when=asyncio.FIRST_COMPLETED)
        for t in (task_up, task_down, watch):
            if not t.done():
                t.cancel()
        await asyncio.gather(task_up, task_down, watch, return_exceptions=True)

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"xhttp: {exc}", "time": datetime.now().isoformat()})
    finally:
        session.closed.set()
        if disconnect_task and not disconnect_task.done():
            disconnect_task.cancel()
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if started:
            try:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            except Exception:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                remove_ip_from_link(info.get("uuid"), info.get("ip"))
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

    parts = [p for p in scope.get("path", "").split("/") if p]
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

if __name__ == "__main__":
    # Hypercorn serves the REST API, WebSocket transport and XHTTP transport on a
    # single $PORT over HTTP/1.1. XHTTP rides ordinary HTTP requests (a streaming
    # GET + short POSTs), so — unlike the old gRPC transport — no end-to-end
    # HTTP/2 and no second/TCP-passthrough port are required. This is exactly why
    # it survives PaaS/CDN edges (Railway, Render) that downgrade HTTP/2.
    from hypercorn.config import Config
    from hypercorn.asyncio import serve

    config = Config()
    config.bind = [f"0.0.0.0:{CONFIG.port}"]
    config.workers = 1
    # Long-lived tunnels: don't let idle-timeouts kill active proxy streams
    # (notably the long streaming XHTTP downlink GET).
    config.keep_alive_timeout = 3600
    asyncio.run(serve(app, config))
