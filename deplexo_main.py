"""Deplexo entrypoint for the REN gateway.

Deplexo (https://deplexo.com) runs every app in a container with a READ-ONLY
root filesystem: only /tmp (100 MB, ephemeral) and the app's persistent data
mount (/data by default) are writable. It also does not inject a "public URL"
env var the way Render (RENDER_EXTERNAL_URL) or Railway (RAILWAY_PUBLIC_DOMAIN)
do, so main.get_domain() would fall back to "localhost" and every generated
vless:// link / subscription would point at localhost.

This module adapts main.py to that runtime WITHOUT changing its behaviour on
Render/Railway:

  * State lives in DATA_DIR (default /data, Deplexo's persistent mount). If that
    directory is not writable we fall back to /tmp/ren with a loud warning,
    instead of failing every save.
  * The public hostname comes from PUBLIC_DOMAIN (or DEPLEXO_DOMAIN) when set.
    Otherwise it is learned from the Host header of real panel / subscription
    requests that reach the app through Deplexo's HTTPS edge, and persisted
    next to the state file so it survives restarts.

Run it with `python deplexo_main.py` (that is what the Dockerfile does).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import tempfile

# Settings are read when main is imported, so the persistent-mount default has
# to be in place first. An explicit DATA_DIR from the dashboard always wins.
os.environ.setdefault("DATA_DIR", "/data")

import main  # noqa: E402

logger = logging.getLogger("REN-Deplexo")

# Explicit domain sources, highest priority first.
_EXPLICIT_DOMAIN_VARS = (
    "PUBLIC_DOMAIN",
    "DEPLEXO_DOMAIN",
    "RENDER_EXTERNAL_URL",
    "RAILWAY_PUBLIC_DOMAIN",
)
# Only these routes are hit by the operator or by client apps through the public
# edge, so their Host header is the real public hostname (not a health probe).
_LEARN_PREFIXES = ("/login", "/dashboard", "/api/login", "/sub/")
_DOMAIN_FILE = "deplexo_domain.txt"
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

_detected = {"host": ""}


# ------------------------------------------------------------------ storage --
def _writable(directory: str) -> bool:
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, f".ren-write-test-{os.getpid()}")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False


def resolve_data_dir() -> str:
    preferred = (main.CONFIG.data_dir or "").strip() or "/data"
    if _writable(preferred):
        return preferred
    fallback = os.path.join(tempfile.gettempdir(), "ren")
    if _writable(fallback):
        logger.warning(
            "DATA_DIR %s is not writable; using %s instead. State (links, panel "
            "password) will be LOST on every redeploy. Check the app's storage "
            "mount path in the Deplexo dashboard.", preferred, fallback)
        return fallback
    logger.error("Neither %s nor %s is writable; state cannot be saved.", preferred, fallback)
    return preferred


# ------------------------------------------------------------------- domain --
def explicit_domain() -> str:
    for var in _EXPLICIT_DOMAIN_VARS:
        value = (os.environ.get(var) or "").strip()
        if value:
            return main._clean_host(value)
    return ""


def get_domain() -> str:
    """Drop-in replacement for main.get_domain()."""
    return explicit_domain() or _detected["host"] or "localhost"


def _domain_file() -> str:
    return os.path.join(main.CONFIG.data_dir or tempfile.gettempdir(), _DOMAIN_FILE)


def _valid_public_host(host: str) -> bool:
    if not host or host == "localhost":
        return False
    try:
        ipaddress.ip_address(host)
        return False  # raw IPs are never the TLS/SNI name we want in links
    except ValueError:
        pass
    return bool(_HOST_RE.match(host))


def _load_detected() -> str:
    try:
        with open(_domain_file(), encoding="utf-8") as fh:
            host = fh.read().strip().lower()
    except OSError:
        return ""
    return host if _valid_public_host(host) else ""


def _save_detected(host: str) -> None:
    path = _domain_file()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(host)
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("Could not persist detected domain: %s", exc)


def host_from_scope(scope) -> str:
    """Public hostname of a request that came through the HTTPS edge, or ""."""
    headers = {}
    for key, value in scope.get("headers", []):
        headers.setdefault(key.lower(), value.decode("latin1"))
    raw = (headers.get(b"x-forwarded-host") or headers.get(b"host") or "").split(",")[0].strip()
    host = main._clean_host(raw).lower().split(":")[0]
    if not _valid_public_host(host):
        return ""
    proto = (headers.get(b"x-forwarded-proto") or scope.get("scheme") or "").split(",")[0].strip().lower()
    # Deplexo subdomains are always HTTPS; custom domains must prove it.
    if proto == "https" or host.endswith(".deplexo.com"):
        return host
    return ""


class PublicHostMiddleware:
    """Pure-ASGI (no buffering, so the XHTTP downlink is untouched)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope["type"] == "http"
                and scope.get("path", "").startswith(_LEARN_PREFIXES)
                and not explicit_domain()):
            host = host_from_scope(scope)
            if host and host != _detected["host"]:
                _detected["host"] = host
                logger.info("Public domain detected: %s", host)
                await asyncio.to_thread(_save_detected, host)
        await self.app(scope, receive, send)


# -------------------------------------------------------------------- setup --
def configure() -> None:
    main.CONFIG.data_dir = resolve_data_dir()
    # generate_vless_link(), the keep-alive ping and the cookie Secure flag all
    # look main.get_domain up at call time, so patching the module global is
    # enough.
    main.get_domain = get_domain
    _detected["host"] = _load_detected()
    domain = get_domain()
    if domain == "localhost":
        logger.warning(
            "Public domain unknown. Open /login once via your Deplexo URL (it is "
            "auto-detected) or set PUBLIC_DOMAIN, otherwise share links point "
            "at localhost.")
    else:
        logger.info("Public domain: %s", domain)
    logger.info("State file: %s", main._data_path())


configure()
application = PublicHostMiddleware(main.app)


def run() -> None:
    # Same server settings as main.py (WS keep-alive pings, large backlog,
    # long keep-alive for the XHTTP downlink, uvloop when installed).
    main.run_server(application)


if __name__ == "__main__":
    run()
