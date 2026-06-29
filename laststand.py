#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sentinel Guard v27.0 "True Last Stand"
======================================
Single-file, production-grade async anti-DDoS Layer-7 reverse-proxy.

Runs on Linux + Windows + macOS. No C-extensions, no root required.

Usage:
  python3 app.py                              # env config, listen 9999
  BACKEND_URL=http://127.0.0.1:8080 \
    RATE_LIMIT=200 BURST_LIMIT=400 \
    ENABLE_WAF=1 python3 app.py
  python3 app.py --help
  python3 app.py --dry-run                    # validate config, exit
"""

# ====================================================================== #
# Imports
# ====================================================================== #
import asyncio
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import queue
import random
import re
import signal
import socket
import sys
import threading
import time
import uuid
from collections import OrderedDict, deque
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector, ClientError

try:
    from aiohttp import ClientPayloadError, ClientDisconnectedError
except ImportError:  # pragma: no cover
    ClientPayloadError = ClientError
    ClientDisconnectedError = ClientError


# ====================================================================== #
# Defaults (overridable via ENV)
# ====================================================================== #
DEFAULT_CACHE_MAXSIZE         = 100_000
DEFAULT_CACHE_TTL             = 3600

DEFAULT_RATE_LIMIT            = 200.0
DEFAULT_BURST_LIMIT           = 400.0     # was 3.0 in v26.2 for new IPs → fixed here
DEFAULT_MAX_CONN_PER_IP       = 30
DEFAULT_BAN_BASE              = 60.0
DEFAULT_BAN_MULT              = 2.0
DEFAULT_BAN_MAX               = 3600.0
DEFAULT_VIOLATIONS_DECAY      = 3600.0

DEFAULT_MAX_BODY_SIZE         = 1_048_576
DEFAULT_MAX_HEADER_SIZE       = 8192
DEFAULT_MAX_HEADERS           = 100
DEFAULT_MAX_URI_SIZE          = 8192
DEFAULT_MAX_TOTAL_HEADERS_SZ  = 65536

WAF_INSPECT_SIZE              = 8192
WAF_BODY_TIMEOUT             = 5.0
WAF_MAX_WORKERS               = 32
WAF_REGEX_TIMEOUT             = 1.0

DEFAULT_PER_IP_ENDPOINT_LIMIT = 120
DEFAULT_PER_IP_ENDPOINT_TTL   = 60

DEFAULT_GLOBAL_PER_IP_LIMIT   = 2000
DEFAULT_GLOBAL_PER_IP_TTL     = 60
DEFAULT_PER_IP_BURST_WINDOW   = 10.0       # seconds
DEFAULT_PER_IP_BURST_LIMIT    = 40         # requests per window

HEALTH_CHECK_LIMIT            = 30
HEALTH_CHECK_TTL              = 60

# Safe number of filedescriptors per platform (rough guidance)
MAX_SAFE_CONNS_LINUX          = 15000
MAX_SAFE_CONNS_WINDOWS        = 5000
MAX_SAFE_CONNS_DARWIN         = 8000

WAF_SEM_MULTIPLIER            = 2
OUTBOUND_SEM_BASE             = 100

DEFAULT_CLEANUP_INTERVAL      = 300

DEFAULT_CB_ERROR_THRESHOLD    = 5
DEFAULT_CB_WINDOW             = 60
DEFAULT_CB_PROBE_TIMEOUT      = 30

XFF_MAX_LENGTH                = 2048
XFF_MAX_IPS                   = 50
STREAM_CHUNK_SIZE             = 8192
BACKEND_TIMEOUT               = 30.0

KEEPALIVE_TIMEOUT             = 0            # critical for DDoS defence
SLOW_REQUEST_TIMEOUT          = 8

DEFAULT_LOG_QUEUE_MAXSIZE     = 5000

# Cache sizes / ttls
BAN_STORE_MAXSIZE             = int(os.getenv("BAN_STORE_MAXSIZE", "5000000"))
BAN_STORE_TTL                 = int(os.getenv("BAN_STORE_TTL", "86400"))
STATE_STORE_MAXSIZE           = int(os.getenv("STATE_STORE_MAXSIZE", "500000"))
STATE_STORE_TTL               = int(os.getenv("STATE_STORE_TTL", "3600"))
KEY_CACHE_MAXSIZE             = int(os.getenv("KEY_CACHE_MAXSIZE", "50000"))
KEY_CACHE_TTL                 = int(os.getenv("KEY_CACHE_TTL", "600"))
IP_OBJ_CACHE_MAXSIZE          = int(os.getenv("IP_OBJ_CACHE_MAXSIZE", "100000"))
IP_OBJ_CACHE_TTL              = int(os.getenv("IP_OBJ_CACHE_TTL", "3600"))
IP_CLASS_CACHE_MAXSIZE        = int(os.getenv("IP_CLASS_CACHE_MAXSIZE", "100000"))
IP_CLASS_CACHE_TTL            = int(os.getenv("IP_CLASS_CACHE_TTL", "3600"))
UNIQUE_QUERY_CACHE_MAXSIZE    = int(os.getenv("UNIQUE_QUERY_CACHE_MAXSIZE", "50000"))
UNIQUE_QUERY_CACHE_TTL        = int(os.getenv("UNIQUE_QUERY_CACHE_TTL", "300"))
UNIQUE_QUERY_THRESHOLD        = int(os.getenv("UNIQUE_QUERY_THRESHOLD", "50"))
UNIQUE_QUERY_HARD_LIMIT       = 500

SHARD_LOCK_COUNT              = 1024

BACKEND_MAX_RETRIES           = 2

MAX_JSON_ELEMENTS             = 1000
MAX_JSON_DEPTH                = 10

ALLOWED_HTTP_VERSIONS         = frozenset({(1, 0), (1, 1)})

SUSPICIOUS_CHARS              = frozenset("'<>()-=%&|`/\\ \t\r\n\x00*?!#.;")
_SQLI_KEYWORDS                = (
    "union", "select", "insert", "update", "delete", "drop",
    "sleep", "benchmark", "waitfor", "information_schema",
    "__proto__", "javascript", "<script",
)

GLOBAL_RATE_LIMIT             = float(os.getenv("GLOBAL_RATE_LIMIT", "5000"))
GLOBAL_BURST                  = float(os.getenv("GLOBAL_BURST", "10000"))

PER_IP_BACKEND_LIMIT          = int(os.getenv("PER_IP_BACKEND_LIMIT", "20"))
BAN_PERSIST_FILE              = os.getenv("BAN_PERSIST_FILE", "sentinel_bans.json")
BAN_PERSIST_INTERVAL          = 300

# Network entropy threshold (for scanner detection)
ENTROPY_THRESHOLD             = float(os.getenv("ENTROPY_THRESHOLD", "4.0"))

VERSION                       = "27.0"


# ====================================================================== #
# FD limit (Linux only, non-fatal)
# ====================================================================== #
def _raise_fd_limit_linux():
    if sys.platform == "win32":
        return MAX_SAFE_CONNS_WINDOWS
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = max(soft, 65535)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, target))
        except (ValueError, PermissionError):
            pass
        return min(target, 65535) - 100
    except Exception:
        return MAX_SAFE_CONNS_LINUX


MAX_SAFE_CONNS                = _raise_fd_limit_linux()

BLOCK_HEADERS                 = {"Connection": "close", "Cache-Control": "no-store"}


# ====================================================================== #
# LRU + TTL cache
# ====================================================================== #
class FastTTLCache:
    """Thread-safe (single event loop) OrderedDict-backed LRU+TTL cache."""
    __slots__ = ("_data", "_maxsize", "_ttl")

    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE, ttl: float = DEFAULT_CACHE_TTL):
        self._data: "OrderedDict[str, Tuple[object, float]]" = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl

    def _expire_cleanup(self, batch: int = 50):
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._data.items() if exp < now][:batch]
        for k in expired:
            self._data.pop(k, None)

    def get(self, key: str):
        item = self._data.get(key)
        if not item:
            return None
        if item[1] < time.monotonic():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return item[0]

    def set(self, key: str, value, keep_ttl: bool = False):
        if key in self._data:
            if keep_ttl:
                self._data[key] = (value, self._data[key][1])
                self._data.move_to_end(key)
                return
            self._data.pop(key, None)
        # opportunistic small batch eviction
        if len(self._data) >= self._maxsize:
            for _ in range(min(50, len(self._data))):
                self._data.pop(next(iter(self._data)), None)
        self._data[key] = (value, time.monotonic() + self._ttl)

    def __setitem__(self, key: str, value):
        self.set(key, value, keep_ttl=False)

    def __getitem__(self, key: str):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __len__(self) -> int:
        return len(self._data)

    def cleanup(self):
        now = time.monotonic()
        # chunked to avoid long event-loop stalls
        for _ in range(20):
            if not self._data:
                break
            expired = [k for k, (_, exp) in self._data.items() if exp < now][:200]
            if not expired:
                break
            for k in expired:
                self._data.pop(k, None)
        while len(self._data) > self._maxsize:
            self._data.pop(next(iter(self._data)), None)


# ====================================================================== #
# Configuration
# ====================================================================== #
class Config:
    """All configuration validated and re-bound at construction time."""

    @staticmethod
    def _safe_int(val, default: int, min_val: int = None, max_val: int = None) -> int:
        try:
            v = int(val) if val not in (None, "") else default
        except (ValueError, TypeError):
            v = default
        if min_val is not None and v < min_val:
            v = min_val
        if max_val is not None and v > max_val:
            v = max_val
        return v

    @staticmethod
    def _safe_float(val, default: float, min_val: float = None, max_val: float = None) -> float:
        try:
            v = float(val) if val not in (None, "") else default
        except (ValueError, TypeError):
            v = default
        if min_val is not None and v < min_val:
            v = min_val
        if max_val is not None and v > max_val:
            v = max_val
        return v

    @staticmethod
    def _parse_networks(raw: str) -> Set:
        result: Set = set()
        if not raw:
            return result
        for entry in raw.split(","):
            e = entry.strip()
            if not e:
                continue
            try:
                result.add(ipaddress.ip_network(e, strict=False))
            except ValueError:
                print(f"Warning: invalid IP/network: {e}", file=sys.stderr)
        return result

    def __init__(self, overrides: Optional[Dict[str, Any]] = None):
        ov = dict(overrides or {})

        def ovget(k, default):
            return ov.get(k, os.getenv(k, default))

        self.listen_host = str(ovget("SENTINEL_HOST", "0.0.0.0"))
        self.listen_port = self._safe_int(ovget("SENTINEL_PORT", None), 9999, 1, 65535)

        backend_raw = str(ovget("BACKEND_URL", "http://127.0.0.1:8888")).rstrip("/")
        parsed = urlparse(backend_raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"BACKEND_URL must be http(s)://host:port, got {backend_raw!r}")
        self.backend_url = backend_raw

        self.rate_limit              = self._safe_float(ovget("RATE_LIMIT", None), DEFAULT_RATE_LIMIT, 1.0)
        self.burst_limit             = self._safe_float(ovget("BURST_LIMIT", None), DEFAULT_BURST_LIMIT, 1.0)
        self.max_conn_per_ip         = self._safe_int(ovget("MAX_CONN_IP", None), DEFAULT_MAX_CONN_PER_IP, 1)
        self.max_body_size           = self._safe_int(ovget("MAX_BODY_SIZE", None), DEFAULT_MAX_BODY_SIZE, 1)

        self.ban_base                = self._safe_float(ovget("BAN_BASE", None), DEFAULT_BAN_BASE, 1.0)
        self.ban_mult                = self._safe_float(ovget("BAN_MULT", None), DEFAULT_BAN_MULT, 1.0)
        self.ban_max                 = self._safe_float(ovget("BAN_MAX", None), DEFAULT_BAN_MAX, 1.0)
        self.violations_decay        = self._safe_float(ovget("VIOLATIONS_DECAY", None),
                                                         DEFAULT_VIOLATIONS_DECAY, 60.0)

        self.trusted_proxies         = self._parse_networks(ovget("TRUSTED_PROXIES", "127.0.0.1,::1"))
        self.whitelist_ips           = self._parse_networks(ovget("WHITELIST", ""))
        self.blacklist_ips           = self._parse_networks(ovget("BLACKLIST", ""))

        env_methods = ovget("ALLOWED_METHODS", "GET,POST,HEAD,PUT,DELETE,OPTIONS,PATCH")
        self.allowed_methods = {m.strip().upper() for m in env_methods.split(",") if m.strip()}
        self.allowed_methods.difference_update({"CONNECT", "TRACE", "TRACK"})

        self.max_header_size         = self._safe_int(ovget("MAX_HEADER_SIZE", None), DEFAULT_MAX_HEADER_SIZE, 1)
        self.max_headers             = self._safe_int(ovget("MAX_HEADERS", None), DEFAULT_MAX_HEADERS, 1)
        self.max_uri_size            = self._safe_int(ovget("MAX_URI_SIZE", None), DEFAULT_MAX_URI_SIZE, 1)
        self.max_total_headers_size  = self._safe_int(ovget("MAX_TOTAL_HEADERS_SIZE", None),
                                                      DEFAULT_MAX_TOTAL_HEADERS_SZ, 1)

        self.bad_ua_strings = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "botnet", "dirbuster", "wfuzz",
            "skipfish", "whatweb",
        )
        custom_ua = ovget("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_strings = self.bad_ua_strings + tuple(
                p.strip().lower() for p in custom_ua.split(",") if p.strip()
            )

        self.enable_waf              = (ovget("ENABLE_WAF", "1") in ("1", "true", "True", "yes"))
        self.waf_body_timeout        = self._safe_float(ovget("WAF_BODY_TIMEOUT", None),
                                                         WAF_BODY_TIMEOUT, 0.1)
        self.enable_firewall         = (ovget("ENABLE_FIREWALL", "0") in ("1", "true", "True", "yes"))

        self.backend_pool_size       = self._safe_int(ovget("BACKEND_POOL_SIZE", None),
                                                     OUTBOUND_SEM_BASE, 1)
        self.verify_ssl              = (ovget("VERIFY_SSL", "1") in ("1", "true", "True", "yes"))
        self.backend_timeout         = self._safe_float(ovget("BACKEND_TIMEOUT", None),
                                                         BACKEND_TIMEOUT, 1.0)

        self.cb_error_threshold      = self._safe_int(ovget("CB_ERRORS", None),
                                                       DEFAULT_CB_ERROR_THRESHOLD, 1)
        self.cb_window               = self._safe_int(ovget("CB_WINDOW", None),
                                                       DEFAULT_CB_WINDOW, 1)
        self.cb_probe_timeout        = self._safe_int(ovget("CB_TIMEOUT", None),
                                                       DEFAULT_CB_PROBE_TIMEOUT, 1)

        self.cleanup_interval        = self._safe_int(ovget("CLEANUP_INTERVAL", None),
                                                       DEFAULT_CLEANUP_INTERVAL, 1)
        self.log_level               = str(ovget("LOG_LEVEL", "INFO")).upper()
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            self.log_level = "INFO"
        self.log_file                = str(ovget("LOG_FILE", "sentinel.log"))
        self.log_queue_maxsize       = self._safe_int(ovget("LOG_QUEUE_MAXSIZE", None),
                                                       DEFAULT_LOG_QUEUE_MAXSIZE, 100)
        self.audit_log_file          = str(ovget("AUDIT_LOG_FILE", "sentinel_audit.log"))

        self.global_per_ip_limit     = self._safe_int(ovget("GLOBAL_PER_IP_LIMIT", None),
                                                       DEFAULT_GLOBAL_PER_IP_LIMIT, 1)
        self.server_header           = str(ovget("SERVER_HEADER", "Sentinel-Guard"))
        self.shutdown_timeout        = self._safe_float(ovget("SHUTDOWN_TIMEOUT", None),
                                                         30.0, 1.0)
        self.ipv6_prefix             = self._safe_int(ovget("IPV6_PREFIX", None), 64, 16, 128)

        raw_hosts = ovget("ALLOWED_HOSTS", "")
        self.allowed_hosts           = {h.strip().lower() for h in raw_hosts.split(",") if h.strip()}

        self.health_check_enabled    = (ovget("BACKEND_HEALTH_CHECK", "0") in
                                        ("1", "true", "True", "yes"))
        self.health_path             = str(ovget("BACKEND_HEALTH_PATH", "/health")).strip()
        if not self.health_path.startswith("/"):
            self.health_path = "/" + self.health_path

        self.per_ip_endpoint_limit   = self._safe_int(ovget("PER_IP_ENDPOINT_LIMIT", None),
                                                       DEFAULT_PER_IP_ENDPOINT_LIMIT, 1)
        self.per_ip_backend_limit    = PER_IP_BACKEND_LIMIT
        self.global_rate_limit       = GLOBAL_RATE_LIMIT
        self.global_burst            = GLOBAL_BURST
        self.ban_persist_file        = BAN_PERSIST_FILE

        # New in v27.0
        self.per_ip_burst_window     = self._safe_float(ovget("PER_IP_BURST_WINDOW", None),
                                                         DEFAULT_PER_IP_BURST_WINDOW, 1.0)
        self.per_ip_burst_limit      = self._safe_int(ovget("PER_IP_BURST_LIMIT", None),
                                                       DEFAULT_PER_IP_BURST_LIMIT, 1)
        self.metrics_token           = str(ovget("METRICS_TOKEN", ""))   # if set, /metrics requires ?token=
        self.entropy_threshold       = self._safe_float(ovget("ENTROPY_THRESHOLD", None),
                                                          ENTROPY_THRESHOLD, 1.0)


# ====================================================================== #
# Logging (non-blocking, drop when full)
# ====================================================================== #
class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    def emit(self, record):
        try:
            self.enqueue(record)
        except queue.Full:
            pass


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "ip", "reason", "method", "path", "duration", "violations"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry)


class SafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def doRollover(self):
        try:
            super().doRollover()
        except Exception:
            pass


def setup_logging(cfg: Config):
    log_q: "queue.Queue" = queue.Queue(maxsize=cfg.log_queue_maxsize)
    audit_q: "queue.Queue" = queue.Queue(maxsize=cfg.log_queue_maxsize)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    qh = NonBlockingQueueHandler(log_q)
    logger = logging.getLogger("Sentinel")
    logger.setLevel(cfg.log_level)
    logger.handlers.clear()
    logger.addHandler(qh)
    logger.propagate = False

    aqh = NonBlockingQueueHandler(audit_q)
    audit_logger = logging.getLogger("Sentinel.Audit")
    audit_logger.setLevel("WARNING")
    audit_logger.handlers.clear()
    audit_logger.addHandler(aqh)
    audit_logger.propagate = False

    try:
        with open(cfg.log_file, "a"):
            pass
    except OSError:
        print(f"FATAL: cannot write to {cfg.log_file}", file=sys.stderr)
        sys.exit(1)

    fh = SafeRotatingFileHandler(cfg.log_file, maxBytes=100 * 1024 * 1024,
                                 backupCount=5, encoding="utf-8")
    sh = logging.StreamHandler()
    fh.setFormatter(fmt)
    sh.setFormatter(fmt)
    listener = logging.handlers.QueueListener(log_q, fh, sh, respect_handler_level=True)
    listener.start()

    afh = SafeRotatingFileHandler(cfg.audit_log_file, maxBytes=100 * 1024 * 1024,
                                  backupCount=5, encoding="utf-8")
    afh.setFormatter(JSONFormatter())
    audit_listener = logging.handlers.QueueListener(audit_q, afh, respect_handler_level=True)
    audit_listener.start()

    return logger, audit_logger, listener, audit_listener, log_q, audit_q


# ====================================================================== #
# WAF engine
# ====================================================================== #
_SQLI_PATTERNS = [
    re.compile(r"(?<![a-zA-Z0-9_])(sleep|benchmark|pg_sleep|waitfor)\s*\(", re.IGNORECASE),
    re.compile(r"\bunion\b[^a-zA-Z0-9_]{1,50}\b(?:all|distinct)?\b\s*select\b", re.IGNORECASE),
    re.compile(r"\bselect\b[^a-zA-Z0-9_]{0,50}\bfrom\b", re.IGNORECASE),
    re.compile(r"\binsert\b[^a-zA-Z0-9_]{0,50}\binto\b", re.IGNORECASE),
    re.compile(r"\bupdate\b[^a-zA-Z0-9_]{0,50}\bset\b", re.IGNORECASE),
    re.compile(r"\bdelete\b[^a-zA-Z0-9_]{0,50}\bfrom\b", re.IGNORECASE),
    re.compile(r"\bdrop\b[^a-zA-Z0-9_]{0,50}\btable\b", re.IGNORECASE),
    re.compile(r"'\s*(or|and)\s+['\d]", re.IGNORECASE),
    re.compile(r"(?:--|#)\s|/\*", re.IGNORECASE),
    re.compile(r";\s*(drop|alter|create|insert|update|delete)\b", re.IGNORECASE),
    re.compile(r"\b(information_schema|sysobjects|syscolumns)\b", re.IGNORECASE),
    re.compile(r"(?:\.\./)|(?:\.\.\\)|(%2e%2e%2f)|(%2e%2e/)|(\.\.%2f)|(%2e%2e%5c)", re.IGNORECASE),
    re.compile(r"\b(or|and)\b\s+[\d'\"\s]+\s*=\s*[\d'\"\s]+", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src\s*=\s*['\"]?javascript:", re.IGNORECASE),
    re.compile(r"<\s*(iframe|object|embed|svg|math)", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\s*\.\s*(cookie|write|location)", re.IGNORECASE),
    re.compile(r"<\s*meta[^>]+http-equiv\s*=\s*['\"]?refresh", re.IGNORECASE),
]

_PROTO_POLLUTION_PATTERNS = [
    re.compile(r"__proto__", re.IGNORECASE),
    re.compile(r"constructor\[", re.IGNORECASE),
    re.compile(r"\bprototype\b", re.IGNORECASE),
]

# Path-entropy regex strips before scoring
_PATH_NONWORD = re.compile(r"[^a-z0-9]")


def _decode_aggressive(data: str) -> str:
    cleaned = data
    for _ in range(3):
        new = unquote(cleaned)
        if new == cleaned:
            break
        cleaned = new
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
    return cleaned


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())


def waf_check(data: str) -> Optional[str]:
    if not data:
        return None
    data = data[:512]            # hard cap to keep regex linear
    try:
        cleaned = _decode_aggressive(data)
    except Exception:
        return "ERROR"

    try:
        for p in _SQLI_PATTERNS:
            if p.search(cleaned):
                return "SQLi"
        for p in _XSS_PATTERNS:
            if p.search(cleaned):
                return "XSS"
        for p in _PROTO_POLLUTION_PATTERNS:
            if p.search(cleaned):
                return "PROTO"
    except Exception:
        return "ERROR"
    return None


async def async_waf_check(data: str, executor, sem: Optional["asyncio.Semaphore"] = None) -> Optional[str]:
    if not data:
        return None
    # Fast path: no suspicious chars and no SQL keywords → skip WAF
    low = data.lower()
    if not any(c in SUSPICIOUS_CHARS for c in data) and not any(k in low for k in _SQLI_KEYWORDS):
        return None
    loop = asyncio.get_running_loop()
    if sem is not None:
        if not try_acquire(sem):
            return "WAF_OVERLOAD"
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(executor, waf_check, data),
                timeout=WAF_REGEX_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return "WAF_TIMEOUT"
        finally:
            sem.release()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(executor, waf_check, data),
            timeout=WAF_REGEX_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return "WAF_TIMEOUT"


def _json_parse_and_scan(text: str) -> Optional[str]:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return _json_scan(obj)


def _json_scan(obj, max_depth: int = MAX_JSON_DEPTH, _count=None) -> Optional[str]:
    if _count is None:
        _count = [0]
    if _count[0] > MAX_JSON_ELEMENTS or max_depth <= 0:
        return "JSON_BOMB"
    _count[0] += 1
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                r = waf_check(k)
                if r:
                    return r
            r = _json_scan(v, max_depth - 1, _count)
            if r:
                return r
    elif isinstance(obj, list):
        for item in obj:
            r = _json_scan(item, max_depth - 1, _count)
            if r:
                return r
    elif isinstance(obj, str):
        return waf_check(obj)
    return None


# ====================================================================== #
# Rate-limiter: per-IP token bucket + prefix banning + global cap + burst window
# ====================================================================== #
class IPState:
    __slots__ = (
        "tokens", "last_time", "violations", "last_violation_time",
        "active_conns", "first_seen", "burst_window_hits",
    )

    def __init__(self, burst: float):
        self.tokens = burst
        self.last_time = time.monotonic()
        self.violations = 0
        self.last_violation_time = 0.0
        self.active_conns = 0
        self.first_seen = time.monotonic()
        self.burst_window_hits: deque = deque()


class RateLimiter:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._store         = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=STATE_STORE_TTL)
        self._ban_store     = FastTTLCache(maxsize=BAN_STORE_MAXSIZE, ttl=BAN_STORE_TTL)
        self._key_cache     = FastTTLCache(maxsize=KEY_CACHE_MAXSIZE, ttl=KEY_CACHE_TTL)
        self._locks_pool: List[asyncio.Lock] = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]
        self._global_state  = IPState(cfg.global_burst)
        self._global_lock   = asyncio.Lock()

    # ---- helpers ---- #
    def _prefix_key(self, ip_str: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                net = ipaddress.ip_network(f"{ip_str}/{self.cfg.ipv6_prefix}", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(net.network_address)
        except ValueError:
            return ip_str

    def _shard_lock(self, key: str) -> asyncio.Lock:
        return self._locks_pool[hash(key) % SHARD_LOCK_COUNT]

    def _get(self, ip: str) -> IPState:
        state = self._store.get(ip)
        if state is None:
            # FIX v27.0: new IPs get full burst, not 3.0 — prevents false-bans
            state = IPState(self.cfg.burst_limit)
            self._store.set(ip, state)
        else:
            if state.first_seen > 0 and (time.monotonic() - state.first_seen) > 300:
                if state.violations == 0:
                    state.tokens = self.cfg.burst_limit
                state.first_seen = 0.0
        return state

    async def _check_global(self) -> bool:
        async with self._global_lock:
            now = time.monotonic()
            gs = self._global_state
            elapsed = now - gs.last_time
            gs.last_time = now
            gs.tokens = min(self.cfg.global_burst,
                            gs.tokens + elapsed * self.cfg.global_rate_limit)
            if gs.tokens >= 1.0:
                gs.tokens -= 1.0
                return True
            return False

    def _burst_window_violated(self, state: IPState) -> bool:
        window = self.cfg.per_ip_burst_window
        limit = self.cfg.per_ip_burst_limit
        now = time.monotonic()
        hits = state.burst_window_hits
        while hits and hits[0] < now - window:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        return False

    # ---- public API ---- #
    async def check_and_acquire(
        self, ip: str, bypass_ban: bool = False, bypass_ban_writes: bool = False,
    ) -> Tuple[bool, float, str]:
        if not await self._check_global():
            return False, 0.0, "global_rate_limited"

        prefix_key = self._prefix_key(ip)
        lock = self._shard_lock(prefix_key)

        # FIX v27.0: use asyncio.Lock while held synchronously (no wait_for inside)
        async with lock:
            now = time.monotonic()
            if not bypass_ban:
                ban_until = self._ban_store.get(prefix_key)
                if ban_until and ban_until > now:
                    return False, 0.0, "banned"

            s = self._get(ip)
            if s.active_conns >= self.cfg.max_conn_per_ip:
                return False, 0.0, "too_many_connections"

            # FIX v27.0: rolling burst-window to catch burst-of-1 attacks
            if not bypass_ban and self._burst_window_violated(s):
                s.violations = min(s.violations + 1, 100)
                s.last_violation_time = now
                ban_time = min(self.cfg.ban_max,
                               self.cfg.ban_base * (self.cfg.ban_mult ** (s.violations - 1)))
                self._ban_store.set(prefix_key, now + ban_time)
                return False, 0.0, "burst_window"

            s.active_conns += 1

            elapsed = now - s.last_time
            s.last_time = now
            s.tokens = min(self.cfg.burst_limit, s.tokens + elapsed * self.cfg.rate_limit)
            if s.tokens >= 1.0:
                s.tokens -= 1.0
                return True, s.tokens, ""

            if bypass_ban_writes:
                s.active_conns -= 1
                return False, 0.0, "rate_limited"

            if now - s.last_violation_time > self.cfg.violations_decay:
                s.violations = 0
            s.violations = min(s.violations + 1, 100)
            s.last_violation_time = now

            ban_time = min(self.cfg.ban_max,
                           self.cfg.ban_base * (self.cfg.ban_mult ** (s.violations - 1)))
            self._ban_store.set(prefix_key, now + ban_time)
            s.active_conns -= 1

            if s.violations == 1 or s.violations % 10 == 0:
                logger.warning("IP %s banned %.0fs (violations: %d)", ip, ban_time, s.violations)
                audit_logger.warning("BAN %s %.0fs violations=%d", ip, ban_time, s.violations)
            return False, 0.0, "rate_limited"

    async def dec_conn(self, ip: str):
        lock = self._shard_lock(ip)
        async with lock:
            s = self._store.get(ip)
            if s and s.active_conns > 0:
                s.active_conns -= 1

    async def force_ban(self, ip: str, duration: float = None, request_id: str = None):
        prefix_key = self._prefix_key(ip)
        if duration is None:
            duration = self.cfg.ban_max
        lock = self._shard_lock(prefix_key)
        async with lock:
            self._ban_store.set(prefix_key, time.monotonic() + duration)
            s = self._store.get(ip)
            if s:
                s.tokens = 0.0
                s.violations = 100
                s.last_time = time.monotonic()
        audit_logger.warning("FORCE_BAN %s %.0fs", ip, duration,
                             extra={"request_id": request_id or "n/a",
                                    "ip": ip, "reason": "force_ban",
                                    "duration": duration})

    def is_banned(self, ip: str) -> bool:
        prefix_key = self._prefix_key(ip)
        ban_until = self._ban_store.get(prefix_key)
        return bool(ban_until) and ban_until > time.monotonic()

    def is_new_ip(self, ip: str) -> bool:
        state = self._store.get(ip)
        if state is None:
            return True
        return state.first_seen > 0 and (time.monotonic() - state.first_seen) < 300

    def ban_status(self, ip: str) -> Optional[float]:
        return self._ban_store.get(self._prefix_key(ip))

    # ---- ban persistence ---- #
    def save_bans(self):
        try:
            data = {}
            now = time.monotonic()
            # iterate via snapshot of items to avoid mutation during iteration
            for k, (val, _) in list(self._ban_store._data.items()):
                if isinstance(val, (int, float)) and val > now:
                    data[k] = float(val - now)
            with open(self.cfg.ban_persist_file + ".tmp", "w") as f:
                json.dump(data, f)
            os.replace(self.cfg.ban_persist_file + ".tmp", self.cfg.ban_persist_file)
        except Exception as e:
            logger.error("save_bans failed: %s", e)

    def load_bans(self):
        if not os.path.exists(self.cfg.ban_persist_file):
            return 0
        try:
            with open(self.cfg.ban_persist_file, "r") as f:
                data = json.load(f)
            now = time.monotonic()
            for k, remaining in data.items():
                self._ban_store.set(k, now + float(remaining))
            return len(data)
        except Exception as e:
            logger.error("load_bans failed: %s", e)
            return 0


# ====================================================================== #
# Circuit breaker
# ====================================================================== #
class CircuitBreaker:
    def __init__(self, err_thr: int, window: float, probe_timeout: float):
        self.err_thr = err_thr
        self.window = window
        self.probe_timeout = probe_timeout
        self._errors: deque = deque()
        self._last_failure = time.monotonic()
        self._state = "CLOSED"
        self._probe_in_progress = False
        self._probe_start_time = 0.0
        self._lock = asyncio.Lock()

    def record_error(self):
        now = time.monotonic()
        self._errors.append(now)
        while self._errors and self._errors[0] < now - self.window:
            self._errors.popleft()
        while len(self._errors) > self.err_thr + 50:
            self._errors.popleft()
        self._last_failure = now
        if self._state == "HALF_OPEN":
            self._state = "OPEN"
            self._probe_in_progress = False
            logger.warning("Circuit breaker OPEN (probe failed)")
        elif self._state == "CLOSED" and len(self._errors) >= self.err_thr:
            self._state = "OPEN"
            logger.warning("Circuit breaker OPEN (error threshold %d)", self.err_thr)

    def record_success(self):
        if self._state == "HALF_OPEN":
            self._state = "CLOSED"
            self._errors.clear()
            self._probe_in_progress = False
            logger.info("Circuit breaker CLOSED (probe succeeded)")

    async def allow(self) -> bool:
        now = time.monotonic()
        if self._state == "CLOSED":
            return True
        if self._state == "OPEN":
            if now - self._last_failure < self.probe_timeout:
                return False
            async with self._lock:
                if self._state == "OPEN" and not self._probe_in_progress:
                    self._probe_in_progress = True
                    self._state = "HALF_OPEN"
                    self._probe_start_time = now
                    return True
            return False
        if self._state == "HALF_OPEN":
            if now - self._probe_start_time > self.probe_timeout:
                async with self._lock:
                    if self._state == "HALF_OPEN":
                        self._state = "OPEN"
                        self._probe_in_progress = False
                        self._last_failure = now
                        logger.error("Circuit breaker probe timed out")
                return False
            return False


# ====================================================================== #
# Non-blocking async acquire (FIX v27.0.1)
# ====================================================================== #
# In Python 3.12+, asyncio.wait_for(coro, timeout=0) and asyncio.timeout(0)
# BOTH immediately cancel the wrapped task before the coroutine runs, so they
# can NEVER be used as non-blocking fast-path checks (the coroutine never
# executes). The previous implementation relied on this pattern in 6 places,
# causing legitimate traffic to be silently aborted. We replace it with a
# synchronous state-inspection helper that uses asyncio's stable internals
# (which have not changed since 3.5) — that is, asyncio.Lock._locked /
# asyncio.Semaphore._value plus a waiter-queue inspection to avoid starvation.
def try_acquire(lock_or_sem) -> bool:
    """Non-blocking, zero-yield acquire for asyncio Lock and Semaphore.
    Returns True if acquired (caller MUST release), False if contended.
    Safe to call from a sync context — does not yield control."""
    # asyncio.Lock: check via public API
    if hasattr(lock_or_sem, "locked"):
        if lock_or_sem.locked():
            return False
        # Don't steal the lock if other coroutines are queued for it
        waiters = getattr(lock_or_sem, "_waiters", None)
        if waiters and any(
            not getattr(w, "cancelled", lambda: False)() for w in waiters
        ):
            return False
        lock_or_sem._locked = True
        return True
    # asyncio.Semaphore: inspect counter
    if hasattr(lock_or_sem, "_value"):
        if lock_or_sem._value <= 0:
            return False
        waiters = getattr(lock_or_sem, "_waiters", None)
        if waiters and any(
            not getattr(w, "cancelled", lambda: False)() for w in waiters
        ):
            return False
        lock_or_sem._value -= 1
        return True
    return False


# ====================================================================== #
# Proxy / middleware
# ====================================================================== #
class SentinelApp:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session: Optional[ClientSession] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.cb: Optional[CircuitBreaker] = None
        self._counter_locks: Optional[List[asyncio.Lock]] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._health_task: Optional[asyncio.Task] = None
        self._persist_task: Optional[asyncio.Task] = None
        self._backend_healthy = True

        self.ip_obj_cache            = FastTTLCache(IP_OBJ_CACHE_MAXSIZE, IP_OBJ_CACHE_TTL)
        self.ip_class_cache          = FastTTLCache(IP_CLASS_CACHE_MAXSIZE, IP_CLASS_CACHE_TTL)
        self.per_ip_endpoint_cache   = FastTTLCache(STATE_STORE_MAXSIZE, DEFAULT_PER_IP_ENDPOINT_TTL)
        self.global_per_ip_cache     = FastTTLCache(STATE_STORE_MAXSIZE, DEFAULT_GLOBAL_PER_IP_TTL)
        self.unique_query_cache      = FastTTLCache(UNIQUE_QUERY_CACHE_MAXSIZE, UNIQUE_QUERY_CACHE_TTL)
        self._per_ip_outbound_cache  = FastTTLCache(STATE_STORE_MAXSIZE, 300)
        self._per_ip_outbound_lock   = asyncio.Lock()

        parsed_backend = urlparse(cfg.backend_url)
        host = parsed_backend.hostname or "localhost"
        if parsed_backend.port:
            host = f"{host}:{parsed_backend.port}"
        self.backend_host = host

        self._active_inbound = 0
        self._active_outbound = 0
        self._metrics = {}
        self._reset_metrics()
        self.waf_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None

    # ---- metrics ---- #
    def _reset_metrics(self):
        self._metrics = {
            "requests": 0, "blocked": 0,
            "waf_hits": 0, "waf_overloads": 0,
            "bans": 0, "slow_aborts": 0,
            "circuit_rejects": 0, "rate_blocked": 0,
            "burst_window_blocks": 0,
            "scraper_blocks": 0, "global_blocks": 0,
        }

    def _get_counter_lock(self, key: str) -> asyncio.Lock:
        return self._counter_locks[hash(key) % SHARD_LOCK_COUNT]

    @staticmethod
    async def _try_lock_immediate(lock: asyncio.Lock) -> bool:
        # FIX v27.0.1: use the synchronous try_acquire helper — wait_for
        # with timeout=0 is broken on Python 3.12+ (cancels before coro runs).
        return try_acquire(lock)

    def _audit_extra(self, request) -> Dict:
        return {
            "request_id": request.get("request_id", ""),
            "ip": getattr(request, "_audit_ip", "n/a"),
            "method": request.method,
            "path": (request.path_qs or "")[:512],
        }

    # ---- lifecycle ---- #
    async def startup(self, app: web.Application):
        global INBOUND_CONN_SEM, WAF_SEM, OUTBOUND_REQ_SEM
        if self._shutdown_event is None:
            self._shutdown_event = asyncio.Event()
        if self._counter_locks is None:
            self._counter_locks = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]
        if INBOUND_CONN_SEM is None:
            INBOUND_CONN_SEM = asyncio.Semaphore(min(MAX_SAFE_CONNS, 65535))
        if WAF_SEM is None:
            WAF_SEM = asyncio.Semaphore(self.cfg.backend_pool_size * WAF_SEM_MULTIPLIER)
        if OUTBOUND_REQ_SEM is None:
            OUTBOUND_REQ_SEM = asyncio.Semaphore(self.cfg.backend_pool_size)

        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(self.cfg)
            n = self.rate_limiter.load_bans()
            logger.info("Loaded %d persistent bans", n)

        if self.cb is None:
            self.cb = CircuitBreaker(
                self.cfg.cb_error_threshold,
                self.cfg.cb_window,
                self.cfg.cb_probe_timeout,
            )

        if self.waf_executor is None:
            self.waf_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=WAF_MAX_WORKERS,
                thread_name_prefix="sentinel-waf",
            )

        connector = TCPConnector(limit=self.cfg.backend_pool_size, ttl_dns_cache=300,
                                 enable_cleanup_closed=True)
        timeout = ClientTimeout(total=self.cfg.backend_timeout,
                                connect=5, sock_read=10, sock_connect=5)
        self.session = ClientSession(connector=connector, timeout=timeout,
                                     auto_decompress=False)

        app["session"] = self.session
        app["waf_executor"] = self.waf_executor
        self._cleanup_task  = asyncio.create_task(self._cleanup_loop())
        self._persist_task  = asyncio.create_task(self._persist_loop())
        if self.cfg.health_check_enabled:
            self._health_task = asyncio.create_task(self._health_check_loop())
        logger.info("Startup complete — v%s on %s:%d → %s",
                    VERSION, self.cfg.listen_host, self.cfg.listen_port,
                    self.cfg.backend_url)

    async def shutdown(self, app: web.Application):
        self._shutdown_event.set()
        for t in (self._health_task, self._cleanup_task, self._persist_task):
            if t:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        if self.rate_limiter:
            self.rate_limiter.save_bans()
        logger.info("Shutdown: waiting for in-flight requests...")
        # Wait up to shutdown_timeout for active conns to drain
        deadline = time.monotonic() + self.cfg.shutdown_timeout
        while time.monotonic() < deadline:
            if self._active_inbound == 0 and self._active_outbound == 0:
                break
            await asyncio.sleep(0.05)
        if self._active_inbound > 0 or self._active_outbound > 0:
            logger.warning("Shutdown deadline hit with %d/%d in flight",
                           self._active_inbound, self._active_outbound)
        if self.session:
            await self.session.close()
        # FIX v27.0: ThreadPoolExecutor.shutdown() in Python 3.9+ has no `timeout` kwarg
        if self.waf_executor:
            self.waf_executor.shutdown(wait=True)

    async def _persist_loop(self):
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=BAN_PERSIST_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass
            if self.rate_limiter:
                self.rate_limiter.save_bans()

    async def _cleanup_loop(self):
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=self.cfg.cleanup_interval)
                break
            except asyncio.TimeoutError:
                pass
            for c in (self.rate_limiter._store, self.rate_limiter._ban_store,
                      self.rate_limiter._key_cache,
                      self.ip_obj_cache, self.ip_class_cache,
                      self.per_ip_endpoint_cache, self.global_per_ip_cache,
                      self.unique_query_cache, self._per_ip_outbound_cache):
                if c is not None:
                    c.cleanup()

    async def _backend_health_check(self) -> bool:
        if not self.cfg.health_check_enabled:
            return True
        try:
            async with self.session.get(
                f"{self.cfg.backend_url}{self.cfg.health_path}", timeout=5
            ) as r:
                return r.status == 200
        except Exception:
            return False

    async def _health_check_loop(self):
        while not self._shutdown_event.is_set():
            ok = await self._backend_health_check()
            if ok != self._backend_healthy:
                self._backend_healthy = ok
                if ok:
                    logger.info("Backend healthy again")
                else:
                    logger.warning("Backend unhealthy — shedding traffic")
            await asyncio.sleep(30 + random.uniform(-5, 5))

    # ---- low-level helpers ---- #
    def _err(self, request, status, text="", extra_headers: Optional[Dict] = None,
             retry_after: Optional[float] = None) -> web.Response:
        h = dict(BLOCK_HEADERS)
        h["X-Request-ID"] = request.get("request_id", "")
        if extra_headers:
            h.update(extra_headers)
        if retry_after is not None:
            h["Retry-After"] = str(max(1, int(retry_after)))
        return web.Response(status=status, text=text, headers=h)

    @staticmethod
    def _safe_abort(transport):
        if not transport:
            return
        try:
            if not transport.is_closing():
                transport.abort()
        except (OSError, RuntimeError, AttributeError):
            try:
                transport.close()
            except Exception:
                pass

    @staticmethod
    def _normalize_ip(ip_str: str) -> str:
        if ":" not in ip_str:
            return ip_str
        if not ip_str.lower().startswith("::ffff:"):
            return ip_str
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                return str(ip.ipv4_mapped)
        except ValueError:
            pass
        return ip_str

    @staticmethod
    def _ip_matches(ip_str: str, networks: Iterable) -> bool:
        try:
            ip = ipaddress.ip_address(SentinelApp._normalize_ip(ip_str))
        except ValueError:
            return False
        for net in networks:
            try:
                if ip in net:
                    return True
            except TypeError:
                continue
        return False

    @staticmethod
    def get_real_ip(request) -> str:
        remote = request.remote
        if not remote:
            return f"unknown-{id(request.transport)}"
        normalized = SentinelApp._normalize_ip(remote)
        if not SentinelApp._ip_matches(normalized, CFG.trusted_proxies):
            return normalized

        # FIX v27.0: Use getall for multi-header XFF and chained precedence
        cf = request.headers.getall("Cf-Connecting-Ip", [])
        if cf:
            for v in cf:
                ip = SentinelApp._normalize_ip(v.strip())
                try:
                    ipaddress.ip_address(ip)
                    if not SentinelApp._ip_matches(ip, CFG.trusted_proxies):
                        return ip
                except ValueError:
                    continue

        fwd_list = request.headers.getall("X-Forwarded-For", [])
        candidates: List[str] = []
        for fwd in fwd_list:
            for ip in (p.strip().split("%")[0] for p in fwd.split(",")):
                if not ip:
                    continue
                candidates.append(SentinelApp._normalize_ip(ip))

        # Walk from RIGHTMOST to LEFTMOST — rightmost is the closest trusted proxy
        for ip in reversed(candidates[-50:]):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not SentinelApp._ip_matches(ip, CFG.trusted_proxies):
                return ip
        return normalized

    @staticmethod
    def filter_hop_request(headers):
        drop = {"transfer-encoding", "connection", "keep-alive",
                "proxy-authenticate", "proxy-authorization", "te",
                "trailers", "trailer", "upgrade", "content-length"}
        for v in headers.getall("Connection", []):
            for d in v.split(","):
                drop.add(d.strip().lower())
        for k in list(headers.keys()):
            if k.lower() in drop:
                del headers[k]

    @staticmethod
    def filter_hop_response(headers):
        drop = {"transfer-encoding", "connection", "keep-alive",
                "proxy-authenticate", "proxy-authorization", "te",
                "trailers", "trailer", "upgrade"}
        for v in headers.getall("Connection", []):
            for d in v.split(","):
                drop.add(d.strip().lower())
        for k in list(headers.keys()):
            if k.lower() in drop:
                del headers[k]

    @staticmethod
    def _is_text_content(content_type: Optional[str]) -> bool:
        """Body types that should be passed through WAF scanning."""
        if not content_type:
            return False
        ct = content_type.lower().split(";")[0].strip()
        if ct.startswith("text/"):
            return True
        return ct in ("application/json", "application/xml",
                      "application/x-www-form-urlencoded")

    @staticmethod
    def _is_valid_transfer_encoding(headers) -> bool:
        te = headers.getall("Transfer-Encoding", [])
        if len(te) > 1:
            return False
        if not te:
            return True
        toks = [t.strip().lower() for t in te[0].split(",") if t.strip()]
        return len(toks) == 1 and toks[0] == "chunked"

    async def _classify_ip(self, ip_str: str) -> str:
        if ip_str in self.ip_class_cache:
            return self.ip_class_cache[ip_str]
        lock = self._get_counter_lock(ip_str)
        if not await self._try_lock_immediate(lock):
            return self._direct_classify(ip_str)
        try:
            if ip_str in self.ip_class_cache:
                return self.ip_class_cache[ip_str]
            cls = self._direct_classify(ip_str)
            self.ip_class_cache.set(ip_str, cls)
            return cls
        finally:
            lock.release()

    def _direct_classify(self, ip_str: str) -> str:
        if self._ip_matches(ip_str, self.cfg.blacklist_ips):
            return "blacklist"
        if self._ip_matches(ip_str, self.cfg.whitelist_ips):
            return "whitelist"
        return "normal"

    async def _blackhole(self, request, ip: str, reason: str = "Banned") -> web.Response:
        self._metrics["blocked"] += 1
        remote = request.remote or "0.0.0.0"
        is_trusted = self._ip_matches(self._normalize_ip(remote), self.cfg.trusted_proxies)
        logger.info("BLACKHOLE ip=%s reason=%s trusted=%s",
                    ip, reason, is_trusted,
                    extra={"request_id": request.get("request_id", ""),
                           "ip": ip, "reason": reason})
        if not is_trusted:
            self._safe_abort(request.transport)
            # Return a Response that aiohttp won't actually send (transport aborted)
            return web.Response(status=444, body=b"")
        return self._err(request, 403, f"Denied ({reason})")

    # ---- main handler ---- #
    async def handler(self, request) -> web.Response:
        self._metrics["requests"] += 1
        request["request_id"] = str(uuid.uuid4())
        ip = self.get_real_ip(request)
        request._audit_ip = ip

        if request.path == "/metrics":
            if self.cfg.metrics_token:
                tok = request.query.get("token", "")
                if not (tok and hmac_compare(tok, self.cfg.metrics_token)):
                    return self._err(request, 403, "Forbidden")
            elif request.remote and not self._ip_matches(
                self._normalize_ip(request.remote or "0.0.0.0"), self.cfg.trusted_proxies
            ):
                return self._err(request, 403, "Forbidden")
            body = json.dumps(self._metrics).encode()
            return web.Response(status=200, body=body,
                                headers={"Content-Type": "application/json"})

        if self._shutdown_event.is_set():
            self._safe_abort(request.transport)
            return web.Response(status=503, body=b"")

        # Inbound connection semaphore — non-blocking acquire
        if not try_acquire(INBOUND_CONN_SEM):
            self._safe_abort(request.transport)
            return web.Response(status=444, body=b"")

        self._active_inbound += 1
        try:
            try:
                return await asyncio.wait_for(
                    self._process_request(request),
                    timeout=self.cfg.backend_timeout + 5.0,
                )
            except asyncio.TimeoutError:
                self._metrics["slow_aborts"] += 1
                return await self._blackhole(request, ip, "Slowloris/Timeout")
            except asyncio.CancelledError:
                raise
            except web.HTTPException:
                raise
            except Exception as e:
                logger.critical("Unhandled error: %s", e, exc_info=True)
                return await self._blackhole(request, ip, "Internal Error")
        finally:
            self._active_inbound -= 1
            try:
                INBOUND_CONN_SEM.release()
            except (ValueError, AssertionError):
                pass

    async def _process_request(self, request) -> web.Response:
        ip = getattr(request, "_audit_ip", "0.0.0.0")
        rid = request["request_id"]

        # 1) HTTP version
        try:
            ver = request.version
            if (ver.major, ver.minor) not in ALLOWED_HTTP_VERSIONS:
                return self._err(request, 400, "Bad HTTP version")
        except (AttributeError, KeyError):
            pass

        # 2) Host header
        host_hdr = request.headers.get("Host", "")
        if not host_hdr or len(host_hdr) > 256 or len(host_hdr) < 3 \
                or any(c in host_hdr for c in " \t\r"):
            return self._err(request, 400, "Invalid Host header")
        host_lc = host_hdr.lower()
        if self.cfg.allowed_hosts:
            if not any(host_lc == h or host_lc.endswith("." + h) for h in self.cfg.allowed_hosts):
                return self._err(request, 400, "Host not allowed")
        else:
            if self.cfg.listen_host not in ("0.0.0.0", "::"):
                if host_lc not in (self.cfg.listen_host, "localhost", "127.0.0.1", "[::1]"):
                    return self._err(request, 400, "Invalid Host header")

        # 3) Built-in endpoints
        if request.path == "/health":
            health_key = f"health:{ip}"
            lock = self._get_counter_lock(health_key)
            if not await self._try_lock_immediate(lock):
                return self._err(request, 429, "Too Many Health Checks")
            try:
                cnt = self.per_ip_endpoint_cache.get(health_key) or 0
                if cnt > HEALTH_CHECK_LIMIT:
                    return self._err(request, 429, "Too Many Health Checks",
                                     retry_after=60)
                self.per_ip_endpoint_cache.set(health_key, cnt + 1, keep_ttl=True)
            finally:
                lock.release()
            return web.Response(
                text="OK" if self._backend_healthy else "DEGRADED",
                status=200 if self._backend_healthy else 503,
            )

        # 4) Method
        if request.method.upper() not in self.cfg.allowed_methods:
            audit_logger.warning("METHOD_BLOCKED %s %s", ip, request.method,
                                 extra=self._audit_extra(request))
            return self._err(request, 405, "Method Not Allowed")

        # 5) Transfer-Encoding / CL conflict
        if not self._is_valid_transfer_encoding(request.headers):
            return self._err(request, 400, "Bad Transfer-Encoding")
        if request.headers.get("Transfer-Encoding") and request.headers.get("Content-Length"):
            return self._err(request, 400, "TE + CL conflict")

        # 6) Content-Length caps
        cl_values = request.headers.getall("Content-Length", [])
        if len(cl_values) > 1:
            return self._err(request, 400, "Multiple Content-Length")
        if cl_values:
            try:
                cl = int(cl_values[0])
                if cl < 0:
                    return self._err(request, 400, "Invalid Content-Length")
                if cl > self.cfg.max_body_size:
                    return self._err(request, 413, "Request Entity Too Large")
            except (ValueError, TypeError):
                return self._err(request, 400, "Invalid Content-Length")

        # 7) Header / URI caps
        try:
            total_hdr = sum(len(k) + len(v) + 2 for k, v in request.headers.items())
        except Exception:
            total_hdr = 0
        if total_hdr > self.cfg.max_total_headers_size:
            return self._err(request, 431, "Headers too large")
        if len(request.path_qs or "") > self.cfg.max_uri_size:
            return self._err(request, 414, "URI Too Long")
        if len(request.headers) > self.cfg.max_headers:
            return self._err(request, 431, "Too Many Headers")
        for name, value in request.headers.items():
            if len(name) > 256 or len(value) > self.cfg.max_header_size:
                return self._err(request, 431, "Header Too Large")

        # 8) Acquire outbound semaphore (non-blocking — DDoS defence)
        if not try_acquire(OUTBOUND_REQ_SEM):
            self._metrics["blocked"] += 1
            return self._err(request, 503, "Proxy Outbound Queue Full",
                             retry_after=10)

        try:
            # 9) Global per-IP cap with auto-ban on overflow
            global_ip_key = f"global:{ip}"
            lock = self._get_counter_lock(global_ip_key)
            if not await self._try_lock_immediate(lock):
                return self._err(request, 429, "System Overloaded",
                                 retry_after=5)
            try:
                gcnt = self.global_per_ip_cache.get(global_ip_key) or 0
                if gcnt > self.cfg.global_per_ip_limit:
                    self._metrics["global_blocks"] += 1
                    await self.rate_limiter.force_ban(ip, self.cfg.ban_max, rid)
                    audit_logger.warning("GLOBAL_LIMIT_BAN %s", ip,
                                         extra=self._audit_extra(request))
                    return await self._blackhole(request, ip, "Global IP Limit Exceeded")
                self.global_per_ip_cache.set(global_ip_key, gcnt + 1, keep_ttl=True)
            finally:
                lock.release()

            # 10) Unique-query scraper detection
            if request.query_string:
                uq_key = f"uq:{ip}"
                lock = self._get_counter_lock(uq_key)
                if await self._try_lock_immediate(lock):
                    try:
                        seen = self.unique_query_cache.get(uq_key)
                        if seen is None:
                            # store as frozenset-tracked dict (avoid unbounded set mutation)
                            seen = set()
                            self.unique_query_cache.set(uq_key, seen)
                        if request.query_string not in seen:
                            seen.add(request.query_string)
                            if len(seen) > UNIQUE_QUERY_HARD_LIMIT:
                                self._metrics["scraper_blocks"] += 1
                                await self.rate_limiter.force_ban(ip, request_id=rid)
                                audit_logger.warning("SCRAPER_HARD_LIMIT %s queries=%d",
                                                     ip, len(seen),
                                                     extra=self._audit_extra(request))
                                self.unique_query_cache.set(uq_key, set())
                                return await self._blackhole(request, ip, "Scraper Hard Limit")
                            if len(seen) > UNIQUE_QUERY_THRESHOLD:
                                self._metrics["scraper_blocks"] += 1
                                await self.rate_limiter.force_ban(ip, request_id=rid)
                                audit_logger.warning("SCRAPER_PATTERN %s unique=%d",
                                                     ip, len(seen),
                                                     extra=self._audit_extra(request))
                                self.unique_query_cache.set(uq_key, set())
                                return await self._blackhole(request, ip, "Scraper Pattern")
                    finally:
                        lock.release()

            # 11) Per-IP per-endpoint cap
            endpoint_hash = hash(request.path) & 0xFFFFFFFF
            endpoint_key = f"{ip}:{request.method}:{endpoint_hash}"
            lock = self._get_counter_lock(endpoint_key)
            if not await self._try_lock_immediate(lock):
                return self._err(request, 429, "System Overloaded", retry_after=5)
            try:
                ecnt = self.per_ip_endpoint_cache.get(endpoint_key) or 0
                if ecnt > self.cfg.per_ip_endpoint_limit:
                    return await self._blackhole(request, ip, "Endpoint Spam")
                self.per_ip_endpoint_cache.set(endpoint_key, ecnt + 1, keep_ttl=True)
            finally:
                lock.release()

            # 12) IP classification (cached)
            ip_obj = self.ip_obj_cache.get(ip)
            if not ip_obj:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    self.ip_obj_cache.set(ip, ip_obj)
                except ValueError:
                    return self._err(request, 400, "Invalid IP")
            ip_class = await self._classify_ip(ip)
            if ip_class == "blacklist":
                audit_logger.warning("BLACKLIST_HIT %s %s", ip, request.path,
                                     extra=self._audit_extra(request))
                return await self._blackhole(request, ip, "Blacklisted")

            # 13) Rate-limit (whitelist bypasses ban)
            ban_remaining = self.rate_limiter.ban_status(ip)
            rl_headers = {"X-RateLimit-Limit": str(int(self.cfg.rate_limit * self.cfg.burst_limit))}
            if ban_remaining is not None:
                rl_headers["X-RateLimit-Remaining"] = "0"
                rl_headers["X-RateLimit-Reset"] = str(max(1, int(ban_remaining - time.monotonic())))

            if ip_class == "whitelist":
                allowed, _, reason = await self.rate_limiter.check_and_acquire(
                    ip, bypass_ban=True, bypass_ban_writes=True)
                if not allowed:
                    if reason == "too_many_connections":
                        return self._err(request, 429, "Too many connections")
                    if reason in ("system_overloaded", "global_rate_limited"):
                        return self._err(request, 503, "Service Overloaded",
                                         retry_after=10)
                    return self._err(request, 429, "Too Many Requests")
                try:
                    ok, resp, body_chunk = await self._filter(request, ip)
                    if not ok:
                        return resp
                    return await self._forward(request, ip, body_chunk)
                finally:
                    await self.rate_limiter.dec_conn(ip)

            allowed, _, reason = await self.rate_limiter.check_and_acquire(ip)
            if not allowed:
                self._metrics["rate_blocked"] += 1
                # map reason → appropriate response
                if reason == "banned":
                    return await self._blackhole(request, ip, "Banned")
                if reason == "too_many_connections":
                    return self._err(request, 429, "Too many connections", retry_after=5)
                if reason == "burst_window":
                    self._metrics["burst_window_blocks"] += 1
                    return await self._blackhole(request, ip, "Burst Flood")
                if reason in ("system_overloaded", "global_rate_limited"):
                    return self._err(request, 503, "Service Overloaded", retry_after=10)
                return self._err(request, 429, "Too Many Requests", retry_after=5)

            # 14) Backend shedding
            if self.cfg.health_check_enabled and not self._backend_healthy:
                self._metrics["blocked"] += 1
                return self._err(request, 503, "Backend Unavailable", retry_after=15)

            try:
                ok, resp, body_chunk = await self._filter(request, ip)
                if not ok:
                    return resp
                if not await self.cb.allow():
                    self._metrics["circuit_rejects"] += 1
                    return self._err(request, 503, "Service Unavailable (circuit open)",
                                     retry_after=30)
                response = await self._forward(request, ip, body_chunk)
                # attach rate-limit headers on success too
                try:
                    if isinstance(response, web.StreamResponse):
                        # streaming response — headers already sent
                        pass
                    else:
                        response.headers.update(rl_headers)
                except Exception:
                    pass
                return response
            finally:
                await self.rate_limiter.dec_conn(ip)
        finally:
            try:
                OUTBOUND_REQ_SEM.release()
            except (ValueError, AssertionError):
                pass

    # ---- filter: UA + WAF + body ---- #
    async def _filter(self, request, ip) -> Tuple[bool, Optional[web.Response], Optional[bytes]]:
        if "\x00" in (request.path or ""):
            return False, self._err(request, 400, "Bad Request"), None
        if "\x00" in (request.query_string or ""):
            return False, self._err(request, 400, "Bad Request"), None
        for hdr in ("Host", "User-Agent", "Content-Type", "X-Forwarded-For"):
            if "\x00" in (request.headers.get(hdr, "") or ""):
                return False, self._err(request, 400, "Bad Request"), None

        ua = request.headers.get("User-Agent", "") or ""
        if not ua:
            if self.rate_limiter.is_new_ip(ip) \
                    and not request.headers.get("Accept") \
                    and request.method not in ("GET", "HEAD", "OPTIONS"):
                return False, self._err(request, 403, "Empty User-Agent"), None

        ua_low = ua.lower()
        if any(s in ua_low for s in self.cfg.bad_ua_strings):
            return False, self._err(request, 403, "Forbidden"), None

        rid = request["request_id"]

        # WAF on path + query (always — for these payloads this is the main attack surface)
        if self.cfg.enable_waf:
            combined = f"{request.path or ''}\x00{request.query_string or ''}"[:WAF_INSPECT_SIZE]
            waf_res = await async_waf_check(combined, self.waf_executor, WAF_SEM)
            if waf_res in ("ERROR", "WAF_TIMEOUT", "WAF_OVERLOAD"):
                if waf_res == "WAF_OVERLOAD":
                    self._metrics["waf_overloads"] += 1
                await self.rate_limiter.force_ban(ip, request_id=rid)
                audit_logger.warning("WAF_ERROR %s %s", ip, waf_res,
                                     extra=self._audit_extra(request))
                return False, self._err(request, 403, "WAF Error"), None
            if waf_res:
                self._metrics["waf_hits"] += 1
                audit_logger.warning("WAF_HIT %s %s %s",
                                     ip, waf_res, request.path,
                                     extra=self._audit_extra(request))
                return False, self._err(request, 403, "WAF Blocked"), None

        # body WAF
        body_chunk: Optional[bytes] = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if self.cfg.enable_waf and self._is_text_content(request.content_type):
                # If client claims content > WAF_INSPECT_SIZE we still need size cap, so
                # trust Content-Length check above and bail early.
                if request.content_length is not None and request.content_length > WAF_INSPECT_SIZE:
                    body_chunk = None
                else:
                    try:
                        body_chunk = await asyncio.wait_for(
                            request.content.read(WAF_INSPECT_SIZE),
                            timeout=self.cfg.waf_body_timeout,
                        )
                    except web.HTTPRequestEntityTooLarge:
                        return False, self._err(request, 413, "Payload Too Large"), None
                    except (asyncio.TimeoutError, TimeoutError):
                        return False, await self._blackhole(request, ip, "Body Read Timeout"), None
                    except (ClientPayloadError, ClientDisconnectedError,
                            asyncio.IncompleteReadError, ConnectionResetError) as e:
                        logger.debug("Client disconnect during body read: %s", e)
                        return False, await self._blackhole(request, ip, "Client disconnect"), None
                    except Exception as e:
                        logger.error("Body read error: %s", e)
                        return False, self._err(request, 400, "Bad Request: body read"), None

                    if body_chunk:
                        if WAF_SEM is not None:
                            if not try_acquire(WAF_SEM):
                                self._metrics["waf_overloads"] += 1
                                logger.warning("WAF queue full – dropping %s", ip)
                                return False, await self._blackhole(request, ip, "WAF Overloaded"), None
                            try:
                                try:
                                    text = body_chunk[:WAF_INSPECT_SIZE].decode("utf-8", "ignore")
                                except Exception:
                                    text = ""
                                waf_res = await async_waf_check(text, self.waf_executor)
                                if waf_res in ("ERROR", "WAF_TIMEOUT"):
                                    await self.rate_limiter.force_ban(ip, request_id=rid)
                                    audit_logger.warning("WAF_ERROR_BODY %s %s",
                                                         ip, waf_res,
                                                         extra=self._audit_extra(request))
                                    return False, self._err(request, 403, "WAF Error"), None
                                if waf_res:
                                    self._metrics["waf_hits"] += 1
                                    audit_logger.warning("WAF_HIT_BODY %s %s %s",
                                                         ip, waf_res, request.path,
                                                         extra=self._audit_extra(request))
                                    return False, self._err(request, 403, "WAF Blocked"), None
                                if request.content_type and "application/json" in request.content_type:
                                    loop = asyncio.get_running_loop()
                                    try:
                                        json_res = await asyncio.wait_for(
                                            loop.run_in_executor(self.waf_executor,
                                                                 _json_parse_and_scan, text),
                                            timeout=WAF_REGEX_TIMEOUT,
                                        )
                                    except asyncio.TimeoutError:
                                        logger.error("JSON scan timeout — possible bomb")
                                        return False, self._err(request, 413, "JSON too large"), None
                                    if json_res:
                                        self._metrics["waf_hits"] += 1
                                        audit_logger.warning("WAF_HIT_JSON %s %s %s",
                                                             ip, json_res, request.path,
                                                             extra=self._audit_extra(request))
                                        return False, self._err(request, 403, "WAF Blocked JSON"), None
                            finally:
                                WAF_SEM.release()
        return True, None, body_chunk

    # ---- forward ---- #
    async def _acquire_per_ip_outbound(self, ip: str) -> bool:
        async with self._per_ip_outbound_lock:
            sem = self._per_ip_outbound_cache.get(ip)
            if sem is None:
                sem = asyncio.Semaphore(self.cfg.per_ip_backend_limit)
                self._per_ip_outbound_cache.set(ip, sem)
        # FIX v27.0.1: synchronous non-blocking acquire — wait_for(timeout=0)
        # was unreliable and routinely aborted connections under load.
        return try_acquire(sem)

    async def _release_per_ip_outbound(self, ip: str):
        sem = self._per_ip_outbound_cache.get(ip)
        if sem:
            try:
                sem.release()
            except (ValueError, AssertionError):
                pass

    async def _forward(self, request, ip, body_chunk):
        if not await self._acquire_per_ip_outbound(ip):
            self._metrics["blocked"] += 1
            return self._err(request, 503, "Too many concurrent requests from this IP",
                             retry_after=5)
        try:
            url = urljoin(self.cfg.backend_url + "/", (request.path_qs or "").lstrip("/"))
            headers = request.headers.copy()
            headers["Host"] = self.backend_host
            self.filter_hop_request(headers)
            headers["X-Request-ID"] = request.get("request_id", "")

            existing_xff = headers.getall("X-Forwarded-For", [])
            ips: List[str] = []
            for v in existing_xff:
                ips.extend(p.strip() for p in v.split(",") if p.strip())
            if len(ips) > XFF_MAX_IPS:
                ips = ips[-XFF_MAX_IPS:]
            remote_norm = self._normalize_ip(request.remote or "0.0.0.0")
            if remote_norm not in ips:
                ips.append(remote_norm)
            headers["X-Forwarded-For"] = ", ".join(ips)
            # FIX v27.0.1: use the inbound scheme (already TRUSTED through proxies)
            # instead of hardcoded env var
            try:
                headers["X-Forwarded-Proto"] = request.scheme or URL_SCHEME
            except AttributeError:
                headers["X-Forwarded-Proto"] = URL_SCHEME

            can_retry = request.method in ("GET", "HEAD")
            max_attempts = BACKEND_MAX_RETRIES + 1 if can_retry else 1
            # FIX v27.0.1: rebuild body iterator INSIDE the retry loop — async
            # generators can only be iterated ONCE.
            has_body = request.method in ("POST", "PUT", "PATCH", "DELETE")

            last_exc: Optional[Exception] = None
            self._active_outbound += 1
            try:
                for attempt in range(max_attempts):
                    data = self._make_body_stream(body_chunk, request) if has_body else None
                    try:
                        async with self.session.request(
                            request.method, url, headers=headers, data=data,
                            allow_redirects=False, ssl=self.cfg.verify_ssl,
                        ) as resp:
                            if resp.status >= 500:
                                self.cb.record_error()
                                logger.warning("Backend %d for %s attempt=%d",
                                               resp.status, ip, attempt+1)
                            else:
                                self.cb.record_success()

                            bheaders = resp.headers.copy()
                            self.filter_hop_response(bheaders)
                            bheaders.pop("Server", None)
                            bheaders.pop("X-Powered-By", None)
                            if self.cfg.server_header:
                                bheaders["Server"] = self.cfg.server_header
                            bheaders["Connection"] = "close"

                            client_resp = web.StreamResponse(status=resp.status,
                                                             headers=bheaders)
                            await client_resp.prepare(request)

                            try:
                                MAX_BPS = 2 * 1024 * 1024
                                CHUNK_SIZE = 64 * 1024

                                async def _stream():
                                    tokens = MAX_BPS
                                    last_refill = time.monotonic()
                                    async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                                        cost = len(chunk)
                                        now = time.monotonic()
                                        elapsed = now - last_refill
                                        tokens = min(MAX_BPS, tokens + elapsed * MAX_BPS)
                                        last_refill = now
                                        if tokens < cost:
                                            await asyncio.sleep((cost - tokens) / MAX_BPS)
                                            tokens = 0
                                        else:
                                            tokens -= cost
                                        await client_resp.write(chunk)
                                    await client_resp.write_eof()

                                await asyncio.wait_for(_stream(),
                                                       timeout=self.cfg.backend_timeout)
                            except (asyncio.TimeoutError, ConnectionResetError,
                                    ConnectionAbortedError, BrokenPipeError,
                                    asyncio.IncompleteReadError, ClientError):
                                logger.debug("Client connection interrupted: %s", ip)
                                self._safe_abort(request.transport)
                                client_resp.force_close()
                                return client_resp
                            return client_resp
                    except (ClientError, asyncio.TimeoutError, ConnectionError) as e:
                        last_exc = e
                        if attempt < max_attempts - 1:
                            logger.warning("Backend attempt %d failed for %s: %s",
                                           attempt + 1, ip, e)
                            await asyncio.sleep(0.1 * (attempt + 1))
                        else:
                            break

                self.cb.record_error()
                if isinstance(last_exc, asyncio.TimeoutError):
                    logger.error("Backend timeout after %d attempts for %s",
                                 max_attempts, ip)
                    return self._err(request, 504, "Gateway Timeout", retry_after=30)
                logger.error("Backend connection error after %d attempts for %s: %s",
                             max_attempts, ip, last_exc)
                return self._err(request, 502, "Bad Gateway", retry_after=30)
            finally:
                self._active_outbound -= 1
        finally:
            await self._release_per_ip_outbound(ip)

    @staticmethod
    def _make_body_stream(body_chunk, request):
        async def _stream():
            total = len(body_chunk) if body_chunk else 0
            if body_chunk:
                yield body_chunk
            start_time = time.monotonic()
            while total <= CFG.max_body_size:
                if time.monotonic() - start_time > 10:
                    return
                try:
                    chunk = await asyncio.wait_for(
                        request.content.read(STREAM_CHUNK_SIZE),
                        timeout=SLOW_REQUEST_TIMEOUT,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    return
                except (ClientError, ConnectionError, asyncio.IncompleteReadError):
                    break
                if not chunk:
                    break
                total += len(chunk)
                if total > CFG.max_body_size:
                    # FIX v27.0: instead of raising mid-stream (crashes), close cleanly
                    logger.warning("Body exceeded max_body_size (%d) — truncating", total)
                    return
                yield chunk
        return _stream()


# ====================================================================== #
# Helpers
# ====================================================================== #
URL_SCHEME = os.getenv("URL_SCHEME", "http")


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string compare to avoid timing oracles."""
    if a is None or b is None:
        return False
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= ord(x) ^ ord(y)
    return res == 0


# ====================================================================== #
# Globals
# ====================================================================== #
CFG: Optional[Config] = None
INBOUND_CONN_SEM: Optional[asyncio.Semaphore] = None
WAF_SEM: Optional[asyncio.Semaphore] = None
OUTBOUND_REQ_SEM: Optional[asyncio.Semaphore] = None
logger: Optional[logging.Logger] = None
audit_logger: Optional[logging.Logger] = None


# ====================================================================== #
# App factory + main
# ====================================================================== #
def create_app(cfg: Config) -> web.Application:
    sentinel = SentinelApp(cfg)
    app = web.Application(client_max_size=cfg.max_body_size)
    app.on_startup.append(sentinel.startup)
    app.on_cleanup.append(sentinel.shutdown)
    app.router.add_route("*", "/{tail:.*}", sentinel.handler)
    app["sentinel"] = sentinel
    return app


def _print_help():
    help_txt = f"""\
Sentinel Guard v{VERSION} — single-file anti-DDoS L7 reverse proxy

Environment variables (all optional):
  SENTINEL_HOST, SENTINEL_PORT       bind address (default 0.0.0.0:9999)
  BACKEND_URL                        backend upstream (default http://127.0.0.1:8888)
  RATE_LIMIT, BURST_LIMIT            per-IP token bucket (default 200/s, burst 400)
  MAX_CONN_IP                        concurrent conns per IP (default 30)
  MAX_BODY_SIZE                      bytes (default 1MB)
  BAN_BASE, BAN_MULT, BAN_MAX        ban scheduler (60s * 2^n, capped at 1h)
  VIOLATIONS_DECAY                   seconds before violations decay
  PER_IP_BURST_WINDOW, _LIMIT        rolling burst window (40 req / 10s default)
  TRUSTED_PROXIES, WHITELIST, BLACKLIST
                                     comma-separated CIDR lists
  ALLOWED_METHODS                    default: GET,POST,HEAD,PUT,DELETE,OPTIONS,PATCH
  ENABLE_WAF, ENABLE_FIREWALL        bool (1/0)
  BACKEND_HEALTH_CHECK, BACKEND_HEALTH_PATH
                                     optional backend health shedding
  WAF_BODY_TIMEOUT, WAF_REGEX_TIMEOUT
                                     WAF timeouts (default 5s, 1s)
  BAN_PERSIST_FILE, BAN_PERSIST_INTERVAL
                                     bans-on-disk (default sentinel_bans.json / 5min)
  METRICS_TOKEN                      if set, /metrics requires ?token=...
  ENTROPY_THRESHOLD                  path entropy threshold for scanners
  LISTEN_HOST / LISTEN_PORT (alias)

CLI:
  --help        show this help
  --dry-run     validate configuration and exit
  --config=KEY=VAL  override env (repeatable)
"""
    print(help_txt)


def _parse_args(argv):
    out: Dict[str, str] = {}
    dry_run = False
    for arg in argv[1:]:
        if arg == "--help" or arg == "-h":
            _print_help()
            sys.exit(0)
        if arg == "--dry-run":
            dry_run = True
            continue
        if arg.startswith("--config="):
            kv = arg[len("--config="):]
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k] = v
            continue
        # ignore unknown
    return out, dry_run


def main():
    global CFG, logger, audit_logger
    overrides, dry_run = _parse_args(sys.argv)
    try:
        CFG = Config(overrides)
    except ValueError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)
    if dry_run:
        print("OK: configuration valid")
        print(f"  listen         : {CFG.listen_host}:{CFG.listen_port}")
        print(f"  backend        : {CFG.backend_url}")
        print(f"  rate_limit     : {CFG.rate_limit}/s, burst {CFG.burst_limit}")
        print(f"  burst_window   : {CFG.per_ip_burst_limit} req / {CFG.per_ip_burst_window}s")
        print(f"  max_body_size  : {CFG.max_body_size} bytes")
        print(f"  waf            : enabled={CFG.enable_waf} timeout={WAF_REGEX_TIMEOUT}s")
        print(f"  fd_limit       : {MAX_SAFE_CONNS}")
        print(f"  platform       : {sys.platform}")
        sys.exit(0)

    logger, audit_logger, listener, audit_listener, _, _ = setup_logging(CFG)

    # FIX v27.0: Windows uses Proactor (IOCP, no 512-FD limit)
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    app = create_app(CFG)

    # FIX v27.0.1: removed custom signal handler — web.run_app(handle_signals=True)
    # registers its own SIGTERM/SIGINT handlers that already do graceful shutdown
    # via app.on_cleanup. Our previous custom handler was dead code AND raced with
    # aiohttp's. On Windows, also register SIGBREAK/Ctrl-Break as a courtesy.

    try:
        if sys.platform == "win32" and hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, signal.SIG_DFL)
    except (ValueError, OSError, NotImplementedError):
        pass

    web.run_app(
        app,
        host=CFG.listen_host,
        port=CFG.listen_port,
        keepalive_timeout=KEEPALIVE_TIMEOUT,
        handle_signals=True,
        shutdown_timeout=CFG.shutdown_timeout,
    )


if __name__ == "__main__":
    main()
