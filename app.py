#!/usr/bin/env python3
"""
Sentinel Guard v22.14 – Last Stand Absolute (Final TCP & CPU patches)
Production‑hardened, single‑file Python async anti‑DDoS layer‑7 wall.
Works on Linux, Windows, macOS – no C‑extensions, no root.
Requires: aiohttp >= 3.8, Python 3.9+
"""

import asyncio
import concurrent.futures
import gc
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import time
import uuid
from collections import deque, OrderedDict
from typing import Dict, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector, ClientError

# --------------------------------------------------------------------------- #
#  Constants                                                                    #
# --------------------------------------------------------------------------- #
DEFAULT_CACHE_MAXSIZE = 100_000
DEFAULT_CACHE_TTL = 3600

DEFAULT_RATE_LIMIT = 50.0
DEFAULT_BURST_LIMIT = 100.0
DEFAULT_MAX_CONN_PER_IP = 30
DEFAULT_BAN_BASE = 60.0
DEFAULT_BAN_MULT = 2.0
DEFAULT_BAN_MAX = 3600.0
DEFAULT_VIOLATIONS_DECAY = 3600.0

DEFAULT_MAX_BODY_SIZE = 1_048_576
DEFAULT_MAX_HEADER_SIZE = 8192
DEFAULT_MAX_HEADERS = 100
DEFAULT_MAX_URI_SIZE = 4096
DEFAULT_MAX_TOTAL_HEADERS_SIZE = 65536

WAF_INSPECT_SIZE = 8192
WAF_BODY_TIMEOUT = 5.0
WAF_MAX_WORKERS = 64

DEFAULT_PER_IP_ENDPOINT_LIMIT = 30
DEFAULT_PER_IP_ENDPOINT_TTL = 60

DEFAULT_GLOBAL_PER_IP_LIMIT = 100
DEFAULT_GLOBAL_PER_IP_TTL = 60

HEALTH_CHECK_LIMIT = 10
HEALTH_CHECK_TTL = 60

MAX_SAFE_CONNS_LINUX = 15000
MAX_SAFE_CONNS_WINDOWS = 5000

WAF_SEM_MULTIPLIER = 2
OUTBOUND_SEM_BASE = 100

DEFAULT_CLEANUP_INTERVAL = 300

DEFAULT_CB_ERROR_THRESHOLD = 5
DEFAULT_CB_WINDOW = 60
DEFAULT_CB_PROBE_TIMEOUT = 30

XFF_MAX_LENGTH = 2048
XFF_MAX_IPS = 50
STREAM_CHUNK_SIZE = 8192
BACKEND_TIMEOUT = 30.0

KEEPALIVE_TIMEOUT = 15
SLOW_REQUEST_TIMEOUT = 10

DEFAULT_LOG_QUEUE_MAXSIZE = 5000

BAN_STORE_MAXSIZE = 500_000
BAN_STORE_TTL = 86400
STATE_STORE_MAXSIZE = 50_000
STATE_STORE_TTL = 3600

KEY_CACHE_MAXSIZE = 20_000
KEY_CACHE_TTL = 600

IP_OBJ_CACHE_MAXSIZE = 100_000
IP_OBJ_CACHE_TTL = 3600

IP_CLASS_CACHE_MAXSIZE = 100_000
IP_CLASS_CACHE_TTL = 3600

UNIQUE_QUERY_CACHE_MAXSIZE = 50_000
UNIQUE_QUERY_CACHE_TTL = 300
UNIQUE_QUERY_THRESHOLD = 20

SHARD_LOCK_COUNT = 1024

BACKEND_MAX_RETRIES = 1

MAX_JSON_ELEMENTS = 1000

# WAF fast-path character set and keywords
SUSPICIOUS_CHARS = set("'\"<>();-=%&|`")
_SQLI_KEYWORDS = ("union", "select", "insert", "update", "delete",
                  "drop", "sleep", "benchmark", "waitfor", "information_schema")

# --------------------------------------------------------------------------- #
#  Raise file descriptor limit (Linux only)                                    #
# --------------------------------------------------------------------------- #
if sys.platform != "win32":
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
    except (ValueError, PermissionError):
        pass

# --------------------------------------------------------------------------- #
#  FAST LRU TTL CACHE                                                         #
# --------------------------------------------------------------------------- #
class FastTTLCache:
    __slots__ = ('_data', '_maxsize', '_ttl')

    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE, ttl: float = DEFAULT_CACHE_TTL):
        self._data = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str):
        item = self._data.get(key)
        if not item:
            return None
        if item[1] < time.monotonic():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return item[0]

    def __setitem__(self, key: str, value):
        if key in self._data:
            self._data.move_to_end(key)
        elif len(self._data) >= self._maxsize:
            self._data.popitem(last=False)
        self._data[key] = (value, time.monotonic() + self._ttl)

    def __getitem__(self, key: str):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: str):
        item = self._data.get(key)
        if not item:
            return False
        return item[1] >= time.monotonic()

# --------------------------------------------------------------------------- #
#  CONFIGURATION (safe environment parsing, validated ranges)                 #
# --------------------------------------------------------------------------- #
class Config:

    @staticmethod
    def _safe_int(val: str, default: int, min_val: int = None, max_val: int = None) -> int:
        try:
            v = int(val) if val else default
        except ValueError:
            v = default
        if min_val is not None and v < min_val:
            v = min_val
        if max_val is not None and v > max_val:
            v = max_val
        return v

    @staticmethod
    def _safe_float(val: str, default: float, min_val: float = None, max_val: float = None) -> float:
        try:
            v = float(val) if val else default
        except ValueError:
            v = default
        if min_val is not None and v < min_val:
            v = min_val
        if max_val is not None and v > max_val:
            v = max_val
        return v

    @staticmethod
    def _parse_networks(raw: str) -> Set:
        result = set()
        if not raw:
            return result
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
                result.add(net)
            except ValueError:
                print(f"Warning: Invalid IP/network in config: {entry}", file=sys.stderr)
        return result

    def __init__(self):
        self.listen_host = os.getenv("SENTINEL_HOST", "0.0.0.0")
        self.listen_port = self._safe_int(os.getenv("SENTINEL_PORT", ""), 9999, 1, 65535)
        if self.listen_port < 1024 and sys.platform != "win32" and os.geteuid() != 0:
            print("WARNING: Listening on port < 1024 requires root privileges.")
        backend_raw = os.getenv("BACKEND_URL", "http://127.0.0.1:8888")
        parsed = urlparse(backend_raw)
        if parsed.scheme not in ("http", "https"):
            print("FATAL: BACKEND_URL scheme must be http or https")
            sys.exit(1)
        self.backend_url = backend_raw.rstrip("/")

        self.rate_limit      = self._safe_float(os.getenv("RATE_LIMIT", ""), DEFAULT_RATE_LIMIT, 1.0)
        self.burst_limit     = self._safe_float(os.getenv("BURST_LIMIT", ""), DEFAULT_BURST_LIMIT, 1.0)
        self.max_conn_per_ip = self._safe_int(os.getenv("MAX_CONN_IP", ""), DEFAULT_MAX_CONN_PER_IP, 1)
        self.max_body_size   = self._safe_int(os.getenv("MAX_BODY_SIZE", ""), DEFAULT_MAX_BODY_SIZE, 1)

        self.ban_base       = self._safe_float(os.getenv("BAN_BASE", ""), DEFAULT_BAN_BASE, 1.0)
        self.ban_mult       = self._safe_float(os.getenv("BAN_MULT", ""), DEFAULT_BAN_MULT, 1.0)
        self.ban_max        = self._safe_float(os.getenv("BAN_MAX", ""), DEFAULT_BAN_MAX, 1.0)
        self.violations_decay = self._safe_float(os.getenv("VIOLATIONS_DECAY", ""), DEFAULT_VIOLATIONS_DECAY, 60.0)

        self.trusted_proxies = self._parse_networks(os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1"))
        self.whitelist_ips   = self._parse_networks(os.getenv("WHITELIST", ""))
        self.blacklist_ips   = self._parse_networks(os.getenv("BLACKLIST", ""))

        self.allowed_methods = set(m.strip().upper() for m in os.getenv("ALLOWED_METHODS", "GET,POST,HEAD,PUT,DELETE").split(",") if m.strip())
        self.max_header_size = self._safe_int(os.getenv("MAX_HEADER_SIZE", ""), DEFAULT_MAX_HEADER_SIZE, 1)
        self.max_headers     = self._safe_int(os.getenv("MAX_HEADERS", ""), DEFAULT_MAX_HEADERS, 1)
        self.max_uri_size    = self._safe_int(os.getenv("MAX_URI_SIZE", ""), DEFAULT_MAX_URI_SIZE, 1)
        self.max_total_headers_size = self._safe_int(os.getenv("MAX_TOTAL_HEADERS_SIZE", ""), DEFAULT_MAX_TOTAL_HEADERS_SIZE, 1)

        # Use substring check for performance (no regex overhead)
        self.bad_ua_strings = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "botnet", "crawler", "scan"
        )
        custom_ua = os.getenv("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_strings = self.bad_ua_strings + tuple(p.strip().lower() for p in custom_ua.split(",") if p.strip())

        self.enable_waf    = os.getenv("ENABLE_WAF", "1") == "1"
        self.waf_body_timeout = self._safe_float(os.getenv("WAF_BODY_TIMEOUT", ""), WAF_BODY_TIMEOUT, 0.1)

        self.enable_firewall    = os.getenv("ENABLE_FIREWALL", "0") == "1"

        self.backend_pool_size  = self._safe_int(os.getenv("BACKEND_POOL_SIZE", ""), OUTBOUND_SEM_BASE, 1)
        self.verify_ssl         = os.getenv("VERIFY_SSL", "1") == "1"
        self.backend_timeout    = self._safe_float(os.getenv("BACKEND_TIMEOUT", ""), BACKEND_TIMEOUT, 1.0)

        self.cb_error_threshold = self._safe_int(os.getenv("CB_ERRORS", ""), DEFAULT_CB_ERROR_THRESHOLD, 1)
        self.cb_window          = self._safe_int(os.getenv("CB_WINDOW", ""), DEFAULT_CB_WINDOW, 1)
        self.cb_probe_timeout   = self._safe_int(os.getenv("CB_TIMEOUT", ""), DEFAULT_CB_PROBE_TIMEOUT, 1)

        self.cleanup_interval   = self._safe_int(os.getenv("CLEANUP_INTERVAL", ""), DEFAULT_CLEANUP_INTERVAL, 1)
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            self.log_level = "INFO"
        self.log_file  = os.getenv("LOG_FILE", "sentinel.log")
        self.log_queue_maxsize = self._safe_int(os.getenv("LOG_QUEUE_MAXSIZE", ""), DEFAULT_LOG_QUEUE_MAXSIZE, 100)
        self.audit_log_file = os.getenv("AUDIT_LOG_FILE", "sentinel_audit.log")

        self.global_per_ip_limit = self._safe_int(os.getenv("GLOBAL_PER_IP_LIMIT", ""), DEFAULT_GLOBAL_PER_IP_LIMIT, 1)
        self.server_header = os.getenv("SERVER_HEADER", "Sentinel-Guard")
        self.shutdown_timeout = self._safe_float(os.getenv("SHUTDOWN_TIMEOUT", ""), 30.0, 1.0)

        self.ipv6_prefix = self._safe_int(os.getenv("IPV6_PREFIX", ""), 64, 16, 128)

CFG = Config()

# --------------------------------------------------------------------------- #
#  GLOBAL RESOURCES (lazy initialized to avoid import‑side effects)          #
# --------------------------------------------------------------------------- #
waf_executor = None
listener = None
audit_listener = None
log_queue = queue.Queue(maxsize=CFG.log_queue_maxsize)
audit_log_queue = queue.Queue(maxsize=CFG.log_queue_maxsize)

# --------------------------------------------------------------------------- #
#  CROSS‑PLATFORM EVENT LOOP & OS LIMITS                                      #
# --------------------------------------------------------------------------- #
try:
    if sys.platform != "win32":
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        max_fds = min(soft, 65535) - 100
        MAX_SAFE_CONNS = max(MAX_SAFE_CONNS_WINDOWS, max_fds // 2)
    else:
        MAX_SAFE_CONNS = MAX_SAFE_CONNS_WINDOWS
except Exception:
    MAX_SAFE_CONNS = MAX_SAFE_CONNS_LINUX

INBOUND_CONN_SEM = asyncio.Semaphore(MAX_SAFE_CONNS)
WAF_SEM = asyncio.Semaphore(CFG.backend_pool_size * WAF_SEM_MULTIPLIER)
OUTBOUND_REQ_SEM = asyncio.Semaphore(CFG.backend_pool_size)

BLOCK_HEADERS = {'Connection': 'close', 'Cache-Control': 'no-store'}

# --------------------------------------------------------------------------- #
#  LOGGING (non‑blocking handlers, structured audit log, log rotation)        #
# --------------------------------------------------------------------------- #
class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    def emit(self, record):
        try:
            self.enqueue(record)
        except queue.Full:
            sys.stderr.write(self.format(record) + '\n')

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        return json.dumps(log_entry)

queue_handler = NonBlockingQueueHandler(log_queue)
logger = logging.getLogger("Sentinel")
logger.setLevel(CFG.log_level)
logger.addHandler(queue_handler)

audit_queue_handler = NonBlockingQueueHandler(audit_log_queue)
audit_logger = logging.getLogger("Sentinel.Audit")
audit_logger.setLevel("WARNING")
audit_logger.addHandler(audit_queue_handler)
audit_logger.propagate = False

_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
_audit_formatter = JSONFormatter()

# --------------------------------------------------------------------------- #
#  PURE PYTHON MICRO‑WAF ENGINE (fast‑path + optimised decoding)             #
# --------------------------------------------------------------------------- #
_SQLI_PATTERNS = [
    re.compile(r"(?<![a-zA-Z0-9_])(sleep|benchmark|pg_sleep|waitfor)\s*\(", re.IGNORECASE),
    re.compile(r"\bunion\b[\s(]*(?:all|distinct)?[\s(]*\bselect\b", re.IGNORECASE),
    re.compile(r"\bselect\b[^a-zA-Z0-9_]{0,50}\bfrom\b", re.IGNORECASE),
    re.compile(r"\binsert\b[^a-zA-Z0-9_]{0,50}\binto\b", re.IGNORECASE),
    re.compile(r"\bupdate\b[^a-zA-Z0-9_]{0,50}\bset\b", re.IGNORECASE),
    re.compile(r"\bdelete\b[^a-zA-Z0-9_]{0,50}\bfrom\b", re.IGNORECASE),
    re.compile(r"\bdrop\b[^a-zA-Z0-9_]{0,50}\btable\b", re.IGNORECASE),
    re.compile(r"'\s*(or|and)\s+['\d]", re.IGNORECASE),
    re.compile(r"(?:--|#)\s|/\*", re.IGNORECASE),
    re.compile(r";\s*(drop|alter|create|insert|update|delete)\b", re.IGNORECASE),
    re.compile(r"\b(information_schema|sysobjects|syscolumns)\b", re.IGNORECASE),
    re.compile(r"(\.\./)|(\.\.\\)|(%2e%2e%2f)|(%2e%2e/)|(\.\.%2f)|(%2e%2e%5c)", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src\s*=\s*['\"]?javascript:", re.IGNORECASE),
    re.compile(r"<\s*(iframe|object|embed|svg|math)", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\s*\.\s*(cookie|write|location)", re.IGNORECASE)
]

_PROTO_POLLUTION_PATTERNS = [
    re.compile(r"__proto__", re.IGNORECASE),
    re.compile(r"constructor\s*\[", re.IGNORECASE),
    re.compile(r"\bprototype\b", re.IGNORECASE),
]

def _decode_aggressive(data: str) -> str:
    cleaned = data
    for _ in range(2):
        new_cleaned = unquote(cleaned)
        if new_cleaned == cleaned:
            break
        cleaned = new_cleaned

    cleaned = cleaned.replace('\x00', '').replace('\r', '').replace('\n', '')
    return cleaned

def waf_check(data: str) -> Optional[str]:
    if not CFG.enable_waf or not data:
        return None

    # Fast-path: skip heavy analysis if no suspicious characters or SQL keywords
    data_lower = data.lower()
    if not any(c in SUSPICIOUS_CHARS for c in data) and not any(kw in data_lower for kw in _SQLI_KEYWORDS):
        return None

    try:
        cleaned = _decode_aggressive(data)
    except Exception:
        return "ERROR"

    try:
        for pattern in _SQLI_PATTERNS:
            if pattern.search(cleaned):
                return "SQLi"
        for pattern in _XSS_PATTERNS:
            if pattern.search(cleaned):
                return "XSS"
        for pattern in _PROTO_POLLUTION_PATTERNS:
            if pattern.search(cleaned):
                return "PROTO"
    except Exception as e:
        logger.error("Micro-WAF execution error: %s", e)
        return "ERROR"

    return None

async def async_waf_check(data: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(waf_executor, waf_check, data)

# --------------------------------------------------------------------------- #
#  JSON deep scan helper (recursively check keys and string values)           #
# --------------------------------------------------------------------------- #
def _json_scan(obj, max_depth=10, _count=None) -> Optional[str]:
    if _count is None:
        _count = [0]
    if _count[0] > MAX_JSON_ELEMENTS or max_depth <= 0:
        return None
    _count[0] += 1
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                result = waf_check(k)
                if result:
                    return result
            result = _json_scan(v, max_depth - 1, _count)
            if result:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = _json_scan(item, max_depth - 1, _count)
            if result:
                return result
    elif isinstance(obj, str):
        return waf_check(obj)
    return None

# --------------------------------------------------------------------------- #
#  RATE LIMITER & IP STATE (bypass_ban_writes for whitelist)                  #
# --------------------------------------------------------------------------- #
class IPState:
    __slots__ = ("tokens","last_time","violations","last_violation_time","active_conns","first_seen")
    def __init__(self, burst: float):
        self.tokens = burst
        self.last_time = time.monotonic()
        self.violations = 0
        self.last_violation_time = 0.0
        self.active_conns = 0
        self.first_seen = time.monotonic()

class RateLimiter:

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._store = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=STATE_STORE_TTL)
        self._ban_store = FastTTLCache(maxsize=BAN_STORE_MAXSIZE, ttl=BAN_STORE_TTL)
        self._key_cache = FastTTLCache(maxsize=KEY_CACHE_MAXSIZE, ttl=KEY_CACHE_TTL)
        self._locks_pool = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]

    def _get_rate_limit_key(self, ip_str: str) -> str:
        key = self._key_cache.get(ip_str)
        if key is not None:
            return key
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                network = ipaddress.ip_network(f"{ip_str}/{self.cfg.ipv6_prefix}", strict=False)
                key = str(network.network_address)
            else:
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                key = str(network.network_address)
        except ValueError:
            key = ip_str
        self._key_cache[ip_str] = key
        return key

    def _get_shard_lock(self, key: str) -> asyncio.Lock:
        return self._locks_pool[hash(key) % SHARD_LOCK_COUNT]

    def _get(self, key: str) -> IPState:
        state = self._store.get(key)
        if state is None:
            warm_burst = max(1.0, self.cfg.burst_limit * 0.1)
            state = IPState(warm_burst)
            self._store[key] = state
        else:
            if state.first_seen > 0 and (time.monotonic() - state.first_seen) > 300:
                if state.violations == 0:
                    state.tokens = self.cfg.burst_limit
                state.first_seen = 0.0
        return state

    async def check_and_acquire(self, ip: str, bypass_ban: bool = False,
                                bypass_ban_writes: bool = False) -> Tuple[bool, float, str]:
        key = self._get_rate_limit_key(ip)
        lock = self._get_shard_lock(key)
        async with lock:
            now = time.monotonic()
            if not bypass_ban:
                ban_until = self._ban_store.get(key)
                if ban_until and ban_until > now:
                    return False, 0.0, "banned"
            s = self._get(key)
            if s.active_conns >= self.cfg.max_conn_per_ip:
                return False, 0.0, "too_many_connections"
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
            ban_time = min(self.cfg.ban_max, self.cfg.ban_base * (self.cfg.ban_mult ** (s.violations - 1)))
            ban_until_time = now + ban_time
            self._ban_store[key] = ban_until_time
            s.active_conns -= 1
            if s.violations == 1 or s.violations % 10 == 0:
                logger.warning("IP %s banned %.0fs (violations: %d)", ip, ban_time, s.violations)
                audit_logger.warning("BAN %s %.0fs violations=%d", ip, ban_time, s.violations)
            if self.cfg.enable_firewall and s.violations > 3:
                logger.info("FIREWALL_BAN_IP=%s DURATION=%.0f", ip, ban_time)
            return False, 0.0, "rate_limited"

    async def dec_conn(self, ip: str):
        key = self._get_rate_limit_key(ip)
        lock = self._get_shard_lock(key)
        async with lock:
            s = self._store.get(key)
            if s and s.active_conns > 0:
                s.active_conns -= 1

    def force_ban(self, ip: str, duration: float = None, request_id: str = None):
        key = self._get_rate_limit_key(ip)
        if duration is None:
            duration = self.cfg.ban_max
        self._ban_store[key] = time.monotonic() + duration
        s = self._store.get(key)
        if s:
            s.tokens = 0.0
            s.violations = 100
            s.last_time = time.monotonic()
        audit_logger.warning("FORCE_BAN %s %.0fs", ip, duration, extra={"request_id": request_id} if request_id else {})

    def is_banned(self, ip: str) -> bool:
        key = self._get_rate_limit_key(ip)
        ban_until = self._ban_store.get(key)
        return ban_until and ban_until > time.monotonic()

    def is_new_ip(self, ip: str) -> bool:
        key = self._get_rate_limit_key(ip)
        state = self._store.get(key)
        if state is None:
            return True
        return state.first_seen > 0 and (time.monotonic() - state.first_seen) < 300

# --------------------------------------------------------------------------- #
#  CIRCUIT BREAKER (with lock for HALF_OPEN transition)                       #
# --------------------------------------------------------------------------- #
class CircuitBreaker:

    def __init__(self, err_thr: int, window: float, probe_timeout: float):
        self.err_thr = err_thr
        self.window = window
        self.probe_timeout = probe_timeout
        self._errors = deque()
        self._last_failure = time.monotonic()
        self._state = "CLOSED"
        self._probe_in_progress = False
        self._probe_start_time = 0.0
        self._transition_lock = asyncio.Lock()

    def record_error(self):
        now = time.monotonic()
        self._errors.append(now)
        if len(self._errors) > self.err_thr + 10:
            self._errors.popleft()
        while self._errors and self._errors[0] < now - self.window:
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
            if now - self._last_failure >= self.probe_timeout:
                async with self._transition_lock:
                    if self._state == "OPEN" and not self._probe_in_progress:
                        self._probe_in_progress = True
                        self._state = "HALF_OPEN"
                        self._probe_start_time = now
                        return True
            return False
        if self._state == "HALF_OPEN":
            if now - self._probe_start_time > self.probe_timeout:
                async with self._transition_lock:
                    if self._state == "HALF_OPEN":
                        self._state = "OPEN"
                        self._probe_in_progress = False
                        self._last_failure = now
                        logger.error("Circuit breaker probe timed out, forcing OPEN")
            return False

# --------------------------------------------------------------------------- #
#  SENTINEL APP (all TCP drops use abort(), WAF fast-path)                   #
# --------------------------------------------------------------------------- #
class SentinelApp:

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session: Optional[ClientSession] = None
        self.rate_limiter = RateLimiter(cfg)
        self.cb = CircuitBreaker(cfg.cb_error_threshold, cfg.cb_window, cfg.cb_probe_timeout)
        self._cleanup_task = None
        self._health_task = None
        self._backend_healthy = True
        self.ip_obj_cache = FastTTLCache(maxsize=IP_OBJ_CACHE_MAXSIZE, ttl=IP_OBJ_CACHE_TTL)
        self.ip_class_cache = FastTTLCache(maxsize=IP_CLASS_CACHE_MAXSIZE, ttl=IP_CLASS_CACHE_TTL)
        self.per_ip_endpoint_cache = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=DEFAULT_PER_IP_ENDPOINT_TTL)
        self.global_per_ip_cache = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=DEFAULT_GLOBAL_PER_IP_TTL)
        self.unique_query_cache = FastTTLCache(maxsize=UNIQUE_QUERY_CACHE_MAXSIZE, ttl=UNIQUE_QUERY_CACHE_TTL)
        self._counter_locks = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]
        parsed_backend = urlparse(cfg.backend_url)
        self.backend_host = parsed_backend.hostname or "localhost"
        if parsed_backend.port:
            self.backend_host = f"{self.backend_host}:{parsed_backend.port}"
        self._shutdown_event = asyncio.Event()
        self._active_inbound = 0
        self._active_outbound = 0
        self._counter_lock = asyncio.Lock()
        self._metrics = {}
        self._reset_metrics()

    def _reset_metrics(self):
        self._metrics = {
            "requests": 0,
            "blocked": 0,
            "waf_hits": 0,
            "bans": 0,
        }

    def _get_counter_lock(self, key: str) -> asyncio.Lock:
        return self._counter_locks[hash(key) % SHARD_LOCK_COUNT]

    async def startup(self, app: web.Application):
        global waf_executor, listener, audit_listener

        try:
            with open(CFG.log_file, 'a'):
                pass
        except IOError:
            print(f"FATAL: Cannot write to log file {CFG.log_file}")
            sys.exit(1)

        if waf_executor is None:
            waf_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(WAF_MAX_WORKERS, (os.cpu_count() or 4) * 5)
            )

        if listener is None:
            fh = logging.handlers.RotatingFileHandler(
                CFG.log_file, maxBytes=100*1024*1024, backupCount=5, encoding="utf-8"
            )
            sh = logging.StreamHandler()
            fh.setFormatter(_formatter)
            sh.setFormatter(_formatter)
            listener = logging.handlers.QueueListener(log_queue, fh, sh, respect_handler_level=True)
            listener.start()

        if audit_listener is None:
            afh = logging.handlers.RotatingFileHandler(
                CFG.audit_log_file, maxBytes=100*1024*1024, backupCount=5, encoding="utf-8"
            )
            afh.setFormatter(_audit_formatter)
            audit_listener = logging.handlers.QueueListener(audit_log_queue, afh, respect_handler_level=True)
            audit_listener.start()

        app['waf_executor'] = waf_executor
        app['log_listener'] = listener
        app['audit_listener'] = audit_listener

        connector = TCPConnector(limit=self.cfg.backend_pool_size, ttl_dns_cache=300)
        timeout = ClientTimeout(total=self.cfg.backend_timeout, connect=5, sock_read=10, sock_connect=5)
        self.session = ClientSession(connector=connector, timeout=timeout, auto_decompress=False)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._health_task = asyncio.create_task(self._health_check_loop())

    async def shutdown(self, app: web.Application):
        self._shutdown_event.set()

        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        logger.info("Shutting down – waiting for in-flight requests...")
        try:
            for _ in range(int(self.cfg.shutdown_timeout * 10)):
                async with self._counter_lock:
                    if self._active_inbound == 0 and self._active_outbound == 0:
                        break
                await asyncio.sleep(0.1)
        except Exception:
            pass

        log_listener = app.get('log_listener')
        audit_listener_ref = app.get('audit_listener')
        if log_listener:
            log_listener.stop()
        if audit_listener_ref:
            audit_listener_ref.stop()

        if self.session:
            await self.session.close()

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        waf_exec = app.get('waf_executor')
        if waf_exec:
            waf_exec.shutdown(wait=True, timeout=30)
            logger.info("WAF executor shut down gracefully")

    async def _cleanup_loop(self):
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.cfg.cleanup_interval)
                break
            except asyncio.TimeoutError:
                pass
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, gc.collect)
            except Exception:
                pass

    async def _backend_health_check(self):
        try:
            async with self.session.get(f"{CFG.backend_url}/health", timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

    async def _health_check_loop(self):
        while not self._shutdown_event.is_set():
            self._backend_healthy = await self._backend_health_check()
            await asyncio.sleep(30)

    # ------------------------------------------------------------------- #
    #  Error response helper (includes X-Request-ID)                       #
    # ------------------------------------------------------------------- #
    def _err(self, request, status, text=""):
        headers = dict(BLOCK_HEADERS)
        headers['X-Request-ID'] = request.get('request_id', 'unknown')
        return web.Response(status=status, text=text, headers=headers)

    # ------------------------------------------------------------------- #
    #  IP EXTRACTION (optimised normalisation)                             #
    # ------------------------------------------------------------------- #
    @staticmethod
    def _normalize_ip(ip_str: str) -> str:
        if ':' not in ip_str:
            return ip_str
        if not ip_str.lower().startswith('::ffff:'):
            return ip_str
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                return str(ip.ipv4_mapped)
        except ValueError:
            pass
        return ip_str

    @staticmethod
    def _ip_matches_networks(ip_str: str, networks: Set) -> bool:
        ip = ipaddress.ip_address(SentinelApp._normalize_ip(ip_str))
        for net in networks:
            if ip in net:
                return True
        return False

    @staticmethod
    def get_real_ip(request: web.Request) -> str:
        remote = request.remote
        if not remote:
            return f"unknown-{id(request.transport)}"
        normalized = SentinelApp._normalize_ip(remote)
        if not SentinelApp._ip_matches_networks(normalized, CFG.trusted_proxies):
            return normalized
        cf_ip = request.headers.get("Cf-Connecting-Ip")
        if cf_ip:
            return SentinelApp._normalize_ip(cf_ip.strip())
        fwd = request.headers.get("X-Forwarded-For")
        if fwd:
            if len(fwd) > XFF_MAX_LENGTH:
                fwd = fwd[-XFF_MAX_LENGTH:]
            ips = [ip.strip() for ip in fwd.split(",") if ip.strip()]
            for ip_str in reversed(ips):
                clean_ip = SentinelApp._normalize_ip(ip_str.split('%')[0])
                try:
                    ip_obj = ipaddress.ip_address(clean_ip)
                except ValueError:
                    continue
                if any(ip_obj in net for net in CFG.trusted_proxies):
                    continue
                return clean_ip
        return normalized

    @staticmethod
    def _is_valid_transfer_encoding(headers: Dict) -> bool:
        te_values = headers.getall('Transfer-Encoding', [])
        if len(te_values) > 1:
            return False
        if te_values:
            te = te_values[0].strip().lower()
            if te not in ('chunked', 'identity'):
                return False
        return True

    @staticmethod
    def filter_hop(headers: Dict):
        hop_lower = {'transfer-encoding', 'connection', 'keep-alive', 'proxy-authenticate',
                     'proxy-authorization', 'te', 'trailers', 'upgrade', 'content-length'}
        conn_vals = headers.getall('Connection', [])
        for val in conn_vals:
            for directive in val.split(','):
                hop_lower.add(directive.strip().lower())
        for key in list(headers.keys()):
            if key.lower() in hop_lower:
                del headers[key]

    async def _classify_ip(self, ip_str: str, ip_obj) -> str:
        if ip_str in self.ip_class_cache:
            return self.ip_class_cache[ip_str]
        lock = self._get_counter_lock(ip_str)
        async with lock:
            if ip_str in self.ip_class_cache:
                return self.ip_class_cache[ip_str]
            if any(ip_obj in net for net in CFG.blacklist_ips):
                cls = "blacklist"
            elif any(ip_obj in net for net in CFG.whitelist_ips):
                cls = "whitelist"
            else:
                cls = "normal"
            self.ip_class_cache[ip_str] = cls
            return cls

    async def _blackhole(self, request: web.Request, ip: str, reason: str = "Banned") -> web.Response:
        async with self._counter_lock:
            self._metrics["blocked"] += 1
        remote = request.remote or "0.0.0.0"
        is_trusted_proxy = self._ip_matches_networks(self._normalize_ip(remote), CFG.trusted_proxies)
        if not is_trusted_proxy and request.transport and not request.transport.is_closing():
            try:
                request.transport.abort()
            except Exception:
                pass
        request_id = request.get('request_id', 'unknown')
        audit_logger.warning("BLACKHOLE %s reason=%s", ip, reason, extra={"request_id": request_id})
        return web.Response(status=444)

    async def handler(self, request: web.Request) -> web.Response:
        async with self._counter_lock:
            self._metrics["requests"] += 1

        request['request_id'] = str(uuid.uuid4())
        ip = self.get_real_ip(request)

        remote = self._normalize_ip(request.remote or "0.0.0.0")
        if request.path == "/metrics":
            if remote not in ("127.0.0.1", "::1"):
                return web.Response(status=403)
            return web.json_response(self._metrics)

        if self._shutdown_event.is_set():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return web.Response(status=444)

        if INBOUND_CONN_SEM.locked():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return web.Response(status=444)

        async with self._counter_lock:
            self._active_inbound += 1
        try:
            async with INBOUND_CONN_SEM:
                try:
                    return await asyncio.wait_for(
                        self._process_request(request),
                        timeout=CFG.backend_timeout + 5.0
                    )
                except asyncio.TimeoutError:
                    return await self._blackhole(request, ip, "Slowloris/Timeout")
                except asyncio.CancelledError:
                    raise
                except web.HTTPException:
                    raise
                except Exception as e:
                    logger.critical("Unhandled catastrophic error: %s", e, exc_info=True)
                    return await self._blackhole(request, ip, "Internal Error")
        finally:
            async with self._counter_lock:
                self._active_inbound -= 1

    async def _process_request(self, request: web.Request) -> web.Response:
        ip = self.get_real_ip(request)
        request_id = request.get('request_id', 'unknown')
        logger.debug("Request %s from %s", request_id, ip)

        if request.path == "/health":
            health_key = f"health:{ip}"
            lock = self._get_counter_lock(health_key)
            async with lock:
                cnt = self.per_ip_endpoint_cache.get(health_key) or 0
                if cnt > HEALTH_CHECK_LIMIT:
                    return self._err(request, 429, "Too Many Health Checks")
                self.per_ip_endpoint_cache[health_key] = cnt + 1
            return web.Response(text="OK" if self._backend_healthy else "DEGRADED",
                                status=200 if self._backend_healthy else 503)

        if not self._is_valid_transfer_encoding(request.headers):
            return self._err(request, 400, "Bad Request")
        if request.headers.get('Transfer-Encoding') and request.headers.get('Content-Length'):
            return self._err(request, 400, "Bad Request")

        total_headers_size = sum(len(k) + len(v) + 2 for k, v in request.headers.items())
        if total_headers_size > CFG.max_total_headers_size:
            return self._err(request, 400, "Headers too large")

        if len(request.path_qs) > CFG.max_uri_size:
            return self._err(request, 414, "URI Too Long")
        if len(request.headers) > CFG.max_headers:
            return self._err(request, 400, "Too Many Headers")
        for name, value in request.headers.items():
            if len(name) > 256 or len(value) > CFG.max_header_size:
                return self._err(request, 400, "Header Too Large")

        # Global per-IP limit (atomic)
        global_ip_key = f"global:{ip}"
        lock = self._get_counter_lock(global_ip_key)
        async with lock:
            global_ip_count = self.global_per_ip_cache.get(global_ip_key) or 0
            if global_ip_count > CFG.global_per_ip_limit:
                self.rate_limiter.force_ban(ip, self.cfg.ban_max, request_id)
                audit_logger.warning("GLOBAL_LIMIT_BAN %s", ip, extra={"request_id": request_id})
                return await self._blackhole(request, ip, "Global IP Limit Exceeded")
            self.global_per_ip_cache[global_ip_key] = global_ip_count + 1

        # Unique query tracking (tracks unique query strings per IP)
        if request.query_string:
            uq_key = f"uq:{ip}"
            lock = self._get_counter_lock(uq_key)
            async with lock:
                seen = self.unique_query_cache.get(uq_key)
                if seen is None:
                    seen = OrderedDict()
                    self.unique_query_cache[uq_key] = seen
                if request.query_string not in seen:
                    seen[request.query_string] = None
                    if len(seen) > UNIQUE_QUERY_THRESHOLD:
                        self.rate_limiter.force_ban(ip, request_id=request_id)
                        audit_logger.warning("SCRAPER_PATTERN %s unique=%d", ip, len(seen),
                                            extra={"request_id": request_id})
                        self.unique_query_cache[uq_key] = OrderedDict()   # free memory
                        return await self._blackhole(request, ip, "Scraper Pattern")

        # Per-IP endpoint limit (atomic, key hashed to control length)
        endpoint_hash = hash(request.path) & 0xFFFFFFFF
        endpoint_key = f"{ip}:{request.method}:{endpoint_hash}"
        lock = self._get_counter_lock(endpoint_key)
        async with lock:
            count_entry = self.per_ip_endpoint_cache.get(endpoint_key)
            count = count_entry if count_entry else 0
            if count > DEFAULT_PER_IP_ENDPOINT_LIMIT:
                return await self._blackhole(request, ip, "Endpoint Spam")
            self.per_ip_endpoint_cache[endpoint_key] = count + 1

        ip_obj = self.ip_obj_cache.get(ip)
        if not ip_obj:
            try:
                ip_obj = ipaddress.ip_address(ip)
                self.ip_obj_cache[ip] = ip_obj
            except ValueError:
                return self._err(request, 400, "Invalid IP")

        ip_class = await self._classify_ip(ip, ip_obj)
        if ip_class == "blacklist":
            audit_logger.warning("BLACKLIST_HIT %s %s", ip, request.path, extra={"request_id": request_id})
            return await self._blackhole(request, ip, "Blacklisted")

        # Whitelist: still rate limit, but do not write bans (avoid polluting subnet store)
        if ip_class == "whitelist":
            allowed, _, reason = await self.rate_limiter.check_and_acquire(
                ip, bypass_ban=True, bypass_ban_writes=True
            )
            if not allowed:
                if reason == "too_many_connections":
                    return self._err(request, 429, "Too many connections")
                return self._err(request, 429, "Too Many Requests")
            try:
                ok, resp, body_chunk = await self._filter(request, ip, skip_waf=False)
                if not ok:
                    return resp
                return await self._forward(request, ip, body_chunk)
            finally:
                await self.rate_limiter.dec_conn(ip)

        allowed, _, reason = await self.rate_limiter.check_and_acquire(ip)
        if not allowed:
            if reason == "banned":
                return await self._blackhole(request, ip, "Banned")
            elif reason == "too_many_connections":
                return self._err(request, 429, "Too many connections")
            else:
                return self._err(request, 429, "Too Many Requests")

        try:
            ok, resp, body_chunk = await self._filter(request, ip, skip_waf=False)
            if not ok:
                return resp

            if not await self.cb.allow():
                return self._err(request, 503, "Service Unavailable (circuit open)")

            return await self._forward(request, ip, body_chunk)
        finally:
            await self.rate_limiter.dec_conn(ip)

    @staticmethod
    def _is_text_content(content_type: Optional[str]) -> bool:
        if not content_type:
            return False
        ct = content_type.lower().split(';')[0].strip()
        if ct.startswith('text/'):
            return True
        if ct in ('application/json', 'application/xml', 'application/x-www-form-urlencoded'):
            return True
        return False

    async def _filter(self, request: web.Request, ip: str, skip_waf: bool = False) -> Tuple[bool, Optional[web.Response], Optional[bytes]]:
        if request.method not in CFG.allowed_methods:
            return False, self._err(request, 405), None

        ua = request.headers.get("User-Agent", "")
        if not ua:
            is_new = self.rate_limiter.is_new_ip(ip)
            if is_new and not request.headers.get('Accept'):
                return False, self._err(request, 403, "Empty User-Agent"), None

        ua_lower = ua.lower()
        if any(s in ua_lower for s in CFG.bad_ua_strings):
            return False, self._err(request, 403, "Forbidden"), None

        request_id = request.get('request_id', 'unknown')
        if CFG.enable_waf and not skip_waf:
            combined = f"{request.path}\x00{request.query_string}"[:WAF_INSPECT_SIZE]
            waf_result = await async_waf_check(combined)
            if waf_result == "ERROR":
                self.rate_limiter.force_ban(ip, request_id=request_id)
                audit_logger.warning("WAF_ERROR %s", ip, extra={"request_id": request_id})
                return False, self._err(request, 403, "WAF Error"), None
            elif waf_result:
                async with self._counter_lock:
                    self._metrics["waf_hits"] += 1
                audit_logger.warning("WAF_HIT %s %s %s", ip, waf_result, request.path, extra={"request_id": request_id})
                return False, self._err(request, 403, "WAF Blocked"), None

        body_chunk = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if CFG.enable_waf and not skip_waf and self._is_text_content(request.content_type):
                if WAF_SEM.locked():
                    logger.warning("WAF queue full – dropping %s", ip)
                    return False, await self._blackhole(request, ip, "WAF Overloaded"), None

                async with WAF_SEM:
                    content_length = request.content_length
                    if content_length is not None and content_length > WAF_INSPECT_SIZE:
                        self.rate_limiter.force_ban(ip, self.cfg.ban_max, request_id)
                        audit_logger.warning("PAYLOAD_TOO_LARGE %s", ip, extra={"request_id": request_id})
                        return False, self._err(request, 413, "Payload Too Large"), None

                    try:
                        body_chunk = await asyncio.wait_for(
                            request.content.read(WAF_INSPECT_SIZE),
                            timeout=CFG.waf_body_timeout
                        )
                    except web.HTTPRequestEntityTooLarge:
                        self.rate_limiter.force_ban(ip, self.cfg.ban_max, request_id)
                        audit_logger.warning("PAYLOAD_TOO_LARGE %s", ip, extra={"request_id": request_id})
                        return False, self._err(request, 413, "Payload Too Large"), None
                    except (asyncio.TimeoutError, TimeoutError):
                        return False, await self._blackhole(request, ip, "Body Read Timeout"), None
                    except Exception as e:
                        logger.error("Body read error: %s", e)
                        return False, self._err(request, 400), None

                    try:
                        body_exceeded = not request.content.at_eof()
                    except Exception:
                        body_exceeded = False
                    if body_chunk and body_exceeded:
                        self.rate_limiter.force_ban(ip, self.cfg.ban_max, request_id)
                        audit_logger.warning("PAYLOAD_TOO_LARGE (WAF limit) %s", ip, extra={"request_id": request_id})
                        return False, self._err(request, 413, "Payload Too Large"), None

                    if body_chunk:
                        text = body_chunk[:WAF_INSPECT_SIZE].decode('utf-8', 'ignore')
                        waf_result = await async_waf_check(text)
                        if waf_result == "ERROR":
                            self.rate_limiter.force_ban(ip, request_id=request_id)
                            audit_logger.warning("WAF_ERROR_BODY %s", ip, extra={"request_id": request_id})
                            return False, self._err(request, 403, "WAF Error"), None
                        elif waf_result:
                            async with self._counter_lock:
                                self._metrics["waf_hits"] += 1
                            audit_logger.warning("WAF_HIT_BODY %s %s %s", ip, waf_result, request.path, extra={"request_id": request_id})
                            return False, self._err(request, 403, "WAF Blocked"), None

                        if request.content_type and 'application/json' in request.content_type:
                            try:
                                obj = json.loads(text)
                                loop = asyncio.get_running_loop()
                                json_result = await loop.run_in_executor(
                                    waf_executor, _json_scan, obj, 10
                                )
                                if json_result:
                                    async with self._counter_lock:
                                        self._metrics["waf_hits"] += 1
                                    audit_logger.warning("WAF_HIT_JSON %s %s %s", ip, json_result, request.path, extra={"request_id": request_id})
                                    return False, self._err(request, 403, "WAF Blocked JSON"), None
                            except (ValueError, TypeError):
                                pass

        return True, None, body_chunk

    async def _forward(self, request: web.Request, ip: str, body_chunk: Optional[bytes]) -> web.Response:
        path = request.path_qs
        if CFG.backend_url.endswith('/') and path.startswith('/'):
            url = CFG.backend_url + path[1:]
        else:
            url = CFG.backend_url + path

        headers = request.headers.copy()
        headers['Host'] = self.backend_host
        self.filter_hop(headers)
        headers['X-Request-ID'] = request.get('request_id', 'unknown')

        existing = headers.get('X-Forwarded-For', '')
        if len(existing) > XFF_MAX_LENGTH:
            existing = existing[-XFF_MAX_LENGTH:]
        ips = [ip.strip() for ip in existing.split(',') if ip.strip()] if existing else []
        if len(ips) > XFF_MAX_IPS:
            existing = ", ".join(ips[-XFF_MAX_IPS:])
            headers['X-Forwarded-For'] = existing

        remote_addr = self._normalize_ip(request.remote or "0.0.0.0")
        if remote_addr not in ips:
            headers['X-Forwarded-For'] = f"{existing}, {remote_addr}" if existing else remote_addr

        if OUTBOUND_REQ_SEM.locked():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return self._err(request, 444)

        can_retry = request.method in ("GET", "HEAD")
        max_attempts = BACKEND_MAX_RETRIES + 1 if can_retry else 1

        last_exception = None
        async with self._counter_lock:
            self._active_outbound += 1
        try:
            async with OUTBOUND_REQ_SEM:
                for attempt in range(max_attempts):
                    try:
                        async with self.session.request(
                            request.method, url, headers=headers,
                            data=self._make_body_stream(body_chunk, request),
                            allow_redirects=False,
                            ssl=CFG.verify_ssl
                        ) as resp:
                            if resp.status >= 500:
                                self.cb.record_error()
                                logger.warning("Backend %d for %s", resp.status, ip)
                            else:
                                self.cb.record_success()

                            backend_headers = resp.headers.copy()
                            self.filter_hop(backend_headers)
                            backend_headers.pop('Server', None)
                            backend_headers.pop('X-Powered-By', None)
                            if CFG.server_header:
                                backend_headers['Server'] = CFG.server_header

                            client_resp = web.StreamResponse(status=resp.status, headers=backend_headers)
                            await client_resp.prepare(request)

                            try:
                                async def stream_response():
                                    async for chunk in resp.content.iter_chunked(STREAM_CHUNK_SIZE):
                                        await client_resp.write(chunk)
                                    await client_resp.write_eof()

                                await asyncio.wait_for(stream_response(), timeout=CFG.backend_timeout)
                            except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError,
                                    BrokenPipeError, asyncio.IncompleteReadError, ClientError):
                                logger.debug("Client connection interrupted: %s", ip)
                                if request.transport and not request.transport.is_closing():
                                    request.transport.abort()
                                return client_resp

                            return client_resp
                    except (ClientError, asyncio.TimeoutError) as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning("Backend request attempt %d failed for %s: %s", attempt+1, ip, e)
                            await asyncio.sleep(0.1 * (attempt + 1))
                        else:
                            break

            self.cb.record_error()
            if isinstance(last_exception, asyncio.TimeoutError):
                logger.error("Backend timeout after %d attempts for %s", max_attempts, ip)
                return self._err(request, 504, "Gateway Timeout")
            else:
                logger.error("Backend connection error after %d attempts for %s: %s", max_attempts, ip, last_exception)
                return self._err(request, 502, "Bad Gateway")
        finally:
            async with self._counter_lock:
                self._active_outbound -= 1

    @staticmethod
    def _make_body_stream(body_chunk: Optional[bytes], request: web.Request):
        async def _stream():
            if body_chunk:
                yield body_chunk
            async for chunk in request.content.iter_chunked(STREAM_CHUNK_SIZE):
                yield chunk
        return _stream()

# --------------------------------------------------------------------------- #
#  APPLICATION FACTORY                                                        #
# --------------------------------------------------------------------------- #
def create_app():
    sentinel = SentinelApp(CFG)
    app = web.Application(client_max_size=CFG.max_body_size)
    app.on_startup.append(sentinel.startup)
    app.on_cleanup.append(sentinel.shutdown)
    app.router.add_route("*", "/{tail:.*}", sentinel.handler)
    return app

if __name__ == "__main__":
    handler_args = {
        'keepalive_timeout': KEEPALIVE_TIMEOUT,
        'slow_request_timeout': SLOW_REQUEST_TIMEOUT
    }
    web.run_app(create_app(), host=CFG.listen_host, port=CFG.listen_port,
                handle_signals=True, handler_args=handler_args)
