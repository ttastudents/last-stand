#!/usr/bin/env python3
"""
Sentinel Guard v21.8 – Last Stand Absolute (P4 code quality & maintainability)
Production‑hardened, single‑file Python async anti‑DDoS layer‑7 wall.
Works on Linux, Windows, macOS – no C‑extensions, no root.
Requires: aiohttp >= 3.8, Python 3.9+
"""

import asyncio
import concurrent.futures
import ipaddress
import logging
import logging.handlers
import os
import queue
import re
import sys
import time
from collections import deque, OrderedDict
from typing import Dict, Optional, Set, Tuple, Any
from urllib.parse import unquote, urlparse

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector, ClientError

# --------------------------------------------------------------------------- #
#  Constants (replace magic numbers)                                           #
# --------------------------------------------------------------------------- #
# FastTTLCache defaults
DEFAULT_CACHE_MAXSIZE = 100_000
DEFAULT_CACHE_TTL = 3600

# Rate limiter
DEFAULT_RATE_LIMIT = 50.0
DEFAULT_BURST_LIMIT = 100.0
DEFAULT_MAX_CONN_PER_IP = 30
DEFAULT_BAN_BASE = 60.0
DEFAULT_BAN_MULT = 2.0
DEFAULT_BAN_MAX = 3600.0
DEFAULT_VIOLATIONS_DECAY = 3600.0

# Request limits
DEFAULT_MAX_BODY_SIZE = 1_048_576  # 1 MB
DEFAULT_MAX_HEADER_SIZE = 8192
DEFAULT_MAX_HEADERS = 100
DEFAULT_MAX_URI_SIZE = 4096
DEFAULT_MAX_TOTAL_HEADERS_SIZE = 65536

# WAF
WAF_INSPECT_SIZE = 8192          # bytes to check in body/headers
WAF_BODY_TIMEOUT = 5.0           # seconds
WAF_MAX_WORKERS = 64             # upper bound of thread pool workers

# Endpoint shield
DEFAULT_PER_IP_ENDPOINT_LIMIT = 30   # requests per minute per IP per endpoint
DEFAULT_PER_IP_ENDPOINT_TTL = 60     # seconds

# Global endpoint limit
DEFAULT_GLOBAL_ENDPOINT_LIMIT = 300

# Health check
HEALTH_CHECK_LIMIT = 10               # per IP per minute
HEALTH_CHECK_TTL = 60

# Connection limits (will be recalculated from FD limit)
MAX_SAFE_CONNS_LINUX = 15000
MAX_SAFE_CONNS_WINDOWS = 5000

# Semaphore multipliers
WAF_SEM_MULTIPLIER = 2
OUTBOUND_SEM_BASE = 100

# Cleanup
DEFAULT_CLEANUP_INTERVAL = 300

# Circuit breaker
DEFAULT_CB_ERROR_THRESHOLD = 5
DEFAULT_CB_WINDOW = 60
DEFAULT_CB_PROBE_TIMEOUT = 30

# Forwarding
XFF_MAX_LENGTH = 2048
XFF_MAX_IPS = 50
STREAM_CHUNK_SIZE = 8192
BACKEND_TIMEOUT = 30.0

# HTTP server
KEEPALIVE_TIMEOUT = 15
SLOW_REQUEST_TIMEOUT = 10

# Logging
DEFAULT_LOG_QUEUE_MAXSIZE = 5000

# Ban stores
BAN_STORE_MAXSIZE = 500_000
BAN_STORE_TTL = 86400  # 24 hours
STATE_STORE_MAXSIZE = 100_000
STATE_STORE_TTL = 3600  # 1 hour

# Rate limit key cache
KEY_CACHE_MAXSIZE = 50_000
KEY_CACHE_TTL = 600

# IP object cache
IP_OBJ_CACHE_MAXSIZE = 100_000
IP_OBJ_CACHE_TTL = 3600

# Classification cache
IP_CLASS_CACHE_MAXSIZE = 100_000
IP_CLASS_CACHE_TTL = 3600

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
    """A fast, LRU‑based TTL cache using OrderedDict.

    Provides O(1) get/set/contains with lazy expiration.
    """
    __slots__ = ('_data', '_maxsize', '_ttl')

    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE, ttl: float = DEFAULT_CACHE_TTL):
        self._data = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str):
        """Return value if key exists and not expired, else None."""
        item = self._data.get(key)
        if not item:
            return None
        if item[1] < time.monotonic():
            del self._data[key]
            return None
        self._data.move_to_end(key)   # LRU promotion
        return item[0]

    def __setitem__(self, key: str, value):
        """Insert or update a key with current timestamp + TTL."""
        if key in self._data:
            self._data.move_to_end(key)
        elif len(self._data) >= self._maxsize:
            self._data.popitem(last=False)   # evict oldest
        self._data[key] = (value, time.monotonic() + self._ttl)

    def __getitem__(self, key: str):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: str):
        """Non‑mutating membership test."""
        item = self._data.get(key)
        if not item:
            return False
        return item[1] >= time.monotonic()

# --------------------------------------------------------------------------- #
#  CONFIGURATION (safe environment parsing, validated ranges)                 #
# --------------------------------------------------------------------------- #
class Config:
    """Application configuration loaded from environment variables."""

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
                logging.warning("Invalid IP/network in config: %s", entry)
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

        self.bad_ua_patterns = [
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "scan", "botnet", "crawler"
        ]
        custom_ua = os.getenv("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_patterns.extend([p.strip().lower() for p in custom_ua.split(",") if p.strip()])

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

        self.global_endpoint_limit = self._safe_int(os.getenv("GLOBAL_ENDPOINT_LIMIT", ""), DEFAULT_GLOBAL_ENDPOINT_LIMIT, 0)
        self.server_header = os.getenv("SERVER_HEADER", "Sentinel-Guard")
        self.shutdown_timeout = self._safe_float(os.getenv("SHUTDOWN_TIMEOUT", ""), 30.0, 1.0)

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
#  LOGGING (non‑blocking handlers, separate audit log)                        #
# --------------------------------------------------------------------------- #
class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    """Queue handler that drops log records when queue is full."""
    def emit(self, record):
        try:
            self.enqueue(record)
        except queue.Full:
            pass

# Main logger
queue_handler = NonBlockingQueueHandler(log_queue)
logger = logging.getLogger("Sentinel")
logger.setLevel(CFG.log_level)
logger.addHandler(queue_handler)

# Security audit logger (separate file, always WARNING)
audit_queue_handler = NonBlockingQueueHandler(audit_log_queue)
audit_logger = logging.getLogger("Sentinel.Audit")
audit_logger.setLevel("WARNING")
audit_logger.addHandler(audit_queue_handler)
audit_logger.propagate = False

_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
_audit_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# --------------------------------------------------------------------------- #
#  PURE PYTHON MICRO‑WAF ENGINE (hardened patterns)                          #
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

def _decode_aggressive(data: str) -> str:
    """Multi‑layer URL decode + UTF‑16/32 detection."""
    cleaned = data
    for _ in range(5):
        new_cleaned = unquote(cleaned)
        if new_cleaned == cleaned:
            break
        cleaned = new_cleaned

    if '\x00' in cleaned:
        for encoding in ('utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be'):
            try:
                decoded = cleaned.encode('latin-1').decode(encoding)
                cleaned = decoded
                break
            except:
                pass

    cleaned = cleaned.replace('\x00', '').replace('\r', '').replace('\n', '')
    return cleaned

def waf_check(data: str) -> Optional[str]:
    """Check data for SQLi or XSS patterns. Returns 'SQLi', 'XSS', 'ERROR', or None."""
    if not CFG.enable_waf or not data:
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
    except Exception as e:
        logger.error("Micro-WAF execution error: %s", e)
        return "ERROR"

    return None

async def async_waf_check(data: str) -> Optional[str]:
    """Run waf_check in thread pool to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(waf_executor, waf_check, data)

# --------------------------------------------------------------------------- #
#  RATE LIMITER & IP STATE (per‑key locks, subnet‑aware)                      #
# --------------------------------------------------------------------------- #
class IPState:
    """Tracks token bucket and violation state for a single IP/subnet."""
    __slots__ = ("tokens","last_time","violations","last_violation_time","active_conns")
    def __init__(self, burst: float):
        self.tokens = burst
        self.last_time = time.monotonic()
        self.violations = 0
        self.last_violation_time = 0.0
        self.active_conns = 0

class RateLimiter:
    """Token‑bucket rate limiter with automatic banning and IPv4/IPv6 subnet grouping."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._store = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=STATE_STORE_TTL)
        self._ban_store = FastTTLCache(maxsize=BAN_STORE_MAXSIZE, ttl=BAN_STORE_TTL)
        self._locks: Dict[str, asyncio.Lock] = {}
        self._key_cache = FastTTLCache(maxsize=KEY_CACHE_MAXSIZE, ttl=KEY_CACHE_TTL)

    def _get_rate_limit_key(self, ip_str: str) -> str:
        """Map IP to a subnet‑based key to prevent IP rotation."""
        key = self._key_cache.get(ip_str)
        if key is not None:
            return key
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                network = ipaddress.ip_network(f"{ip_str}/64", strict=False)
                key = str(network.network_address)
            else:
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                key = str(network.network_address)
        except ValueError:
            key = ip_str
        self._key_cache[ip_str] = key
        return key

    def _get_lock(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def _get(self, key: str) -> IPState:
        state = self._store.get(key)
        if state is None:
            state = IPState(self.cfg.burst_limit)
            self._store[key] = state
        return state

    async def check_and_acquire(self, ip: str) -> Tuple[bool, float, str]:
        """Atomically check ban, connection limit, and token acquisition."""
        key = self._get_rate_limit_key(ip)
        lock = self._get_lock(key)
        async with lock:
            now = time.monotonic()
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

    def dec_conn(self, ip: str):
        key = self._get_rate_limit_key(ip)
        s = self._store.get(key)
        if s and s.active_conns > 0:
            s.active_conns -= 1

    def force_ban(self, ip: str, duration: float = None):
        """Immediately ban an IP, regardless of current state."""
        key = self._get_rate_limit_key(ip)
        if duration is None:
            duration = self.cfg.ban_max
        self._ban_store[key] = time.monotonic() + duration
        s = self._store.get(key)
        if s:
            s.tokens = 0.0
            s.violations = 100
            s.last_time = time.monotonic()
        audit_logger.warning("FORCE_BAN %s %.0fs", ip, duration)

    def is_banned(self, ip: str) -> bool:
        key = self._get_rate_limit_key(ip)
        ban_until = self._ban_store.get(key)
        return ban_until and ban_until > time.monotonic()

    async def cleanup_expired_bans(self):
        """Remove stale entries from all stores."""
        now = time.monotonic()
        for store in (self._ban_store, self._store, self._key_cache):
            expired_keys = [k for k, (_, exp) in store._data.items() if exp < now]
            for k in expired_keys:
                try:
                    del store._data[k]
                except KeyError:
                    pass
            await asyncio.sleep(0)

# --------------------------------------------------------------------------- #
#  CIRCUIT BREAKER (with lock for HALF_OPEN transition)                       #
# --------------------------------------------------------------------------- #
class CircuitBreaker:
    """Circuit breaker to prevent cascading failures to backend."""

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
        """Return True if a request may proceed to the backend."""
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
#  SENTINEL APP (main reverse proxy application)                              #
# --------------------------------------------------------------------------- #
class SentinelApp:
    """Core reverse proxy with integrated WAF, rate limiter, and circuit breaker."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session: Optional[ClientSession] = None
        self.rate_limiter = RateLimiter(cfg)
        self.cb = CircuitBreaker(cfg.cb_error_threshold, cfg.cb_window, cfg.cb_probe_timeout)
        self._cleanup_task = None
        self.ip_obj_cache = FastTTLCache(maxsize=IP_OBJ_CACHE_MAXSIZE, ttl=IP_OBJ_CACHE_TTL)
        self.ip_class_cache = FastTTLCache(maxsize=IP_CLASS_CACHE_MAXSIZE, ttl=IP_CLASS_CACHE_TTL)
        self.per_ip_endpoint_cache = FastTTLCache(maxsize=STATE_STORE_MAXSIZE, ttl=DEFAULT_PER_IP_ENDPOINT_TTL)
        parsed_backend = urlparse(cfg.backend_url)
        self.backend_host = parsed_backend.hostname or "localhost"
        if parsed_backend.port:
            self.backend_host = f"{self.backend_host}:{parsed_backend.port}"
        self._shutdown_event = asyncio.Event()

    async def startup(self, app: web.Application):
        """Initialize resources and start background tasks."""
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
            fh = logging.FileHandler(CFG.log_file, encoding="utf-8")
            sh = logging.StreamHandler()
            fh.setFormatter(_formatter)
            sh.setFormatter(_formatter)
            listener = logging.handlers.QueueListener(log_queue, fh, sh, respect_handler_level=True)
            listener.start()

        if audit_listener is None:
            afh = logging.FileHandler(CFG.audit_log_file, encoding="utf-8")
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

    async def shutdown(self, app: web.Application):
        """Gracefully stop the service: wait for in‑flight requests, then clean up."""
        self._shutdown_event.set()

        logger.info("Shutting down – waiting for in-flight requests...")
        try:
            for _ in range(int(self.cfg.shutdown_timeout * 10)):
                if INBOUND_CONN_SEM._value == MAX_SAFE_CONNS and OUTBOUND_REQ_SEM._value == CFG.backend_pool_size:
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
        """Periodically purge expired cache entries."""
        while True:
            await asyncio.sleep(self.cfg.cleanup_interval)
            await self.rate_limiter.cleanup_expired_bans()

    # ------------------------------------------------------------------- #
    #  IP EXTRACTION – Cloudflare‑aware, IPv4‑mapped IPv6 handling        #
    # ------------------------------------------------------------------- #
    @staticmethod
    def _normalize_ip(ip_str: str) -> str:
        """Convert IPv4‑mapped IPv6 addresses to plain IPv4."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                return str(ip.ipv4_mapped)
            return ip_str
        except ValueError:
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
        """Extract the real client IP, honoring Cloudflare and X-Forwarded-For."""
        remote = request.remote or "0.0.0.0"
        normalized = SentinelApp._normalize_ip(remote)
        if not SentinelApp._ip_matches_networks(normalized, CFG.trusted_proxies):
            return normalized
        cf_ip = request.headers.get("Cf-Connecting-Ip")
        if cf_ip:
            return SentinelApp._normalize_ip(cf_ip.strip())
        fwd = request.headers.get("X-Forwarded-For")
        if fwd:
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
    def filter_hop(headers: Dict):
        """Remove hop‑by‑hop headers before forwarding."""
        hop_lower = {'transfer-encoding', 'connection', 'keep-alive', 'proxy-authenticate',
                     'proxy-authorization', 'te', 'trailers', 'upgrade', 'content-length'}
        conn_vals = headers.getall('Connection', [])
        for val in conn_vals:
            for directive in val.split(','):
                hop_lower.add(directive.strip().lower())
        for key in list(headers.keys()):
            if key.lower() in hop_lower:
                del headers[key]

    def _classify_ip(self, ip_str: str, ip_obj) -> str:
        """Classify IP as blacklist, whitelist, or normal (with caching)."""
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

    async def _blackhole(self, request: web.Request, reason: str = "Banned") -> web.Response:
        """Immediately drop the connection (TCP RST) unless behind a trusted proxy."""
        remote = request.remote or "0.0.0.0"
        is_trusted_proxy = self._ip_matches_networks(self._normalize_ip(remote), CFG.trusted_proxies)
        if not is_trusted_proxy and request.transport and not request.transport.is_closing():
            try:
                request.transport.abort()
            except Exception:
                pass
        return web.Response(status=444)

    async def handler(self, request: web.Request) -> web.Response:
        """Main request handler: concurrency limit, routing, and timeout."""
        if self._shutdown_event.is_set():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return web.Response(status=444)

        if INBOUND_CONN_SEM.locked():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return web.Response(status=444)

        async with INBOUND_CONN_SEM:
            try:
                return await asyncio.wait_for(
                    self._process_request(request),
                    timeout=CFG.backend_timeout + 5.0
                )
            except asyncio.TimeoutError:
                return await self._blackhole(request, "Slowloris/Timeout")
            except asyncio.CancelledError:
                raise
            except web.HTTPException:
                raise
            except Exception as e:
                logger.critical("Unhandled catastrophic error: %s", e, exc_info=True)
                return await self._blackhole(request, "Internal Error")

    async def _process_request(self, request: web.Request) -> web.Response:
        """Core request processing: validation, rate limiting, WAF, forwarding."""
        ip = self.get_real_ip(request)

        if request.path == "/health":
            health_key = f"health:{ip}"
            cnt = self.per_ip_endpoint_cache.get(health_key) or 0
            if cnt > HEALTH_CHECK_LIMIT:
                return web.Response(status=429, text="Too Many Health Checks", headers=BLOCK_HEADERS)
            self.per_ip_endpoint_cache[health_key] = cnt + 1
            return web.Response(text="OK")

        if request.headers.get('Transfer-Encoding') and request.headers.get('Content-Length'):
            return web.Response(status=400, text="Bad Request", headers=BLOCK_HEADERS)

        total_headers_size = sum(len(k) + len(v) + 2 for k, v in request.headers.items())
        if total_headers_size > CFG.max_total_headers_size:
            return web.Response(status=400, text="Headers too large", headers=BLOCK_HEADERS)

        if len(request.path_qs) > CFG.max_uri_size:
            return web.Response(status=414, text="URI Too Long", headers=BLOCK_HEADERS)
        if len(request.headers) > CFG.max_headers:
            return web.Response(status=400, text="Too Many Headers", headers=BLOCK_HEADERS)
        for name, value in request.headers.items():
            if len(name) > 256 or len(value) > CFG.max_header_size:
                return web.Response(status=400, text="Header Too Large", headers=BLOCK_HEADERS)

        endpoint_key = f"{ip}:{request.method}:{request.path}"
        count_entry = self.per_ip_endpoint_cache.get(endpoint_key)
        count = count_entry if count_entry else 0
        if count > DEFAULT_PER_IP_ENDPOINT_LIMIT:
            return await self._blackhole(request, "Endpoint Spam")
        self.per_ip_endpoint_cache[endpoint_key] = count + 1

        ip_obj = self.ip_obj_cache.get(ip)
        if not ip_obj:
            try:
                ip_obj = ipaddress.ip_address(ip)
                self.ip_obj_cache[ip] = ip_obj
            except ValueError:
                return web.Response(status=400, text="Invalid IP", headers=BLOCK_HEADERS)

        ip_class = self._classify_ip(ip, ip_obj)
        if ip_class == "blacklist":
            audit_logger.warning("BLACKLIST_HIT %s %s", ip, request.path)
            return await self._blackhole(request, "Blacklisted")

        if ip_class == "whitelist":
            ok, resp, body_chunk = await self._filter(request, ip, skip_waf=False)
            if not ok:
                return resp
            return await self._forward(request, ip, body_chunk)

        allowed, _, reason = await self.rate_limiter.check_and_acquire(ip)
        if not allowed:
            if reason == "banned":
                return await self._blackhole(request, "Banned")
            elif reason == "too_many_connections":
                return web.Response(status=429, text="Too many connections", headers=BLOCK_HEADERS)
            else:
                return web.Response(status=429, text="Too Many Requests", headers=BLOCK_HEADERS)

        try:
            ok, resp, body_chunk = await self._filter(request, ip, skip_waf=False)
            if not ok:
                return resp

            if not await self.cb.allow():
                return web.Response(status=503, text="Service Unavailable (circuit open)", headers=BLOCK_HEADERS)

            return await self._forward(request, ip, body_chunk)
        finally:
            self.rate_limiter.dec_conn(ip)

    async def _filter(self, request: web.Request, ip: str, skip_waf: bool = False) -> Tuple[bool, Optional[web.Response], Optional[bytes]]:
        """Run method, UA, WAF checks, and optionally read body for WAF inspection."""
        if request.method not in CFG.allowed_methods:
            return False, web.Response(status=405, headers=BLOCK_HEADERS), None

        ua = request.headers.get("User-Agent", "")
        if not ua:
            return False, web.Response(status=403, text="Empty User-Agent", headers=BLOCK_HEADERS), None
        ua_lower = ua.lower()
        if any(bad in ua_lower for bad in CFG.bad_ua_patterns):
            return False, web.Response(status=403, text="Forbidden", headers=BLOCK_HEADERS), None

        if CFG.enable_waf and not skip_waf:
            combined = "\x00".join([
                request.path,
                request.query_string,
                request.headers.get("Cookie", ""),
                request.headers.get("Referer", ""),
                request.headers.get("X-Forwarded-For", "")
            ])[:WAF_INSPECT_SIZE]
            waf_result = await async_waf_check(combined)
            if waf_result == "ERROR":
                self.rate_limiter.force_ban(ip)
                audit_logger.warning("WAF_ERROR %s", ip)
                return False, web.Response(status=403, text="WAF Error", headers=BLOCK_HEADERS), None
            elif waf_result:
                audit_logger.warning("WAF_HIT %s %s %s", ip, waf_result, request.path)
                return False, web.Response(status=403, text="WAF Blocked", headers=BLOCK_HEADERS), None

        body_chunk = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if WAF_SEM.locked():
                logger.warning("WAF queue full – dropping %s", ip)
                return False, await self._blackhole(request, "WAF Overloaded"), None

            async with WAF_SEM:
                try:
                    body_chunk = await asyncio.wait_for(request.read(), timeout=CFG.waf_body_timeout)
                except web.HTTPRequestEntityTooLarge:
                    self.rate_limiter.force_ban(ip, self.cfg.ban_max)
                    audit_logger.warning("PAYLOAD_TOO_LARGE %s", ip)
                    return False, web.Response(status=413, text="Payload Too Large", headers=BLOCK_HEADERS), None
                except (asyncio.TimeoutError, TimeoutError):
                    return False, await self._blackhole(request, "Body Read Timeout"), None
                except Exception as e:
                    logger.error("Body read error: %s", e)
                    return False, web.Response(status=400, headers=BLOCK_HEADERS), None

                if CFG.enable_waf and body_chunk:
                    text = body_chunk[:WAF_INSPECT_SIZE].decode('utf-8', 'ignore')
                    waf_result = await async_waf_check(text)
                    if waf_result == "ERROR":
                        self.rate_limiter.force_ban(ip)
                        audit_logger.warning("WAF_ERROR_BODY %s", ip)
                        return False, web.Response(status=403, text="WAF Error", headers=BLOCK_HEADERS), None
                    elif waf_result:
                        audit_logger.warning("WAF_HIT_BODY %s %s %s", ip, waf_result, request.path)
                        return False, web.Response(status=403, text="WAF Blocked", headers=BLOCK_HEADERS), None

        return True, None, body_chunk

    async def _forward(self, request: web.Request, ip: str, body_chunk: Optional[bytes]) -> web.Response:
        """Forward the request to the backend and stream the response back."""
        path = request.path_qs
        if CFG.backend_url.endswith('/') and path.startswith('/'):
            url = CFG.backend_url + path[1:]
        else:
            url = CFG.backend_url + path

        headers = request.headers.copy()
        headers['Host'] = self.backend_host
        self.filter_hop(headers)

        existing = headers.get('X-Forwarded-For', '')
        if len(existing) > XFF_MAX_LENGTH:
            ips = [ip.strip() for ip in existing.split(',') if ip.strip()]
            if len(ips) > XFF_MAX_IPS:
                existing = ", ".join(ips[-XFF_MAX_IPS:])
                headers['X-Forwarded-For'] = existing

        remote_addr = self._normalize_ip(request.remote or "0.0.0.0")
        existing_ips = [x.strip() for x in existing.split(",") if x.strip()] if existing else []
        if remote_addr not in existing_ips:
            headers['X-Forwarded-For'] = f"{existing}, {remote_addr}" if existing else remote_addr

        if OUTBOUND_REQ_SEM.locked():
            if request.transport and not request.transport.is_closing():
                request.transport.abort()
            return web.Response(status=444)

        async with OUTBOUND_REQ_SEM:
            try:
                resp = await self.session.request(
                    request.method, url, headers=headers,
                    data=body_chunk, allow_redirects=False,
                    ssl=CFG.verify_ssl
                )
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
            except ClientError as e:
                self.cb.record_error()
                logger.error("Backend connection error for %s: %s", ip, e)
                return web.Response(status=502, text="Bad Gateway", headers=BLOCK_HEADERS)
            except asyncio.TimeoutError:
                self.cb.record_error()
                return web.Response(status=504, text="Gateway Timeout", headers=BLOCK_HEADERS)

# --------------------------------------------------------------------------- #
#  APPLICATION FACTORY                                                        #
# --------------------------------------------------------------------------- #
def create_app():
    """Build and return the aiohttp Application instance."""
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
