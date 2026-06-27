#!/usr/bin/env python3
"""
Sentinel Guard v23.8 – Last Stand Absolute (Cache leak fix)
Production‑hardened, single‑file Python async anti‑DDoS layer‑7 wall.
Works on Linux, Windows, macOS – no C‑extensions, no root required.
Tested with: aiohttp >= 3.8, Python 3.9+.
"""

import asyncio
import concurrent.futures
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
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector, ClientError

try:
    from aiohttp import ClientPayloadError, ClientDisconnectedError
except ImportError:
    ClientPayloadError = ClientError
    ClientDisconnectedError = ClientError

# --------------------------------------------------------------------------- #
#  Constants                                                                    #
# --------------------------------------------------------------------------- #
DEFAULT_CACHE_MAXSIZE = 100_000
DEFAULT_CACHE_TTL = 3600

DEFAULT_RATE_LIMIT = 200.0
DEFAULT_BURST_LIMIT = 400.0
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
WAF_REGEX_TIMEOUT = 2.0

DEFAULT_PER_IP_ENDPOINT_LIMIT = 120
DEFAULT_PER_IP_ENDPOINT_TTL = 60

DEFAULT_GLOBAL_PER_IP_LIMIT = 500
DEFAULT_GLOBAL_PER_IP_TTL = 60

HEALTH_CHECK_LIMIT = 30
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
SLOW_REQUEST_TIMEOUT = 8

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
UNIQUE_QUERY_THRESHOLD = 50

SHARD_LOCK_COUNT = 1024

BACKEND_MAX_RETRIES = 2

MAX_JSON_ELEMENTS = 1000
MAX_JSON_DEPTH = 10

ALLOWED_HTTP_VERSIONS = frozenset({(1, 0), (1, 1)})

SUSPICIOUS_CHARS = set("'<>();-=%&|`\\/\t\r\n\x00*?!#.")
_SQLI_KEYWORDS = (
    "union", "select", "insert", "update", "delete", "drop",
    "sleep", "benchmark", "waitfor", "information_schema",
    "__proto__", "javascript", "<script"
)

# --------------------------------------------------------------------------- #
#  Raise file descriptor limit (non‑fatal)                                     #
# --------------------------------------------------------------------------- #
if sys.platform != "win32":
    try:
        import resource
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
        except (ValueError, PermissionError):
            pass
    except ImportError:
        pass

# --------------------------------------------------------------------------- #
#  Fast LRU + TTL cache (plain dict, no OrderedDict overhead)                  #
# --------------------------------------------------------------------------- #
class FastTTLCache:
    __slots__ = ("_data", "_maxsize", "_ttl")

    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE, ttl: float = DEFAULT_CACHE_TTL):
        self._data: Dict[str, Tuple[object, float]] = {}
        self._maxsize = maxsize
        self._ttl = ttl

    def get(self, key: str):
        item = self._data.get(key)
        if not item:
            return None
        if item[1] < time.monotonic():
            del self._data[key]
            return None
        return item[0]

    def __setitem__(self, key: str, value):
        if len(self._data) >= self._maxsize:
            batch = max(1, self._maxsize // 10)
            for _ in range(batch):
                if not self._data:
                    break
                self._data.pop(next(iter(self._data)), None)
        self._data[key] = (value, time.monotonic() + self._ttl)

    def __getitem__(self, key: str):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __contains__(self, key: str) -> bool:
        item = self._data.get(key)
        return bool(item) and item[1] >= time.monotonic()

    def items(self):
        return self._data.items()

    def __len__(self) -> int:
        return len(self._data)


# --------------------------------------------------------------------------- #
#  Configuration                                                               #
# --------------------------------------------------------------------------- #
class Config:
    @staticmethod
    def _safe_int(val, default: int, min_val: int = None, max_val: int = None) -> int:
        try:
            v = int(val) if val else default
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
            v = float(val) if val else default
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
        if self.listen_port < 1024 and sys.platform != "win32":
            try:
                if os.geteuid() != 0:
                    print("WARNING: Listening on port < 1024 requires root privileges.")
            except AttributeError:
                pass

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

        env_methods = os.getenv("ALLOWED_METHODS", "GET,POST,HEAD,PUT,DELETE,OPTIONS,PATCH")
        self.allowed_methods = set(
            m.strip().upper() for m in env_methods.split(",") if m.strip()
        )
        self.allowed_methods.discard("CONNECT")
        self.allowed_methods.discard("TRACE")
        self.allowed_methods.discard("TRACK")

        self.max_header_size = self._safe_int(os.getenv("MAX_HEADER_SIZE", ""), DEFAULT_MAX_HEADER_SIZE, 1)
        self.max_headers     = self._safe_int(os.getenv("MAX_HEADERS", ""), DEFAULT_MAX_HEADERS, 1)
        self.max_uri_size    = self._safe_int(os.getenv("MAX_URI_SIZE", ""), DEFAULT_MAX_URI_SIZE, 1)
        self.max_total_headers_size = self._safe_int(os.getenv("MAX_TOTAL_HEADERS_SIZE", ""), DEFAULT_MAX_TOTAL_HEADERS_SIZE, 1)

        self.bad_ua_strings = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "botnet", "scan", "dirbuster", "wfuzz",
            "skipfish", "whatweb",
        )
        custom_ua = os.getenv("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_strings = self.bad_ua_strings + tuple(
                p.strip().lower() for p in custom_ua.split(",") if p.strip()
            )

        self.enable_waf    = os.getenv("ENABLE_WAF", "1") == "1"
        self.waf_body_timeout = self._safe_float(os.getenv("WAF_BODY_TIMEOUT", ""), WAF_BODY_TIMEOUT, 0.1)
        self.enable_firewall = os.getenv("ENABLE_FIREWALL", "0") == "1"

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

        raw_hosts = os.getenv("ALLOWED_HOSTS", "")
        self.allowed_hosts = set(h.strip().lower() for h in raw_hosts.split(",") if h.strip())

        self.health_check_enabled = os.getenv("BACKEND_HEALTH_CHECK", "0") == "1"
        self.health_path = os.getenv("BACKEND_HEALTH_PATH", "/health").strip()
        if not self.health_path.startswith("/"):
            self.health_path = "/" + self.health_path


CFG = Config()

# --------------------------------------------------------------------------- #
#  Global resources                                                           #
# --------------------------------------------------------------------------- #
waf_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
listener: Optional[logging.handlers.QueueListener] = None
audit_listener: Optional[logging.handlers.QueueListener] = None
log_queue: "queue.Queue" = queue.Queue(maxsize=CFG.log_queue_maxsize)
audit_log_queue: "queue.Queue" = queue.Queue(maxsize=CFG.log_queue_maxsize)

# --------------------------------------------------------------------------- #
#  FD accounting                                                              #
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

BLOCK_HEADERS = {"Connection": "close", "Cache-Control": "no-store"}

# --------------------------------------------------------------------------- #
#  Logging – non‑blocking, drop when full                                      #
# --------------------------------------------------------------------------- #
class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    def emit(self, record):
        try:
            self.enqueue(record)
        except queue.Full:
            pass


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "ip", "reason", "method",
                     "path", "duration", "violations"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
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
#  Micro‑WAF engine – ReDoS‑safe UNION SELECT, JSON bomb detection             #
# --------------------------------------------------------------------------- #
_SQLI_PATTERNS = [
    re.compile(r"(?<![a-zA-Z0-9_])(sleep|benchmark|pg_sleep|waitfor)\s*\(", re.IGNORECASE),
    # ReDoS‑safe UNION SELECT (handles both bare and ALL/DISTINCT variants)
    re.compile(r"\bunion\b[^a-zA-Z0-9_]{1,50}\b(?:all|distinct)\b[^a-zA-Z0-9_]{1,50}\bselect\b"
               r"|\bunion\b[^a-zA-Z0-9_]{1,50}\bselect\b", re.IGNORECASE),
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
    re.compile(r"\b(or|and)\b\s+[\d'\"]+\s*=\s*[\d'\"]+", re.IGNORECASE),
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
    re.compile(r"constructor\s*\[", re.IGNORECASE),
    re.compile(r"\bprototype\b", re.IGNORECASE),
]

def _decode_aggressive(data: str) -> str:
    cleaned = data
    for _ in range(3):
        new_cleaned = unquote(cleaned)
        if new_cleaned == cleaned:
            break
        cleaned = new_cleaned
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
    return cleaned


def waf_check(data: str) -> Optional[str]:
    if not CFG.enable_waf or not data:
        return None

    data_lower = data.lower()
    if not any(c in SUSPICIOUS_CHARS for c in data) and \
       not any(kw in data_lower for kw in _SQLI_KEYWORDS):
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
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(waf_executor, waf_check, data),
            timeout=WAF_REGEX_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.error("WAF regex timeout – possible ReDoS attempt")
        return "ERROR"
    except Exception:
        return "ERROR"


def _json_parse_and_scan(text: str) -> Optional[str]:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return _json_scan(obj)


def _json_scan(obj, max_depth: int = MAX_JSON_DEPTH, _count: Optional[List[int]] = None) -> Optional[str]:
    if _count is None:
        _count = [0]
    if _count[0] > MAX_JSON_ELEMENTS or max_depth <= 0:
        return "JSON_BOMB"
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
#  Rate limiter – sharded locks                                               #
# --------------------------------------------------------------------------- #
class IPState:
    __slots__ = ("tokens", "last_time", "violations", "last_violation_time",
                 "active_conns", "first_seen")

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
        self._locks_pool: List[asyncio.Lock] = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]

    def _get_rate_limit_key(self, ip_str: str) -> str:
        key = self._key_cache.get(ip_str)
        if key is not None:
            return key
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                network = ipaddress.ip_network(
                    f"{ip_str}/{self.cfg.ipv6_prefix}", strict=False
                )
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
            warm_burst = 3.0
            state = IPState(warm_burst)
            self._store[key] = state
        else:
            if state.first_seen > 0 and (time.monotonic() - state.first_seen) > 300:
                if state.violations == 0:
                    state.tokens = self.cfg.burst_limit
                state.first_seen = 0.0
        return state

    async def check_and_acquire(
        self, ip: str, bypass_ban: bool = False, bypass_ban_writes: bool = False,
    ) -> Tuple[bool, float, str]:
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
            s.tokens = min(self.cfg.burst_limit,
                           s.tokens + elapsed * self.cfg.rate_limit)
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
            self._ban_store[key] = now + ban_time
            s.active_conns -= 1
            if s.violations == 1 or s.violations % 10 == 0:
                logger.warning("IP %s banned %.0fs (violations: %d)", ip, ban_time, s.violations)
                audit_logger.warning(
                    "BAN %s %.0fs violations=%d", ip, ban_time, s.violations
                )
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

    async def force_ban(self, ip: str, duration: float = None, request_id: str = None):
        key = self._get_rate_limit_key(ip)
        if duration is None:
            duration = self.cfg.ban_max
        lock = self._get_shard_lock(key)
        async with lock:
            self._ban_store[key] = time.monotonic() + duration
            s = self._store.get(key)
            if s:
                s.tokens = 0.0
                s.violations = 100
                s.last_time = time.monotonic()
        audit_logger.warning(
            "FORCE_BAN %s %.0fs", ip, duration,
            extra={"request_id": request_id or "n/a", "ip": ip, "reason": "force_ban", "duration": duration},
        )

    def is_banned(self, ip: str) -> bool:
        key = self._get_rate_limit_key(ip)
        ban_until = self._ban_store.get(key)
        return bool(ban_until) and ban_until > time.monotonic()

    def is_new_ip(self, ip: str) -> bool:
        key = self._get_rate_limit_key(ip)
        state = self._store.get(key)
        if state is None:
            return True
        return state.first_seen > 0 and (time.monotonic() - state.first_seen) < 300

    async def prune_caches(self, batch_limit: int = 1024):
        """Rotating sweep: expired entries are deleted, alive ones move to the back."""
        now = time.monotonic()
        for store in (self._ban_store, self._store):
            checked = 0
            while checked < batch_limit and store._data:
                key, item = next(iter(store._data.items()))
                _, ts = item
                if ts < now:
                    del store._data[key]
                else:
                    # Push still‑valid entry to the end so we can reach deeper items
                    store._data[key] = store._data.pop(key)
                checked += 1
            await asyncio.sleep(0)


# --------------------------------------------------------------------------- #
#  Circuit breaker                                                             #
# --------------------------------------------------------------------------- #
class CircuitBreaker:
    def __init__(self, err_thr: int, window: float, probe_timeout: float):
        self.err_thr = err_thr
        self.window = window
        self.probe_timeout = probe_timeout
        self._errors: "deque[float]" = deque()
        self._last_failure = time.monotonic()
        self._state = "CLOSED"
        self._probe_in_progress = False
        self._probe_start_time = 0.0
        self._transition_lock = asyncio.Lock()

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
#  SentinelApp – lock‑free metrics, safe WAF, keep‑alive disabled              #
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

        self._counter_locks: List[asyncio.Lock] = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]

        parsed_backend = urlparse(cfg.backend_url)
        self.backend_host = parsed_backend.hostname or "localhost"
        if parsed_backend.port:
            self.backend_host = f"{self.backend_host}:{parsed_backend.port}"
        self._shutdown_event = asyncio.Event()
        self._active_inbound = 0
        self._active_outbound = 0
        self._metrics = {}
        self._reset_metrics()

    def _reset_metrics(self):
        self._metrics = {"requests": 0, "blocked": 0, "waf_hits": 0, "bans": 0,
                         "slow_aborts": 0, "circuit_rejects": 0}

    def _get_counter_lock(self, key: str) -> asyncio.Lock:
        return self._counter_locks[hash(key) % SHARD_LOCK_COUNT]

    def _audit_extra(self, request: web.Request) -> Dict:
        return {
            "request_id": request["request_id"],
            "ip": getattr(request, "_audit_ip", "n/a"),
            "method": request.method,
            "path": request.path_qs[:512],
        }

    # ------------------------------------------------------------------- #
    #  Lifecycle                                                            #
    # ------------------------------------------------------------------- #
    async def startup(self, app: web.Application):
        global waf_executor, listener, audit_listener
        try:
            with open(CFG.log_file, "a"):
                pass
        except IOError:
            print(f"FATAL: Cannot write to log file {CFG.log_file}")
            sys.exit(1)

        if waf_executor is None:
            waf_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(WAF_MAX_WORKERS, (os.cpu_count() or 4) * 5),
                thread_name_prefix="sentinel-waf",
            )

        if listener is None:
            fh = logging.handlers.RotatingFileHandler(
                CFG.log_file, maxBytes=100 * 1024 * 1024, backupCount=5, encoding="utf-8",
            )
            sh = logging.StreamHandler()
            fh.setFormatter(_formatter)
            sh.setFormatter(_formatter)
            listener = logging.handlers.QueueListener(log_queue, fh, sh, respect_handler_level=True)
            listener.start()

        if audit_listener is None:
            afh = logging.handlers.RotatingFileHandler(
                CFG.audit_log_file, maxBytes=100 * 1024 * 1024, backupCount=5, encoding="utf-8",
            )
            afh.setFormatter(_audit_formatter)
            audit_listener = logging.handlers.QueueListener(audit_log_queue, afh, respect_handler_level=True)
            audit_listener.start()

        app["waf_executor"] = waf_executor
        app["log_listener"] = listener
        app["audit_listener"] = audit_listener

        connector = TCPConnector(limit=self.cfg.backend_pool_size, ttl_dns_cache=300)
        timeout = ClientTimeout(total=self.cfg.backend_timeout, connect=5, sock_read=10, sock_connect=5)
        self.session = ClientSession(connector=connector, timeout=timeout, auto_decompress=False)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        if self.cfg.health_check_enabled:
            self._health_task = asyncio.create_task(self._health_check_loop())

    async def shutdown(self, app: web.Application):
        self._shutdown_event.set()
        for t in (self._health_task, self._cleanup_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

        logger.info("Shutting down – waiting for in-flight requests...")
        try:
            for _ in range(int(self.cfg.shutdown_timeout * 10)):
                if self._active_inbound == 0 and self._active_outbound == 0:
                    break
                await asyncio.sleep(0.1)
        except Exception:
            pass

        log_listener = app.get("log_listener")
        audit_listener_ref = app.get("audit_listener")
        if log_listener:
            log_listener.stop()
        if audit_listener_ref:
            audit_listener_ref.stop()

        if self.session:
            await self.session.close()

        waf_exec = app.get("waf_executor")
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
            try:
                await self.rate_limiter.prune_caches(batch_limit=1024)
            except Exception as e:
                logger.debug("Cleanup loop iteration error: %s", e)

    async def _backend_health_check(self):
        if not self.cfg.health_check_enabled:
            return True
        try:
            async with self.session.get(
                f"{CFG.backend_url}{self.cfg.health_path}", timeout=5
            ) as r:
                return r.status == 200
        except Exception:
            return False

    async def _health_check_loop(self):
        while not self._shutdown_event.is_set():
            healthy = await self._backend_health_check()
            if healthy != self._backend_healthy:
                self._backend_healthy = healthy
                if healthy:
                    logger.info("Backend is healthy again")
                else:
                    logger.warning("Backend is unhealthy – shedding traffic")
            await asyncio.sleep(30)

    # ------------------------------------------------------------------- #
    #  Error response helper                                                #
    # ------------------------------------------------------------------- #
    def _err(self, request, status, text=""):
        headers = dict(BLOCK_HEADERS)
        headers["X-Request-ID"] = request["request_id"]
        return web.Response(status=status, text=text, headers=headers)

    # ------------------------------------------------------------------- #
    #  IP / XFF                                                              #
    # ------------------------------------------------------------------- #
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
    def _ip_matches_networks(ip_str: str, networks: Iterable) -> bool:
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
                clean_ip = SentinelApp._normalize_ip(ip_str.split("%")[0])
                try:
                    ip_obj = ipaddress.ip_address(clean_ip)
                except ValueError:
                    continue
                if SentinelApp._ip_matches_networks(clean_ip, CFG.trusted_proxies):
                    continue
                return clean_ip
        return normalized

    # ------------------------------------------------------------------- #
    #  Hop‑by‑hop headers (separate for request and response)               #
    # ------------------------------------------------------------------- #
    @staticmethod
    def filter_hop_request(headers):
        hop_lower = {"transfer-encoding", "connection", "keep-alive",
                     "proxy-authenticate", "proxy-authorization", "te",
                     "trailers", "trailer", "upgrade", "content-length"}
        conn_vals = headers.getall("Connection", [])
        for val in conn_vals:
            for directive in val.split(","):
                hop_lower.add(directive.strip().lower())
        for key in list(headers.keys()):
            if key.lower() in hop_lower:
                del headers[key]

    @staticmethod
    def filter_hop_response(headers):
        hop_lower = {"transfer-encoding", "connection", "keep-alive",
                     "proxy-authenticate", "proxy-authorization", "te",
                     "trailers", "trailer", "upgrade"}
        conn_vals = headers.getall("Connection", [])
        for val in conn_vals:
            for directive in val.split(","):
                hop_lower.add(directive.strip().lower())
        for key in list(headers.keys()):
            if key.lower() in hop_lower:
                del headers[key]

    # ------------------------------------------------------------------- #
    #  Transfer‑Encoding validation                                        #
    # ------------------------------------------------------------------- #
    @staticmethod
    def _is_valid_transfer_encoding(headers) -> bool:
        te_values = headers.getall("Transfer-Encoding", [])
        if len(te_values) > 1:
            return False
        if te_values:
            tokens = [t.strip().lower() for t in te_values[0].split(",") if t.strip()]
            for token in tokens:
                if token not in ("chunked", "identity"):
                    return False
        return True

    # ------------------------------------------------------------------- #
    #  IP classification                                                    #
    # ------------------------------------------------------------------- #
    async def _classify_ip(self, ip_str: str, ip_obj) -> str:
        if ip_str in self.ip_class_cache:
            return self.ip_class_cache[ip_str]
        lock = self._get_counter_lock(ip_str)
        async with lock:
            if ip_str in self.ip_class_cache:
                return self.ip_class_cache[ip_str]
            if self._ip_matches_networks(ip_str, CFG.blacklist_ips):
                cls = "blacklist"
            elif self._ip_matches_networks(ip_str, CFG.whitelist_ips):
                cls = "whitelist"
            else:
                cls = "normal"
            self.ip_class_cache[ip_str] = cls
            return cls

    # ------------------------------------------------------------------- #
    #  Blackhole                                                             #
    # ------------------------------------------------------------------- #
    async def _blackhole(self, request: web.Request, ip: str, reason: str = "Banned") -> web.Response:
        self._metrics["blocked"] += 1
        remote = request.remote or "0.0.0.0"
        is_trusted_proxy = self._ip_matches_networks(self._normalize_ip(remote), CFG.trusted_proxies)
        if not is_trusted_proxy and request.transport and not request.transport.is_closing():
            try:
                request.transport.abort()
            except (OSError, RuntimeError):
                pass
        audit_logger.warning("BLACKHOLE %s reason=%s", ip, reason,
                             extra=self._audit_extra(request))
        return web.Response(status=444)

    # ------------------------------------------------------------------- #
    #  HTTP version                                                          #
    # ------------------------------------------------------------------- #
    @staticmethod
    def _allowed_version(request: web.Request) -> bool:
        try:
            ver = request.version
            return (ver.major, ver.minor) in ALLOWED_HTTP_VERSIONS
        except (AttributeError, KeyError):
            return True

    @staticmethod
    def _valid_host(request: web.Request) -> bool:
        host = request.headers.get("Host")
        if not host:
            return False
        if len(host) > 256 or len(host) < 3:
            return False
        if " " in host or "\t" in host or "\r" in host:
            return False
        return True

    @staticmethod
    def _valid_cl(request) -> bool:
        cl_values = request.headers.getall("Content-Length", [])
        if not cl_values:
            return True
        if len(cl_values) > 1:
            return False
        try:
            n = int(cl_values[0])
        except (ValueError, TypeError):
            return False
        if n < 0:
            return False
        return True

    # ------------------------------------------------------------------- #
    #  Top‑level handler                                                    #
    # ------------------------------------------------------------------- #
    async def handler(self, request: web.Request) -> web.Response:
        self._metrics["requests"] += 1

        request["request_id"] = str(uuid.uuid4())
        ip = self.get_real_ip(request)
        request._audit_ip = ip

        if request.path == "/metrics":
            remote_norm = self._normalize_ip(request.remote or "0.0.0.0")
            if remote_norm not in ("127.0.0.1", "::1"):
                return web.Response(status=403)
            host_hdr = (request.headers.get("Host") or "").lower()
            if host_hdr and not (host_hdr.startswith("localhost") or
                                 host_hdr == CFG.listen_host.lower() or
                                 host_hdr.startswith("127.0.0.1") or
                                 host_hdr.startswith("[::1]") or
                                 host_hdr.startswith("::1")):
                return web.Response(status=403)
            return web.json_response(self._metrics)

        if self._shutdown_event.is_set():
            if request.transport and not request.transport.is_closing():
                try:
                    request.transport.abort()
                except (OSError, RuntimeError):
                    pass
            return web.Response(status=444)

        if INBOUND_CONN_SEM.locked():
            if request.transport and not request.transport.is_closing():
                try:
                    request.transport.abort()
                except (OSError, RuntimeError):
                    pass
            return web.Response(status=444)

        self._active_inbound += 1
        try:
            async with INBOUND_CONN_SEM:
                try:
                    return await asyncio.wait_for(
                        self._process_request(request),
                        timeout=CFG.backend_timeout + 5.0,
                    )
                except asyncio.TimeoutError:
                    self._metrics["slow_aborts"] += 1
                    return await self._blackhole(request, ip, "Slowloris/Timeout")
                except asyncio.CancelledError:
                    raise
                except web.HTTPException:
                    raise
                except Exception as e:
                    logger.critical("Unhandled catastrophic error: %s", e, exc_info=True)
                    return await self._blackhole(request, ip, "Internal Error")
        finally:
            self._active_inbound -= 1

    # ------------------------------------------------------------------- #
    #  Core request processing                                              #
    # ------------------------------------------------------------------- #
    async def _process_request(self, request: web.Request) -> web.Response:
        ip = request._audit_ip
        request_id = request["request_id"]
        logger.debug("Request %s from %s", request_id, ip)

        # 1) HTTP version
        if not self._allowed_version(request):
            return self._err(request, 400, "Bad HTTP version")

        # 2) Host header
        if not self._valid_host(request):
            return self._err(request, 400, "Invalid Host header")
        if CFG.allowed_hosts:
            host_lc = (request.headers.get("Host", "")).lower()
            if not any(host_lc == h or host_lc.endswith("." + h) for h in CFG.allowed_hosts):
                return self._err(request, 400, "Host not allowed")

        # 3) /health
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

        # 4) Method
        if request.method.upper() not in CFG.allowed_methods:
            audit_logger.warning("METHOD_BLOCKED %s %s", ip, request.method,
                                 extra=self._audit_extra(request))
            return self._err(request, 405, "Method Not Allowed")

        # 5) Transfer-Encoding (improved)
        if not self._is_valid_transfer_encoding(request.headers):
            return self._err(request, 400, "Bad Transfer-Encoding")
        if request.headers.get("Transfer-Encoding") and request.headers.get("Content-Length"):
            return self._err(request, 400, "Bad Request: TE + CL conflict")

        # 6) Content-Length
        if not self._valid_cl(request):
            return self._err(request, 400, "Invalid Content-Length")

        # 7) Header caps
        total_headers_size = sum(len(k) + len(v) + 2 for k, v in request.headers.items())
        if total_headers_size > CFG.max_total_headers_size:
            return self._err(request, 431, "Headers too large")
        if len(request.path_qs) > CFG.max_uri_size:
            return self._err(request, 414, "URI Too Long")
        if len(request.headers) > CFG.max_headers:
            return self._err(request, 431, "Too Many Headers")
        for name, value in request.headers.items():
            if len(name) > 256 or len(value) > CFG.max_header_size:
                return self._err(request, 431, "Header Too Large")

        # 8) Global per-IP
        global_ip_key = f"global:{ip}"
        lock = self._get_counter_lock(global_ip_key)
        async with lock:
            global_ip_count = self.global_per_ip_cache.get(global_ip_key) or 0
            if global_ip_count > CFG.global_per_ip_limit:
                await self.rate_limiter.force_ban(ip, self.cfg.ban_max, request_id)
                audit_logger.warning("GLOBAL_LIMIT_BAN %s", ip,
                                     extra=self._audit_extra(request))
                return await self._blackhole(request, ip, "Global IP Limit Exceeded")
            self.global_per_ip_cache[global_ip_key] = global_ip_count + 1

        # 9) Unique-query scraper
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
                        await self.rate_limiter.force_ban(ip, request_id=request_id)
                        audit_logger.warning(
                            "SCRAPER_PATTERN %s unique=%d", ip, len(seen),
                            extra=self._audit_extra(request))
                        self.unique_query_cache[uq_key] = OrderedDict()
                        return await self._blackhole(request, ip, "Scraper Pattern")

        # 10) Per-IP endpoint
        endpoint_hash = hash(request.path) & 0xFFFFFFFF
        endpoint_key = f"{ip}:{request.method}:{endpoint_hash}"
        lock = self._get_counter_lock(endpoint_key)
        async with lock:
            count_entry = self.per_ip_endpoint_cache.get(endpoint_key)
            count = count_entry if count_entry else 0
            if count > DEFAULT_PER_IP_ENDPOINT_LIMIT:
                return await self._blackhole(request, ip, "Endpoint Spam")
            self.per_ip_endpoint_cache[endpoint_key] = count + 1

        # 11) IP classification
        ip_obj = self.ip_obj_cache.get(ip)
        if not ip_obj:
            try:
                ip_obj = ipaddress.ip_address(ip)
                self.ip_obj_cache[ip] = ip_obj
            except ValueError:
                return self._err(request, 400, "Invalid IP")
        ip_class = await self._classify_ip(ip, ip_obj)
        if ip_class == "blacklist":
            audit_logger.warning("BLACKLIST_HIT %s %s", ip, request.path,
                                 extra=self._audit_extra(request))
            return await self._blackhole(request, ip, "Blacklisted")

        # 12) Rate-limit
        if ip_class == "whitelist":
            allowed, _, reason = await self.rate_limiter.check_and_acquire(
                ip, bypass_ban=True, bypass_ban_writes=True,
            )
            if not allowed:
                if reason == "too_many_connections":
                    return self._err(request, 429, "Too many connections")
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
            if reason == "banned":
                return await self._blackhole(request, ip, "Banned")
            if reason == "too_many_connections":
                return self._err(request, 429, "Too many connections")
            return self._err(request, 429, "Too Many Requests")

        # 13) Backend unhealthy shedding (only when health‑check is enabled)
        if self.cfg.health_check_enabled and not self._backend_healthy:
            self._metrics["blocked"] += 1
            return self._err(request, 503, "Backend Unavailable")

        try:
            ok, resp, body_chunk = await self._filter(request, ip)
            if not ok:
                return resp
            if not await self.cb.allow():
                self._metrics["circuit_rejects"] += 1
                return self._err(request, 503, "Service Unavailable (circuit open)")
            return await self._forward(request, ip, body_chunk)
        finally:
            await self.rate_limiter.dec_conn(ip)

    # ------------------------------------------------------------------- #
    #  WAF + body inspection – network I/O OUTSIDE semaphore               #
    # ------------------------------------------------------------------- #
    @staticmethod
    def _is_text_content(content_type: Optional[str]) -> bool:
        if not content_type:
            return False
        ct = content_type.lower().split(";")[0].strip()
        if ct.startswith("text/"):
            return True
        if ct in ("application/json", "application/xml",
                  "application/x-www-form-urlencoded"):
            return True
        return False

    async def _filter(self, request: web.Request, ip: str) -> Tuple[bool, Optional[web.Response], Optional[bytes]]:
        # Null-byte early rejection
        if "\x00" in request.path or "\x00" in (request.query_string or ""):
            return False, self._err(request, 400, "Bad Request"), None
        for hdr in ("Host", "User-Agent", "Content-Type", "X-Forwarded-For"):
            val = request.headers.get(hdr, "")
            if "\x00" in val:
                return False, self._err(request, 400, "Bad Request"), None

        ua = request.headers.get("User-Agent", "")
        if not ua:
            is_new = self.rate_limiter.is_new_ip(ip)
            if is_new and not request.headers.get("Accept"):
                return False, self._err(request, 403, "Empty User-Agent"), None

        ua_lower = ua.lower()
        if any(s in ua_lower for s in CFG.bad_ua_strings):
            return False, self._err(request, 403, "Forbidden"), None

        request_id = request["request_id"]
        if CFG.enable_waf:
            combined = f"{request.path}\x00{request.query_string}"[:WAF_INSPECT_SIZE]
            waf_result = await async_waf_check(combined)
            if waf_result == "ERROR":
                await self.rate_limiter.force_ban(ip, request_id=request_id)
                audit_logger.warning("WAF_ERROR %s", ip,
                                     extra=self._audit_extra(request))
                return False, self._err(request, 403, "WAF Error"), None
            if waf_result:
                self._metrics["waf_hits"] += 1
                audit_logger.warning("WAF_HIT %s %s %s", ip, waf_result, request.path,
                                     extra=self._audit_extra(request))
                return False, self._err(request, 403, "WAF Blocked"), None

        body_chunk = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if CFG.enable_waf and self._is_text_content(request.content_type):
                # Read body OUTSIDE WAF semaphore to avoid slow POST holding slots
                content_length = request.content_length
                if content_length is not None and content_length > WAF_INSPECT_SIZE:
                    body_chunk = None   # too large – skip inspection, stream directly
                else:
                    try:
                        body_chunk = await asyncio.wait_for(
                            request.content.read(WAF_INSPECT_SIZE),
                            timeout=CFG.waf_body_timeout,
                        )
                    except web.HTTPRequestEntityTooLarge:
                        return False, self._err(request, 413, "Payload Too Large"), None
                    except (asyncio.TimeoutError, TimeoutError):
                        return False, await self._blackhole(request, ip, "Body Read Timeout"), None
                    except (ClientPayloadError, ClientDisconnectedError, asyncio.IncompleteReadError,
                            ConnectionResetError) as e:
                        logger.debug("Client disconnected during body read: %s", e)
                        return False, await self._blackhole(request, ip, "Client disconnect"), None
                    except Exception as e:
                        logger.error("Body read error: %s", e)
                        return False, self._err(request, 400, "Bad Request: body read"), None

                if body_chunk is not None:
                    # Only acquire WAF semaphore for the CPU‑bound scan
                    if WAF_SEM.locked():
                        logger.warning("WAF queue full – dropping %s", ip)
                        return False, await self._blackhole(request, ip, "WAF Overloaded"), None
                    async with WAF_SEM:
                        try:
                            text = body_chunk[:WAF_INSPECT_SIZE].decode("utf-8", "ignore")
                        except UnicodeDecodeError:
                            text = ""

                        waf_result = await async_waf_check(text)
                        if waf_result == "ERROR":
                            await self.rate_limiter.force_ban(ip, request_id=request_id)
                            audit_logger.warning("WAF_ERROR_BODY %s", ip,
                                                 extra=self._audit_extra(request))
                            return False, self._err(request, 403, "WAF Error"), None
                        if waf_result:
                            self._metrics["waf_hits"] += 1
                            audit_logger.warning("WAF_HIT_BODY %s %s %s", ip, waf_result, request.path,
                                                 extra=self._audit_extra(request))
                            return False, self._err(request, 403, "WAF Blocked"), None

                        if request.content_type and "application/json" in request.content_type:
                            loop = asyncio.get_running_loop()
                            try:
                                json_result = await asyncio.wait_for(
                                    loop.run_in_executor(waf_executor, _json_parse_and_scan, text),
                                    timeout=WAF_REGEX_TIMEOUT,
                                )
                            except asyncio.TimeoutError:
                                logger.error("JSON scan timeout – possible bomb")
                                return False, self._err(request, 413, "JSON too large"), None
                            if json_result:
                                self._metrics["waf_hits"] += 1
                                audit_logger.warning("WAF_HIT_JSON %s %s %s",
                                                     ip, json_result, request.path,
                                                     extra=self._audit_extra(request))
                                return False, self._err(request, 403, "WAF Blocked JSON"), None

        return True, None, body_chunk

    # ------------------------------------------------------------------- #
    #  Forwarding – forced close, stream timeout, safe retry                #
    # ------------------------------------------------------------------- #
    async def _forward(self, request: web.Request, ip: str, body_chunk: Optional[bytes]) -> web.Response:
        url = urljoin(CFG.backend_url + "/", request.path_qs.lstrip("/"))

        headers = request.headers.copy()
        headers["Host"] = self.backend_host
        self.filter_hop_request(headers)
        headers["X-Request-ID"] = request["request_id"]

        existing = headers.get("X-Forwarded-For", "")
        if len(existing) > XFF_MAX_LENGTH:
            existing = existing[-XFF_MAX_LENGTH:]
        ips = [ip.strip() for ip in existing.split(",") if ip.strip()] if existing else []
        if len(ips) > XFF_MAX_IPS:
            existing = ", ".join(ips[-XFF_MAX_IPS:])
            headers["X-Forwarded-For"] = existing

        remote_addr = self._normalize_ip(request.remote or "0.0.0.0")
        if remote_addr not in ips:
            headers["X-Forwarded-For"] = f"{existing}, {remote_addr}" if existing else remote_addr

        if OUTBOUND_REQ_SEM.locked():
            if request.transport and not request.transport.is_closing():
                try:
                    request.transport.abort()
                except (OSError, RuntimeError):
                    pass
            return self._err(request, 444)

        can_retry = request.method in ("GET", "HEAD")
        max_attempts = BACKEND_MAX_RETRIES + 1 if can_retry else 1
        data = self._make_body_stream(body_chunk, request) if request.method in ("POST", "PUT", "PATCH", "DELETE") else None

        last_exception: Optional[Exception] = None
        self._active_outbound += 1
        try:
            async with OUTBOUND_REQ_SEM:
                for attempt in range(max_attempts):
                    try:
                        async with self.session.request(
                            request.method, url, headers=headers,
                            data=data,
                            allow_redirects=False,
                            ssl=CFG.verify_ssl,
                        ) as resp:
                            if resp.status >= 500:
                                self.cb.record_error()
                                logger.warning("Backend %d for %s", resp.status, ip)
                            else:
                                self.cb.record_success()

                            backend_headers = resp.headers.copy()
                            self.filter_hop_response(backend_headers)
                            backend_headers.pop("Server", None)
                            backend_headers.pop("X-Powered-By", None)
                            if CFG.server_header:
                                backend_headers["Server"] = CFG.server_header
                            # Force connection close to prevent FD exhaustion
                            backend_headers["Connection"] = "close"

                            client_resp = web.StreamResponse(status=resp.status, headers=backend_headers)
                            await client_resp.prepare(request)

                            try:
                                async def stream_response():
                                    async for chunk in resp.content.iter_chunked(STREAM_CHUNK_SIZE):
                                        await client_resp.write(chunk)
                                    await client_resp.write_eof()

                                await asyncio.wait_for(stream_response(), timeout=CFG.backend_timeout)
                            except (asyncio.TimeoutError, ConnectionResetError,
                                    ConnectionAbortedError, BrokenPipeError,
                                    asyncio.IncompleteReadError, ClientError):
                                logger.debug("Client connection interrupted: %s", ip)
                                if request.transport and not request.transport.is_closing():
                                    try:
                                        request.transport.abort()
                                    except (OSError, RuntimeError):
                                        pass
                                return client_resp

                            return client_resp
                    except (ClientError, asyncio.TimeoutError, ConnectionError) as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning("Backend request attempt %d failed for %s: %s",
                                           attempt + 1, ip, e)
                            await asyncio.sleep(0.1 * (attempt + 1))
                        else:
                            break

            self.cb.record_error()
            if isinstance(last_exception, asyncio.TimeoutError):
                logger.error("Backend timeout after %d attempts for %s", max_attempts, ip)
                return self._err(request, 504, "Gateway Timeout")
            logger.error("Backend connection error after %d attempts for %s: %s",
                         max_attempts, ip, last_exception)
            return self._err(request, 502, "Bad Gateway")
        finally:
            self._active_outbound -= 1

    @staticmethod
    def _make_body_stream(body_chunk: Optional[bytes], request: web.Request):
        async def _stream():
            if body_chunk:
                yield body_chunk
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        request.content.read(STREAM_CHUNK_SIZE),
                        timeout=SLOW_REQUEST_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    return   # disconnect if client stalls
                if not chunk:
                    break
                yield chunk
        return _stream()


# --------------------------------------------------------------------------- #
#  Application factory                                                        #
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
        "keepalive_timeout": KEEPALIVE_TIMEOUT,
        "slow_request_timeout": SLOW_REQUEST_TIMEOUT,
    }
    web.run_app(create_app(), host=CFG.listen_host, port=CFG.listen_port,
                handle_signals=True, handler_args=handler_args)
