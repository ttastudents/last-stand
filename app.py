#!/usr/bin/env python3
"""
Sentinel Guard v17.0 – Immortal Bastion (Safe Forwarding)
Production‑hardened, single‑file Python async anti‑DDoS layer‑7 wall.
Works on Linux, Windows, macOS – no C‑extensions, no root.
Requires: aiohttp, cachetools
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
from collections import deque
from typing import Dict, Optional, Set, Tuple
from urllib.parse import unquote

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector, ClientError
from cachetools import TTLCache

# --------------------------------------------------------------------------- #
#  CONFIGURATION (safe environment parsing)                                   #
# --------------------------------------------------------------------------- #
class Config:
    @staticmethod
    def _safe_int(val: str, default: int) -> int:
        try: return int(val) if val else default
        except ValueError: return default

    @staticmethod
    def _safe_float(val: str, default: float) -> float:
        try: return float(val) if val else default
        except ValueError: return default

    @staticmethod
    def _parse_networks(raw: str) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
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
        self.listen_port = self._safe_int(os.getenv("SENTINEL_PORT", ""), 9999)
        self.backend_url  = os.getenv("BACKEND_URL", "http://127.0.0.1:8888").rstrip("/")

        self.rate_limit      = self._safe_float(os.getenv("RATE_LIMIT", ""), 50.0)
        self.burst_limit     = self._safe_float(os.getenv("BURST_LIMIT", ""), 100.0)
        self.max_conn_per_ip = self._safe_int(os.getenv("MAX_CONN_IP", ""), 30)
        self.max_body_size   = self._safe_int(os.getenv("MAX_BODY_SIZE", ""), 1_048_576)

        self.ban_base       = self._safe_float(os.getenv("BAN_BASE", ""), 60.0)
        self.ban_mult       = self._safe_float(os.getenv("BAN_MULT", ""), 2.0)
        self.ban_max        = self._safe_float(os.getenv("BAN_MAX", ""), 3600.0)
        self.violations_decay = self._safe_float(os.getenv("VIOLATIONS_DECAY", ""), 3600.0)

        self.trusted_proxies = self._parse_networks(os.getenv("TRUSTED_PROXIES", ""))
        self.whitelist_ips   = self._parse_networks(os.getenv("WHITELIST", "127.0.0.1,::1"))
        self.blacklist_ips   = self._parse_networks(os.getenv("BLACKLIST", ""))

        self.allowed_methods = set(m.strip().upper() for m in os.getenv("ALLOWED_METHODS", "GET,POST,HEAD,PUT,DELETE").split(",") if m.strip())
        self.max_header_size = self._safe_int(os.getenv("MAX_HEADER_SIZE", ""), 8192)
        self.max_headers     = self._safe_int(os.getenv("MAX_HEADERS", ""), 100)
        self.max_uri_size    = self._safe_int(os.getenv("MAX_URI_SIZE", ""), 4096)

        self.bad_ua_patterns = [
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "scan", "botnet", "crawler"
        ]
        custom_ua = os.getenv("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_patterns.extend([p.strip().lower() for p in custom_ua.split(",") if p.strip()])

        self.enable_waf    = os.getenv("ENABLE_WAF", "1") == "1"
        self.waf_body_timeout = self._safe_float(os.getenv("WAF_BODY_TIMEOUT", ""), 5.0)

        self.enable_firewall    = os.getenv("ENABLE_FIREWALL", "0") == "1"

        self.backend_pool_size  = self._safe_int(os.getenv("BACKEND_POOL_SIZE", ""), 100)
        self.verify_ssl         = os.getenv("VERIFY_SSL", "1") == "1"
        self.backend_timeout    = self._safe_float(os.getenv("BACKEND_TIMEOUT", ""), 30.0)

        self.cb_error_threshold = self._safe_int(os.getenv("CB_ERRORS", ""), 5)
        self.cb_window          = self._safe_int(os.getenv("CB_WINDOW", ""), 60)
        self.cb_probe_timeout   = self._safe_int(os.getenv("CB_TIMEOUT", ""), 30)

        self.cleanup_interval   = self._safe_int(os.getenv("CLEANUP_INTERVAL", ""), 300)
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file  = os.getenv("LOG_FILE", "sentinel.log")
        self.log_queue_maxsize = self._safe_int(os.getenv("LOG_QUEUE_MAXSIZE", ""), 5000)

CFG = Config()

# --------------------------------------------------------------------------- #
#  CROSS‑PLATFORM EVENT LOOP & OS LIMITS                                      #
# --------------------------------------------------------------------------- #
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    MAX_SAFE_CONNS = 5000
else:
    MAX_SAFE_CONNS = 15000

INBOUND_CONN_SEM = asyncio.Semaphore(MAX_SAFE_CONNS)
WAF_SEM = asyncio.Semaphore(CFG.backend_pool_size * 2)
OUTBOUND_REQ_SEM = asyncio.Semaphore(CFG.backend_pool_size)

# --------------------------------------------------------------------------- #
#  ASYNC‑SAFE LOGGING (non‑blocking QueueHandler)                             #
# --------------------------------------------------------------------------- #
class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    def emit(self, record):
        try:
            self.enqueue(record)
        except queue.Full:
            pass

log_queue = queue.Queue(maxsize=CFG.log_queue_maxsize)
queue_handler = NonBlockingQueueHandler(log_queue)
logger = logging.getLogger("Sentinel")
logger.setLevel(CFG.log_level)
logger.addHandler(queue_handler)

file_handler = logging.FileHandler(CFG.log_file, encoding="utf-8")
stream_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

listener = logging.handlers.QueueListener(log_queue, file_handler, stream_handler, respect_handler_level=True)
listener.start()

# --------------------------------------------------------------------------- #
#  PURE PYTHON MICRO‑WAF ENGINE (No C‑extensions, safe against ReDoS)        #
# --------------------------------------------------------------------------- #
_SQLI_PATTERNS = [
    re.compile(r"\bunion\b.{0,50}\bselect\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bselect\b.{0,50}\bfrom\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\binsert\b.{0,50}\binto\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bupdate\b.{0,50}\bset\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bdelete\b.{0,50}\bfrom\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bdrop\b.{0,50}\btable\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"'\s*(or|and)\s+['\d]", re.IGNORECASE),
    re.compile(r"(--|#|/\*)", re.IGNORECASE),
    re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor)\b\s*\(", re.IGNORECASE),
    re.compile(r";\s*(drop|alter|create|insert|update|delete)\b", re.IGNORECASE),
    re.compile(r"\b(information_schema|sysobjects|syscolumns)\b", re.IGNORECASE)
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

waf_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=min(64, (os.cpu_count() or 4) * 5)
)

def waf_check(data: str) -> Optional[str]:
    """Returns 'SQLi' or 'XSS' if attack detected, else None. Pure Python, ReDoS‑safe."""
    if not CFG.enable_waf or not data:
        return None

    cleaned = data
    if '%' in cleaned:
        for _ in range(3):
            new_cleaned = unquote(cleaned)
            if new_cleaned == cleaned:
                break
            cleaned = new_cleaned

    cleaned = cleaned.replace('\x00', '').replace('\r', '').replace('\n', '')

    try:
        for pattern in _SQLI_PATTERNS:
            if pattern.search(cleaned):
                return "SQLi"
        for pattern in _XSS_PATTERNS:
            if pattern.search(cleaned):
                return "XSS"
    except Exception as e:
        logger.error("Micro-WAF execution error: %s", e)

    return None

async def async_waf_check(data: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(waf_executor, waf_check, data)

# --------------------------------------------------------------------------- #
#  RATE LIMITER & IP STATE (monotonic time)                                    #
# --------------------------------------------------------------------------- #
class IPState:
    __slots__ = ("tokens","last_time","violations","last_violation_time","ban_until","active_conns")
    def __init__(self, burst: float):
        self.tokens = burst
        self.last_time = time.monotonic()
        self.violations = 0
        self.last_violation_time = 0.0
        self.ban_until = 0.0
        self.active_conns = 0

class RateLimiter:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._store: TTLCache = TTLCache(maxsize=1_000_000, ttl=3600)

    def _get(self, ip: str) -> IPState:
        state = self._store.get(ip)
        if state is None:
            state = IPState(self.cfg.burst_limit)
            self._store[ip] = state
        return state

    def acquire(self, ip: str) -> Tuple[bool, float]:
        now = time.monotonic()
        s = self._get(ip)
        if s.ban_until > now:
            return False, 0.0
        elapsed = now - s.last_time
        s.last_time = now
        s.tokens = min(self.cfg.burst_limit, s.tokens + elapsed * self.cfg.rate_limit)
        if s.tokens >= 1.0:
            s.tokens -= 1.0
            return True, s.tokens
        if s.ban_until <= now:
            if now - s.last_violation_time > self.cfg.violations_decay:
                s.violations = 0
            s.violations = min(s.violations + 1, 100)
            s.last_violation_time = now
            ban_time = min(self.cfg.ban_max, self.cfg.ban_base * (self.cfg.ban_mult ** (s.violations - 1)))
            s.ban_until = now + ban_time
            logger.warning("IP %s banned %.0fs (violations: %d)", ip, ban_time, s.violations)
            if self.cfg.enable_firewall and s.violations > 3:
                logger.info("FIREWALL_BAN_IP=%s DURATION=%.0f", ip, ban_time)
        return False, s.tokens

    def inc_conn(self, ip: str) -> bool:
        s = self._get(ip)
        if s.active_conns >= self.cfg.max_conn_per_ip:
            return False
        s.active_conns += 1
        return True

    def dec_conn(self, ip: str):
        s = self._store.get(ip)
        if s and s.active_conns > 0:
            s.active_conns -= 1

    def is_banned(self, ip: str) -> bool:
        s = self._get(ip)
        return s.ban_until > time.monotonic()

# --------------------------------------------------------------------------- #
#  CIRCUIT BREAKER                                                             #
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

    def allow(self) -> bool:
        now = time.monotonic()
        if self._state == "CLOSED":
            return True
        if self._state == "OPEN":
            if now - self._last_failure >= self.probe_timeout:
                if not self._probe_in_progress:
                    self._probe_in_progress = True
                    self._state = "HALF_OPEN"
                    self._probe_start_time = now
                    return True
            return False
        if self._state == "HALF_OPEN":
            if now - self._probe_start_time > self.probe_timeout:
                self._state = "OPEN"
                self._probe_in_progress = False
                self._last_failure = now
                logger.error("Circuit breaker probe timed out, forcing OPEN")
            return False

# --------------------------------------------------------------------------- #
#  SENTINEL APP (safe forwarding – no path normalization)                    #
# --------------------------------------------------------------------------- #
class SentinelApp:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session: Optional[ClientSession] = None
        self.rate_limiter = RateLimiter(cfg)
        self.cb = CircuitBreaker(cfg.cb_error_threshold, cfg.cb_window, cfg.cb_probe_timeout)
        self._cleanup_task = None
        self.ip_obj_cache = TTLCache(maxsize=200_000, ttl=3600)
        self.ip_class_cache = TTLCache(maxsize=200_000, ttl=3600)

    async def startup(self, app: web.Application):
        connector = TCPConnector(limit=self.cfg.backend_pool_size, ttl_dns_cache=300)
        timeout = ClientTimeout(total=self.cfg.backend_timeout, connect=5, sock_read=10, sock_connect=5)
        self.session = ClientSession(connector=connector, timeout=timeout, auto_decompress=False)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def shutdown(self, app: web.Application):
        global listener
        if listener:
            listener.stop()
        if self.session:
            await self.session.close()
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.cfg.cleanup_interval)

    @staticmethod
    def get_real_ip(request: web.Request) -> str:
        remote = request.remote or "0.0.0.0"
        try:
            remote_ip = ipaddress.ip_address(remote)
        except ValueError:
            remote = "0.0.0.0"
            remote_ip = ipaddress.IPv4Address("0.0.0.0")

        if not any(remote_ip in net for net in CFG.trusted_proxies):
            return remote

        fwd = request.headers.get("X-Forwarded-For")
        if not fwd:
            return remote
        ips = [ip.strip() for ip in fwd.split(",") if ip.strip()]
        for ip_str in reversed(ips):
            clean_ip = ip_str.split('%')[0]
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
            except ValueError:
                continue
            if any(ip_obj in net for net in CFG.trusted_proxies):
                continue
            return clean_ip
        return remote

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

    def _classify_ip(self, ip_str: str, ip_obj) -> str:
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
        if request.transport and not request.transport.is_closing():
            try:
                request.transport.abort()
            except Exception:
                pass
        return web.Response(status=444)

    async def handler(self, request: web.Request) -> web.Response:
        if INBOUND_CONN_SEM.locked():
            return await self._blackhole(request, "Server Busy")

        async with INBOUND_CONN_SEM:
            try:
                return await asyncio.wait_for(
                    self._process_request(request),
                    timeout=CFG.backend_timeout + 5.0
                )
            except asyncio.TimeoutError:
                return await self._blackhole(request, "Slowloris/Timeout")
            except Exception as e:
                logger.error("Unhandled handler error: %s", e)
                return await self._blackhole(request, "Internal Error")

    async def _process_request(self, request: web.Request) -> web.Response:
        ip = self.get_real_ip(request)

        if len(request.path_qs) > CFG.max_uri_size:
            return web.Response(status=414, text="URI Too Long")
        if len(request.headers) > CFG.max_headers:
            return web.Response(status=400, text="Too Many Headers")
        for name, value in request.headers.items():
            if len(name) > 256 or len(value) > CFG.max_header_size:
                return web.Response(status=400, text="Header Too Large")

        ip_obj = self.ip_obj_cache.get(ip)
        if not ip_obj:
            try:
                ip_obj = ipaddress.ip_address(ip)
                self.ip_obj_cache[ip] = ip_obj
            except ValueError:
                return web.Response(status=400, text="Invalid IP")

        ip_class = self._classify_ip(ip, ip_obj)
        if ip_class == "blacklist":
            return await self._blackhole(request, "Blacklisted")
        if ip_class == "whitelist":
            return await self._forward(request, ip, None)

        if self.rate_limiter.is_banned(ip):
            return await self._blackhole(request, "Banned")
        if not self.rate_limiter.inc_conn(ip):
            return web.Response(status=429, text="Too many connections")
        allowed, _ = self.rate_limiter.acquire(ip)
        if not allowed:
            self.rate_limiter.dec_conn(ip)
            return web.Response(status=429, text="Too Many Requests")

        ok, resp, body_chunk = await self._filter(request, ip)
        if not ok:
            self.rate_limiter.dec_conn(ip)
            return resp

        if not self.cb.allow():
            self.rate_limiter.dec_conn(ip)
            return web.Response(status=503, text="Service Unavailable (circuit open)")

        try:
            return await self._forward(request, ip, body_chunk)
        finally:
            self.rate_limiter.dec_conn(ip)

    async def _filter(self, request: web.Request, ip: str) -> Tuple[bool, Optional[web.Response], Optional[bytes]]:
        if request.method not in CFG.allowed_methods:
            return False, web.Response(status=405), None

        ua = request.headers.get("User-Agent", "")
        if not ua:
            return False, web.Response(status=403, text="Empty User-Agent"), None
        ua_lower = ua.lower()
        if any(bad in ua_lower for bad in CFG.bad_ua_patterns):
            return False, web.Response(status=403, text="Forbidden"), None

        if CFG.enable_waf:
            if await async_waf_check(request.path):
                return False, web.Response(status=403, text="WAF Blocked"), None
            if request.query_string and await async_waf_check(request.query_string):
                return False, web.Response(status=403, text="WAF Blocked"), None
            for header_name in ("Cookie", "Referer", "X-Forwarded-For"):
                val = request.headers.get(header_name)
                if val and await async_waf_check(val):
                    return False, web.Response(status=403, text="WAF Blocked Header"), None

        body_chunk = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if WAF_SEM.locked():
                logger.warning("WAF queue full – dropping %s", ip)
                return False, await self._blackhole(request, "WAF Overloaded")

            async with WAF_SEM:
                try:
                    body_chunk = await asyncio.wait_for(request.read(), timeout=CFG.waf_body_timeout)
                except web.HTTPRequestEntityTooLarge:
                    state = self.rate_limiter._get(ip)
                    state.violations += 5
                    self.rate_limiter.acquire(ip)
                    return False, web.Response(status=413, text="Payload Too Large"), None
                except (asyncio.TimeoutError, TimeoutError):
                    return False, await self._blackhole(request, "Body Read Timeout")
                except Exception as e:
                    logger.error("Body read error: %s", e)
                    return False, web.Response(status=400), None

                if CFG.enable_waf and body_chunk:
                    try:
                        text = body_chunk.decode('utf-8', 'ignore')
                    except:
                        text = body_chunk.decode('latin-1')
                    if await async_waf_check(text):
                        return False, web.Response(status=403, text="WAF Blocked"), None

        return True, None, body_chunk

    async def _forward(self, request: web.Request, ip: str, body_chunk: Optional[bytes]) -> web.Response:
        # No path normalization – forward original path_qs to backend
        url = f"{CFG.backend_url}{request.path_qs}"

        headers = request.headers.copy()
        headers.pop('Host', None)
        self.filter_hop(headers)

        existing = headers.get('X-Forwarded-For', '')
        if len(existing) > 2048:
            existing = existing[-2048:]
            headers['X-Forwarded-For'] = existing
        remote_addr = request.remote or "0.0.0.0"
        existing_ips = [x.strip() for x in existing.split(",") if x.strip()] if existing else []
        if remote_addr not in existing_ips:
            headers['X-Forwarded-For'] = f"{existing}, {remote_addr}" if existing else remote_addr

        async def body_stream():
            if body_chunk:
                yield body_chunk
            # body is already fully read, nothing more to stream from client
            # but just in case, we stop here

        if OUTBOUND_REQ_SEM.locked():
            logger.warning("Backend pool exhausted – dropping %s", ip)
            return web.Response(status=503, text="Service Unavailable")
        async with OUTBOUND_REQ_SEM:
            try:
                resp = await self.session.request(
                    request.method, url, headers=headers,
                    data=body_stream(), allow_redirects=False,
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
                backend_headers['Server'] = 'Sentinel-Guard'

                client_resp = web.StreamResponse(status=resp.status, headers=backend_headers)
                await client_resp.prepare(request)

                try:
                    async for chunk in resp.content.iter_chunked(8192):
                        await client_resp.write(chunk)
                    await client_resp.write_eof()
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, asyncio.IncompleteReadError, ClientError):
                    logger.debug("Client disconnected abruptly: %s", ip)
                    return client_resp

                return client_resp
            except ClientError as e:
                self.cb.record_error()
                logger.error("Backend connection error for %s: %s", ip, e)
                return web.Response(status=502, text="Bad Gateway")
            except asyncio.TimeoutError:
                self.cb.record_error()
                return web.Response(status=504, text="Gateway Timeout")

# --------------------------------------------------------------------------- #
#  APPLICATION FACTORY                                                        #
# --------------------------------------------------------------------------- #
def create_app():
    sentinel = SentinelApp(CFG)
    app = web.Application(client_max_size=CFG.max_body_size)
    app.on_startup.append(sentinel.startup)
    app.on_cleanup.append(sentinel.shutdown)
    app.router.add_get("/health", lambda r: web.Response(text="OK"))
    app.router.add_route("*", "/{tail:.*}", sentinel.handler)
    return app

if __name__ == "__main__":
    handler_args = {
        'keepalive_timeout': 15,
        'slow_request_timeout': 10
    }
    web.run_app(create_app(), host=CFG.listen_host, port=CFG.listen_port,
                handle_signals=True, handler_args=handler_args)