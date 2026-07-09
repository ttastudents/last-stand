#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sentinel Guard v30.0 "Last Stand — Ascendant"
=============================================
Single-file, production-grade async anti-DDoS **Layer-7** reverse-proxy.

Pure application layer: no iptables/nftables, no kernel or root dependency.
Runs on Linux + Windows + macOS. Only dependency is aiohttp.

Usage:
  python3 laststand.py                        # env config, listen 9999
  BACKEND_URL=http://127.0.0.1:8080 \\
    RATE_LIMIT=200 BURST_LIMIT=400 \\
    ENABLE_WAF=1 POW_MODE=auto python3 laststand.py
  python3 laststand.py --help
  python3 laststand.py --dry-run
  python3 laststand.py --self-test           # run the built-in unit suite

Defence-in-depth, all L7:
  • Per-IP token-bucket rate limiting with escalating prefix bans
  • Rolling burst-window flood detection + global request cap
  • Connection / endpoint / unique-query (scraper) caps
  • Linear-time WAF: SQLi, XSS, prototype-pollution, LFI/traversal, RCE,
    SSRF, Log4Shell/JNDI, SpEL/template injection, XXE, NoSQL — inspected in
    path, query, JSON/text body **and headers**
  • HTTP request-smuggling (TE/CL) and Slowloris defence
  • Proof-of-Work "I'm Under Attack" challenge with a signed clearance cookie,
    auto-engaged when a block-rate spike is detected
  • Circuit breaker, backend health shedding, graceful drain, ban persistence
  • Prometheus / JSON metrics

Changes since v29 ("True Last Stand"):
  [v30-1] Streaming no longer truncates large downloads. The total-response
          timeout (backend ClientTimeout.total + a wait_for wrapping the whole
          stream) is replaced by per-chunk *idle* timeouts on both the backend
          read and the client write — a stalled peer is still cut, a steady
          large transfer completes. Also fixes the latent "prepare a response
          twice" error when the old total-timeout fired mid-stream.
  [v30-2] Constant-time secret comparison via hmac.compare_digest (the v29
          hand-rolled compare leaked length via an early return).
  [v30-3] Banned IPs no longer drain the global token bucket — the ban store
          is peeked before a global token is spent, closing a self-DoS vector.
  [v30-4] WAF expanded to LFI/RCE/SSRF/Log4Shell/SpEL/XXE/NoSQL and now scans
          header values (Log4Shell's usual vector) with a low-false-positive
          rule subset. All patterns remain provably linear-time.
  [v30-5] Proof-of-Work challenge subsystem + adaptive under-attack mode.
  Backwards compatible — same env vars, endpoints and flags as v28/v29; every
  new capability is opt-in or engages only under attack.

Every pass has been audited for self-DoS, smuggling, runaway CPU,
regex-pathology, and linear-time guarantees under attack.
"""

# ====================================================================== #
# Imports
# ====================================================================== #
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import platform
import queue
import random
import re
import secrets
import signal
import sys
import time
import uuid
from collections import OrderedDict, deque
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple
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
DEFAULT_BURST_LIMIT           = 400.0
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
WAF_BODY_TIMEOUT              = 5.0
# FIX-F: clamp workers to a sane CPU count to prevent context-switch DDoS
# on machines where os.cpu_count() reports high values.
WAF_MAX_WORKERS               = min(16, max(4, (os.cpu_count() or 4)))
WAF_REGEX_TIMEOUT             = 0.5  # tightened

DEFAULT_PER_IP_ENDPOINT_LIMIT = 120
DEFAULT_PER_IP_ENDPOINT_TTL   = 60

DEFAULT_GLOBAL_PER_IP_LIMIT   = 2000
DEFAULT_GLOBAL_PER_IP_TTL     = 60
DEFAULT_PER_IP_BURST_WINDOW   = 10.0
DEFAULT_PER_IP_BURST_LIMIT    = 40

HEALTH_CHECK_LIMIT            = 30
HEALTH_CHECK_TTL              = 60

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
DEFAULT_BACKEND_TIMEOUT       = 30.0

KEEPALIVE_TIMEOUT             = 0  # DDoS defence: no keepalive

SLOW_REQUEST_TIMEOUT          = 8
MAX_TOTAL_BODY_READ_SECONDS   = 15

DEFAULT_LOG_QUEUE_MAXSIZE     = 5000

# Cache sizes / ttls
_BAN_STORE_MAXSIZE            = int(os.getenv("BAN_STORE_MAXSIZE", "5000000"))
_BAN_STORE_TTL                = int(os.getenv("BAN_STORE_TTL",     "86400"))
_STATE_STORE_MAXSIZE          = int(os.getenv("STATE_STORE_MAXSIZE", "500000"))
_STATE_STORE_TTL              = int(os.getenv("STATE_STORE_TTL",     "3600"))
_KEY_CACHE_MAXSIZE            = int(os.getenv("KEY_CACHE_MAXSIZE",   "50000"))
_KEY_CACHE_TTL                = int(os.getenv("KEY_CACHE_TTL",       "600"))

SHARD_LOCK_COUNT              = 1024

BACKEND_MAX_RETRIES           = 2

MAX_JSON_ELEMENTS             = 1000
MAX_JSON_DEPTH                = 10
MAX_JSON_BYTES                = 65536

ALLOWED_HTTP_VERSIONS         = frozenset({(1, 0), (1, 1)})

_SQLI_KEYWORDS_LOWER = frozenset((
    "union", "select", "insert", "update", "delete", "drop",
    "sleep", "benchmark", "waitfor", "information_schema",
    "__proto__", "javascript",
))

# Wide set; cheap O(n) membership per chunk. Real matching uses regex with \b.
_SUSPICIOUS_CHARS            = frozenset("'<>()-=%&|`/\\ \t\r\n\x00*?!#.;,{}[]")

# Cloudflare public egress CIDRs (last verified against published list).
# Source: https://www.cloudflare.com/ips/  Operators can override CF_PROXIES env.
CF_KNOWN_NETWORKS: Tuple[ipaddress._BaseNetwork, ...] = (
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.192.0/20"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("2400:cb00::/32"),
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2803:f800::/32"),
    ipaddress.ip_network("2405:b500::/32"),
    ipaddress.ip_network("2405:8100::/32"),
    ipaddress.ip_network("2a06:98c0::/29"),
    ipaddress.ip_network("2c0f:f248::/32"),
)

VERSION = "30.0"


# ====================================================================== #
# FD limit (cross-platform)
# ====================================================================== #
def _raise_fd_limit() -> int:
    if sys.platform == "win32":
        return MAX_SAFE_CONNS_WINDOWS
    if sys.platform == "darwin":
        try:
            import resource
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = min(max(soft, 8192), 65535)
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, target))
            except (ValueError, PermissionError):
                pass
            return min(target, 65535) - 100
        except Exception:
            return MAX_SAFE_CONNS_DARWIN
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


MAX_SAFE_CONNS: int = _raise_fd_limit()

BLOCK_HEADERS = {"Connection": "close", "Cache-Control": "no-store"}


# ====================================================================== #
# FastTTLCache (single event loop, O(1) amortised, bounded cleanup)
# ====================================================================== #
class FastTTLCache:
    __slots__ = ("_data", "_maxsize", "_ttl")

    def __init__(self, maxsize: int = DEFAULT_CACHE_MAXSIZE, ttl: float = DEFAULT_CACHE_TTL) -> None:
        self._data: "OrderedDict[str, Tuple[object, float]]" = OrderedDict()
        self._maxsize = max(1, maxsize)
        self._ttl = ttl

    def now(self) -> float:
        return time.monotonic()

    def _evict_expired_batch(self, batch: int = 200) -> int:
        """FIX-E: use iterator over keys, not materialised list. v28 called
        `list(self._data.keys())[:batch]` which cloned ALL keys into a list
        (e.g. ~40 MB for 5M-entry ban cache) and blocked the event loop
        dozens of milliseconds on every cleanup tick. We now iter until we
        see `batch` expired entries OR hit the first fresh one, then pop in
        a single batch. OrderedDict preserves insertion order so untouched
        old entries live at the head — exactly what we want to drop."""
        if not self._data:
            return 0
        now = self.now()
        keys_to_pop = []
        n = 0
        # Iterate insertion order; break on first non-expired or `batch`.
        for k in self._data:
            if n >= batch:
                break
            try:
                _, exp = self._data[k]
            except KeyError:
                continue
            if exp < now:
                keys_to_pop.append(k)
                n += 1
            else:
                break
        for k in keys_to_pop:
            self._data.pop(k, None)
        return n

    def get(self, key: str):
        item = self._data.get(key)
        if item is None:
            return None
        val, exp = item
        if exp < self.now():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return val

    def set(self, key: str, value, keep_ttl: bool = False) -> None:
        if keep_ttl and key in self._data:
            try:
                _, exp = self._data[key]
                self._data[key] = (value, exp)
            except KeyError:
                self._data[key] = (value, self.now() + self._ttl)
                return
            self._data.move_to_end(key)
            return
        if key in self._data:
            self._data.pop(key, None)
        if len(self._data) >= self._maxsize:
            for _ in range(min(64, len(self._data))):
                self._data.pop(next(iter(self._data)), None)
        self._data[key] = (value, self.now() + self._ttl)

    def __setitem__(self, key: str, value) -> None:
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

    def cleanup(self) -> None:
        for _ in range(10):
            n = self._evict_expired_batch(200)
            if n == 0:
                break
        while len(self._data) > self._maxsize:
            self._data.pop(next(iter(self._data)), None)

    def items_snapshot(self):
        return list(self._data.items())

    def clear(self) -> None:
        self._data.clear()


# ====================================================================== #
# Configuration
# ====================================================================== #
class Config:
    @staticmethod
    def _safe_int(val, default: int, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
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
    def _safe_float(val, default: float, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
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
    def _parse_networks(raw: str) -> Set[ipaddress._BaseNetwork]:
        result: Set[ipaddress._BaseNetwork] = set()
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

    def __init__(self, overrides: Optional[Dict[str, Any]] = None) -> None:
        ov = dict(overrides or {})

        def ovget(k: str, default):
            return ov.get(k, os.getenv(k, default))

        self.listen_host = str(ovget("SENTINEL_HOST", ovget("LISTEN_HOST", "0.0.0.0")))
        self.listen_port = self._safe_int(ovget("SENTINEL_PORT", ovget("LISTEN_PORT", None)), 9999, 1, 65535)

        raw_backend = str(ovget("BACKEND_URL", "http://127.0.0.1:8888")).rstrip("/")
        parsed = urlparse(raw_backend)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"BACKEND_URL must be http(s)://host:port, got {raw_backend!r}")
        self.backend_url = raw_backend

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
        self.cloudflare_proxies      = self._parse_networks(ovget("CF_PROXIES", ""))
        if not self.cloudflare_proxies:
            self.cloudflare_proxies = set(CF_KNOWN_NETWORKS)
        self.whitelist_ips           = self._parse_networks(ovget("WHITELIST", ""))
        self.blacklist_ips           = self._parse_networks(ovget("BLACKLIST", ""))

        env_methods = ovget("ALLOWED_METHODS", "GET,POST,HEAD,PUT,DELETE,OPTIONS,PATCH")
        self.allowed_methods: Set[str] = {m.strip().upper() for m in env_methods.split(",") if m.strip()}
        self.allowed_methods.difference_update({"CONNECT", "TRACE", "TRACK"})

        self.max_header_size         = self._safe_int(ovget("MAX_HEADER_SIZE", None), DEFAULT_MAX_HEADER_SIZE, 1)
        self.max_headers             = self._safe_int(ovget("MAX_HEADERS", None), DEFAULT_MAX_HEADERS, 1)
        self.max_uri_size            = self._safe_int(ovget("MAX_URI_SIZE", None), DEFAULT_MAX_URI_SIZE, 1)
        self.max_total_headers_size  = self._safe_int(ovget("MAX_TOTAL_HEADERS_SIZE", None),
                                                      DEFAULT_MAX_TOTAL_HEADERS_SZ, 1)

        self.bad_ua_strings: Tuple[str, ...] = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nessus",
            "acunetix", "burp", "dirbuster", "wfuzz", "skipfish",
            "whatweb", "netsparker", "w3af", "zaproxy", "arachni",
            "gobuster", "feroxbuster",
        )
        custom_ua = ovget("BAD_UA_PATTERNS", "")
        if custom_ua:
            self.bad_ua_strings = self.bad_ua_strings + tuple(
                p.strip().lower() for p in custom_ua.split(",") if p.strip()
            )
        self.bad_ua_regex = re.compile(
            r"(?<![\w-])(" + "|".join(re.escape(s) for s in self.bad_ua_strings) + r")(?![\w-])",
            re.IGNORECASE,
        )

        self.enable_waf              = (ovget("ENABLE_WAF", "1") in ("1", "true", "True", "yes"))
        self.waf_body_timeout        = self._safe_float(ovget("WAF_BODY_TIMEOUT", None),
                                                         WAF_BODY_TIMEOUT, 0.1)
        self.waf_regex_timeout       = self._safe_float(ovget("WAF_REGEX_TIMEOUT", None),
                                                         WAF_REGEX_TIMEOUT, 0.05)

        self.backend_pool_size       = self._safe_int(ovget("BACKEND_POOL_SIZE", None),
                                                     OUTBOUND_SEM_BASE, 1)
        self.verify_ssl              = (ovget("VERIFY_SSL", "1") in ("1", "true", "True", "yes"))
        self.backend_timeout         = self._safe_float(ovget("BACKEND_TIMEOUT", None),
                                                         DEFAULT_BACKEND_TIMEOUT, 1.0)

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
        self.server_header           = str(ovget("SERVER_HEADER", "Sentinel"))
        self.shutdown_timeout        = self._safe_float(ovget("SHUTDOWN_TIMEOUT", None), 30.0, 1.0)
        self.ipv6_prefix             = self._safe_int(ovget("IPV6_PREFIX", None), 64, 16, 128)

        raw_hosts = ovget("ALLOWED_HOSTS", "")
        self.allowed_hosts: Set[str] = {h.strip().lower() for h in raw_hosts.split(",") if h.strip()}

        self.health_check_enabled    = (ovget("BACKEND_HEALTH_CHECK", "0") in
                                        ("1", "true", "True", "yes"))
        self.health_path             = str(ovget("BACKEND_HEALTH_PATH", "/health")).strip()
        if not self.health_path.startswith("/"):
            self.health_path = "/" + self.health_path

        self.per_ip_endpoint_limit   = self._safe_int(ovget("PER_IP_ENDPOINT_LIMIT", None),
                                                       DEFAULT_PER_IP_ENDPOINT_LIMIT, 1)
        self.per_ip_backend_limit    = self._safe_int(ovget("PER_IP_BACKEND_LIMIT", None), 20, 1)
        self.global_rate_limit       = self._safe_float(ovget("GLOBAL_RATE_LIMIT", None), 5000.0, 1.0)
        self.global_burst            = self._safe_float(ovget("GLOBAL_BURST", None), 10000.0, 1.0)
        self.ban_persist_file        = str(ovget("BAN_PERSIST_FILE", "sentinel_bans.json"))
        self.ban_persist_interval    = self._safe_int(ovget("BAN_PERSIST_INTERVAL", None), 300, 1)

        self.per_ip_burst_window     = self._safe_float(ovget("PER_IP_BURST_WINDOW", None),
                                                         DEFAULT_PER_IP_BURST_WINDOW, 1.0)
        self.per_ip_burst_limit      = self._safe_int(ovget("PER_IP_BURST_LIMIT", None),
                                                       DEFAULT_PER_IP_BURST_LIMIT, 1)
        self.metrics_token           = str(ovget("METRICS_TOKEN", ""))
        self.unique_query_threshold  = self._safe_int(ovget("UNIQUE_QUERY_THRESHOLD", None), 50, 1)
        self.unique_query_hard_limit = self._safe_int(ovget("UNIQUE_QUERY_HARD_LIMIT", None), 500, 1)

        # Streaming (v30). resp_max_bps=0 disables the response throttle.
        # The stream uses an *idle* timeout (max gap between chunks), not a
        # total-duration timeout, so large legitimate downloads are never
        # truncated while stalled backends/clients are still cut off.
        self.resp_max_bps            = self._safe_int(ovget("RESP_MAX_BPS", None),
                                                      2 * 1024 * 1024, 0)
        self.stream_idle_timeout     = self._safe_float(ovget("STREAM_IDLE_TIMEOUT", None),
                                                        15.0, 1.0)
        # Bounds the pre-forward analysis phase only (WAF, rate-limit, etc.).
        # The streaming phase is governed by stream_idle_timeout instead.
        self.analysis_timeout        = self._safe_float(
            ovget("ANALYSIS_TIMEOUT", None),
            max(self.backend_timeout + 5.0, 12.0), 2.0)

        # Proof-of-Work challenge ("I'm Under Attack" mode, v30).
        #   off  — never challenge (v29 behaviour)
        #   on   — always challenge un-cleared browser navigations
        #   auto — engage automatically when a block-rate spike is detected
        pm = str(ovget("POW_MODE", "auto")).lower().strip()
        self.pow_mode                = pm if pm in ("off", "on", "auto") else "auto"
        self.pow_bits                = self._safe_int(ovget("POW_BITS", None), 18, 8, 26)
        self.pow_ttl                 = self._safe_int(ovget("POW_TTL", None), 300, 10)
        self.pow_clearance_ttl       = self._safe_int(ovget("POW_CLEARANCE_TTL", None),
                                                      1800, 30)
        self.pow_cookie              = str(ovget("POW_COOKIE", "__sentinel_clr")).strip() \
                                       or "__sentinel_clr"
        # Shared secret for multi-instance deployments — clearance cookies /
        # challenges issued by one node must validate on another. If unset a
        # random per-process secret is generated (single-instance only).
        self.pow_secret              = str(ovget("POW_SECRET", "")).strip()
        self.pow_verify_limit        = self._safe_int(ovget("POW_VERIFY_LIMIT", None), 60, 1)
        # auto-engage: >= this many blocks within the window trips under-attack.
        self.auto_pow_blocks         = self._safe_int(ovget("AUTO_POW_BLOCKS", None), 100, 1)
        self.auto_pow_window         = self._safe_float(ovget("AUTO_POW_WINDOW", None), 10.0, 1.0)
        self.auto_pow_cooldown       = self._safe_float(ovget("AUTO_POW_COOLDOWN", None),
                                                        120.0, 5.0)


# ====================================================================== #
# Logging (non-blocking, drop on full, drop counter exposed)
# ====================================================================== #
class _MetricsCollector:
    __slots__ = (
        "requests", "blocked", "waf_hits", "waf_overloads", "waf_errors",
        "bans", "slow_aborts", "circuit_rejects", "rate_blocked",
        "burst_window_blocks", "scraper_blocks", "global_blocks",
        "log_drops", "audit_log_drops",
        "pow_challenges", "pow_solved", "pow_failed", "clearance_granted",
        "under_attack", "under_attack_engaged",
    )

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.requests = 0
        self.blocked = 0
        self.waf_hits = 0
        self.waf_overloads = 0
        self.waf_errors = 0
        self.bans = 0
        self.slow_aborts = 0
        self.circuit_rejects = 0
        self.rate_blocked = 0
        self.burst_window_blocks = 0
        self.scraper_blocks = 0
        self.global_blocks = 0
        self.log_drops = 0
        self.audit_log_drops = 0
        self.pow_challenges = 0        # challenge interstitials issued
        self.pow_solved = 0            # valid PoW solutions accepted
        self.pow_failed = 0            # invalid/expired solutions rejected
        self.clearance_granted = 0     # clearance cookies issued
        self.under_attack = 0          # gauge: 1 while auto-mode is engaged
        self.under_attack_engaged = 0  # counter: times auto-mode engaged


_METRICS = _MetricsCollector()


class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    """Drops on full but bumps a counter so the operator can see drops."""

    def __init__(self, q: "queue.Queue", metric_attr: Optional[str] = None) -> None:
        super().__init__(q)
        self._metric_attr = metric_attr

    def emit(self, record) -> None:
        try:
            self.enqueue(record)
        except queue.Full:
            if self._metric_attr and hasattr(_METRICS, self._metric_attr):
                setattr(_METRICS, self._metric_attr,
                        getattr(_METRICS, self._metric_attr) + 1)


class JSONFormatter(logging.Formatter):
    def format(self, record) -> str:
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

    qh = NonBlockingQueueHandler(log_q, metric_attr="log_drops")
    logger = logging.getLogger("Sentinel")
    logger.setLevel(cfg.log_level)
    logger.handlers.clear()
    logger.addHandler(qh)
    logger.propagate = False

    aqh = NonBlockingQueueHandler(audit_q, metric_attr="audit_log_drops")
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

    return logger, audit_logger, listener, audit_listener


# ====================================================================== #
# WAF engine  (linear-time, hard-capped, runs in worker thread pool)
# ====================================================================== #
WAF_REGEX_SCAN_BYTES = 2048

_SQLI_PATTERNS = [
    re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor)\s*\(", re.IGNORECASE),
    re.compile(r"\bunion\b[^\w]{1,8}\b(?:all|distinct)?\b\s*\bselect\b", re.IGNORECASE),
    re.compile(r"\bselect\b[^\w]{0,8}\bfrom\b", re.IGNORECASE),
    re.compile(r"\binsert\b[^\w]{0,8}\binto\b", re.IGNORECASE),
    re.compile(r"\bupdate\b[^\w]{0,8}\bset\b", re.IGNORECASE),
    re.compile(r"\bdelete\b[^\w]{0,8}\bfrom\b", re.IGNORECASE),
    re.compile(r"\bdrop\b[^\w]{0,8}\btable\b", re.IGNORECASE),
    re.compile(r"'\s*(?:or|and)\s+['\d]", re.IGNORECASE),
    re.compile(r"(?:--|#)\s|/\*", re.IGNORECASE),
    re.compile(r";\s*(?:drop|alter|create|insert|update|delete)\b", re.IGNORECASE),
    re.compile(r"\b(?:information_schema|sysobjects|syscolumns)\b", re.IGNORECASE),
    re.compile(r"(?:\.\./)|(?:\.\.\\)|(?:%2e%2e%2f)|(?:%2e%2e/)|(?:\.\.%2f)|(?:%2e%2e%5c)",
               re.IGNORECASE),
    # FIX-C: removed `[\d'\"\s]+` whitespace class overlap with `\s*`
    # that caused catastrophic backtracking. New `[\d'\"]+` is provably
    # linear (no overlapping whitespace between tokens).
    re.compile(r"\b(?:or|and)\b\s+[\d'\"]+\s*=\s*[\d'\"]+\s*", re.IGNORECASE),
    re.compile(r"\b(?:concat|char|load_file)\s*\(", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"\bon\w{1,32}\s*=", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<\s*img\b[^>]{0,200}src\s*=\s*['\"]?javascript:",
               re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*(?:iframe|object|embed|svg|math|base|frame)\b", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bdocument\s*\.\s*(?:cookie|write|location)", re.IGNORECASE),
    re.compile(r"<\s*meta\b[^>]{0,200}http-equiv\s*=\s*['\"]?refresh",
               re.IGNORECASE | re.DOTALL),
]

_PROTO_POLLUTION_PATTERNS = [
    re.compile(r"\b__proto__\b", re.IGNORECASE),
    re.compile(r"\bconstructor\b\s*\[", re.IGNORECASE),
    re.compile(r"\bprototype\b\s*\[", re.IGNORECASE),
]

# --- v30 categories. Every pattern is provably linear-time: bounded
# quantifiers only, no nested/overlapping repetition, no back-references.

# Local File Inclusion / path traversal (file-target specific — the bare
# `../` case is also caught by the SQLi traversal rule above).
_TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\.[\\/]){2,}"),
    re.compile(r"(?:%2e%2e[\\/%])", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|hosts|group|gshadow|mysql)\b", re.IGNORECASE),
    re.compile(r"/proc/self/(?:environ|cmdline|status|maps|fd)\b", re.IGNORECASE),
    re.compile(r"\b(?:php|file|zip|phar|expect|data|glob|compress\.\w+)://", re.IGNORECASE),
    re.compile(r"[\\/](?:windows|winnt)[\\/](?:win\.ini|system32|system\.ini)", re.IGNORECASE),
]

# Remote Command Execution / OS command injection. Every rule is gated on a
# shell metacharacter so bare words never match.
_RCE_PATTERNS = [
    re.compile(r"[;&|]\s{0,4}(?:cat|ls|id|pwd|whoami|uname|wget|curl|bash|sh|zsh|ksh|"
               r"nc|ncat|netcat|python[0-9]?|perl|ruby|php|powershell|pwsh|cmd|certutil|"
               r"nslookup|dig|ping|chmod|chown|rm|mv|cp|kill|touch|mkdir|scp|ssh|tftp)\b",
               re.IGNORECASE),
    re.compile(r"\$\(\s*[\w/]"),
    re.compile(r"`[^`]{0,80}`"),
    re.compile(r"\|\s{0,4}(?:sh|bash|zsh|nc|ncat|curl|wget|python[0-9]?|perl|php)\b",
               re.IGNORECASE),
    re.compile(r"&&\s{0,4}(?:cat|curl|wget|bash|sh|nc|whoami|id|ping)\b", re.IGNORECASE),
    re.compile(r"/(?:bin|usr/bin|sbin)/(?:sh|bash|zsh|nc|python[0-9]?|perl)\b", re.IGNORECASE),
    re.compile(r"\$\{IFS\}", re.IGNORECASE),
    re.compile(r"\bnc\b\s{0,4}-[a-z]{0,3}e\b", re.IGNORECASE),
]

# Server-Side Request Forgery — cloud metadata endpoints, dangerous URL
# schemes, and internal hosts. Public URLs (https://example.com) do NOT match.
_SSRF_PATTERNS = [
    re.compile(r"\b169\.254\.169\.254\b"),
    re.compile(r"\bmetadata\.google\.internal\b", re.IGNORECASE),
    re.compile(r"\b100\.100\.100\.200\b"),
    re.compile(r"\b(?:gopher|dict|ftp|tftp|ldap|ldaps|jar|netdoc)://", re.IGNORECASE),
    re.compile(r"://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d|\[?::1\]?)", re.IGNORECASE),
]

# Log4Shell / JNDI + SpEL / template / scriptlet injection.
_INJECT_PATTERNS = [
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    re.compile(r"\$\{(?:env|sys|ctx|lower|upper|date|java|main|base64|url|spring|"
               r"k8s|log4j|kubernetes|hostName|sd):", re.IGNORECASE),
    re.compile(r"\$\{[^}]{0,30}\$\{"),
    re.compile(r"\$\{T\(", re.IGNORECASE),
    re.compile(r"#\{[^}]{0,60}\}"),
    re.compile(r"<%[=@]?[^%]{0,100}%>"),
    re.compile(r"\{\{[^}]{0,60}(?:\*|__|\bconfig\b|\bself\b|request|cycler|joiner)[^}]{0,60}\}\}",
               re.IGNORECASE),
]

# XML External Entity.
_XXE_PATTERNS = [
    re.compile(r"<!ENTITY\b", re.IGNORECASE),
    re.compile(r"<!DOCTYPE\b[^>]{0,200}(?:SYSTEM|PUBLIC)\b", re.IGNORECASE),
    re.compile(r"\bSYSTEM\s+[\"']?(?:file|https?|php|expect)://", re.IGNORECASE),
]

# NoSQL / operator injection.
_NOSQL_PATTERNS = [
    re.compile(r"\[\$(?:ne|eq|gt|gte|lt|lte|in|nin|or|and|not|nor|where|regex|"
               r"exists|type|mod|all|size|elemmatch)\]", re.IGNORECASE),
    re.compile(r"\$where\b", re.IGNORECASE),
    re.compile(r"\{\s*\$(?:ne|gt|gte|lt|lte|where|regex|function)\b", re.IGNORECASE),
]

# Fixed high-signal substrings — a single cheap lowercase pass before regex.
_TOKEN_SIGNATURES: Tuple[Tuple[str, str], ...] = (
    ("${jndi:", "INJECT"), ("jndi:ldap", "INJECT"), ("jndi:rmi", "INJECT"),
    ("jndi:dns", "INJECT"), ("jndi:iiop", "INJECT"),
    ("/etc/passwd", "LFI"), ("/etc/shadow", "LFI"), ("etc/passwd", "LFI"),
    ("/proc/self/environ", "LFI"), ("boot.ini", "LFI"),
    ("169.254.169.254", "SSRF"), ("metadata.google.internal", "SSRF"),
    ("<!entity", "XXE"), ("<!doctype", "XXE"),
    ("/bin/sh", "RCE"), ("/bin/bash", "RCE"), ("cmd.exe", "RCE"),
)

# Category groups scanned by waf_check (full) and the header scanner (subset).
_ALL_GROUPS: Tuple[Tuple[list, str], ...] = (
    (_SQLI_PATTERNS, "SQLi"),
    (_XSS_PATTERNS, "XSS"),
    (_TRAVERSAL_PATTERNS, "LFI"),
    (_RCE_PATTERNS, "RCE"),
    (_SSRF_PATTERNS, "SSRF"),
    (_INJECT_PATTERNS, "INJECT"),
    (_PROTO_POLLUTION_PATTERNS, "PROTO"),
    (_XXE_PATTERNS, "XXE"),
    (_NOSQL_PATTERNS, "NOSQL"),
)
# Header-borne threats only. SQLi/XSS are deliberately excluded so a legit
# `Referer` carrying a query string is never a false positive.
_HEADER_GROUPS: Tuple[Tuple[list, str], ...] = (
    (_TRAVERSAL_PATTERNS, "LFI"),
    (_SSRF_PATTERNS, "SSRF"),
    (_INJECT_PATTERNS, "INJECT"),
    (_XXE_PATTERNS, "XXE"),
)

# Every attack label the WAF can emit (vs. the WAF_* infra-error labels).
WAF_ATTACK_LABELS = frozenset({"SQLi", "XSS", "PROTO", "LFI", "RCE",
                               "SSRF", "INJECT", "XXE", "NOSQL"})
WAF_JSON_LABELS = WAF_ATTACK_LABELS | {"JSON_BOMB", "JSON_OVERSIZED",
                                       "JSON_DEPTH", "JSON_ELEMENTS"}

HEADER_WAF_SCAN_BUDGET = 8192
HEADER_WAF_VALUE_CAP   = 1024


def _decode_aggressive(data: str) -> str:
    cleaned = data
    for _ in range(3):
        new = unquote(cleaned)
        if new == cleaned:
            break
        cleaned = new
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
    return cleaned


def _scan_groups(cleaned: str, low: str, groups) -> Optional[str]:
    for tok, label in _TOKEN_SIGNATURES:
        if tok in low:
            return label
    for pats, label in groups:
        for p in pats:
            if p.search(cleaned):
                return label
    return None


def waf_check(data: str) -> Optional[str]:
    """Linear-time signature scan on a hard-capped prefix. Returns the attack
    category label (SQLi/XSS/LFI/RCE/SSRF/INJECT/PROTO/XXE/NOSQL) or None."""
    if not data:
        return None
    data = data[:WAF_REGEX_SCAN_BYTES]
    try:
        cleaned = _decode_aggressive(data)
    except Exception:
        return "ERROR"
    try:
        return _scan_groups(cleaned, cleaned.lower(), _ALL_GROUPS)
    except Exception:
        return "ERROR"


def waf_check_headers_text(seg: str) -> Optional[str]:
    """Low-false-positive header scan (traversal/SSRF/JNDI/XXE + fixed tokens).
    Never runs SQLi/XSS rules — those false-positive on legit Referer values."""
    if not seg:
        return None
    try:
        cleaned = _decode_aggressive(seg[:WAF_REGEX_SCAN_BYTES])
        return _scan_groups(cleaned, cleaned.lower(), _HEADER_GROUPS)
    except Exception:
        return None


async def async_waf_check(data: str, executor, sem: Optional["asyncio.Semaphore"] = None,
                          cfg: Optional[Config] = None) -> Optional[str]:
    """Run waf_check in a thread pool with hard timeout and bounded queue.

    CRITICAL [FIX-01]: WAF infra failures (timeout, overload, executor death)
    MUST NOT translate into user bans — that would let any attacker ban every
    legit IP in their subnet. Returns "WAF_*" so caller can return 503/400."""
    if not data:
        return None
    # Cheap fast-path: looks normal, skip
    if (not any((ord(c) < 32 or c in _SUSPICIOUS_CHARS) for c in data[:256])
            and not any(kw in data.lower() for kw in _SQLI_KEYWORDS_LOWER)):
        return None

    loop = asyncio.get_running_loop()
    timeout = cfg.waf_regex_timeout if cfg else WAF_REGEX_TIMEOUT

    if sem is not None:
        if not await _try_acquire_async(sem):  # FIX-A
            _METRICS.waf_overloads += 1
            return "WAF_OVERLOAD"
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(executor, waf_check, data),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            _METRICS.waf_errors += 1
            return "WAF_TIMEOUT"
        finally:
            sem.release()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(executor, waf_check, data),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        _METRICS.waf_errors += 1
        return "WAF_TIMEOUT"


def _json_preflight(text: str) -> Optional[str]:
    """Cheap JSON-bomb pre-screening before handing to json.loads."""
    if not text:
        return None
    if len(text) > MAX_JSON_BYTES:
        return "JSON_OVERSIZED"
    depth = 0
    in_string = False
    escape = False
    elements = 0
    for c in text:
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c == "{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return "JSON_DEPTH"
        elif c == "}":
            if depth > 0:
                depth -= 1
        elif c in "[,":
            elements += 1
            if elements > MAX_JSON_ELEMENTS:
                return "JSON_ELEMENTS"
    return None


def _json_parse_and_scan(text: str) -> Optional[str]:
    pre = _json_preflight(text)
    if pre:
        return pre
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
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
# RateLimiter: per-IP token bucket + prefix banning + global cap + burst
# ====================================================================== #
class IPState:
    __slots__ = (
        "tokens", "last_time", "violations", "last_violation_time",
        "active_conns", "first_seen", "queries_seen",
    )

    def __init__(self, burst: float,
                 burst_limit: int = DEFAULT_PER_IP_BURST_LIMIT) -> None:
        self.tokens = burst
        self.last_time = time.monotonic()
        self.violations = 0
        self.last_violation_time = 0.0
        self.active_conns = 0
        self.first_seen = time.monotonic()
        # FIX-16: deque sized to actual configured burst limit + headroom.
        # Old code used a static 160 maxlen, which silently broke burst
        # detection when operators raised PER_IP_BURST_LIMIT above 160.
        self.queries_seen: deque = deque(maxlen=max(256, burst_limit * 8))


class RateLimiter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._store       = FastTTLCache(_STATE_STORE_MAXSIZE, _STATE_STORE_TTL)
        self._ban_store   = FastTTLCache(_BAN_STORE_MAXSIZE, _BAN_STORE_TTL)
        self._locks_pool: List[asyncio.Lock] = [asyncio.Lock() for _ in range(SHARD_LOCK_COUNT)]
        self._global_state = IPState(cfg.global_burst, int(cfg.global_burst))
        self._global_lock = asyncio.Lock()

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
            state = IPState(self.cfg.burst_limit, self.cfg.per_ip_burst_limit)
            self._store.set(ip, state)
        else:
            if state.first_seen > 0 and (time.monotonic() - state.first_seen) > 300:
                if state.violations == 0:
                    state.tokens = self.cfg.burst_limit
                state.first_seen = 0.0
        return state

    async def _check_global(self, ip_class: str) -> bool:
        if ip_class == "whitelist":
            return True
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
        hits = state.queries_seen
        while hits and hits[0] < now - window:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        return False

    async def check_and_acquire(self, ip: str, ip_class: str = "normal",
                                 bypass_ban: bool = False) -> Tuple[bool, float, str]:
        if ip_class == "blacklist":
            return False, 0.0, "blacklisted"

        # FIX (v30): peek the ban store BEFORE consuming a global token.
        # v29 called `_check_global` first, so a large *already-banned*
        # botnet still drained the global bucket on every request and
        # self-DoS'd legit users into "global_rate_limited". Dict `get`
        # is atomic under the GIL; the authoritative re-check still runs
        # under the shard lock below to close the peek→lock race.
        prefix_key = self._prefix_key(ip)
        if not bypass_ban:
            ban_until = self._ban_store.get(prefix_key)
            if ban_until and ban_until > time.monotonic():
                return False, 0.0, "banned"

        if not await self._check_global(ip_class):
            _METRICS.global_blocks += 1
            return False, 0.0, "global_rate_limited"

        lock = self._shard_lock(prefix_key)
        async with lock:
            now = time.monotonic()
            if not bypass_ban:
                ban_until = self._ban_store.get(prefix_key)
                if ban_until and ban_until > now:
                    return False, 0.0, "banned"

            s = self._get(ip)
            if s.active_conns >= self.cfg.max_conn_per_ip:
                return False, 0.0, "too_many_connections"

            if not bypass_ban and ip_class != "whitelist":
                if self._burst_window_violated(s):
                    s.violations = min(s.violations + 1, 100)
                    s.last_violation_time = now
                    ban_time = min(self.cfg.ban_max,
                                  self.cfg.ban_base * (self.cfg.ban_mult ** (s.violations - 1)))
                    self._ban_store.set(prefix_key, now + ban_time)
                    _METRICS.burst_window_blocks += 1
                    return False, 0.0, "burst_window"

            s.active_conns += 1

            elapsed = now - s.last_time
            s.last_time = now
            s.tokens = min(self.cfg.burst_limit, s.tokens + elapsed * self.cfg.rate_limit)
            if s.tokens >= 1.0:
                s.tokens -= 1.0
                return True, s.tokens, ""

            if ip_class == "whitelist":
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
            _METRICS.rate_blocked += 1
            if s.violations == 1 or s.violations % 10 == 0:
                if logger is not None:
                    logger.warning("IP %s banned %.0fs (violations: %d)",
                                   ip, ban_time, s.violations)
                if audit_logger is not None:
                    audit_logger.warning("BAN %s %.0fs violations=%d",
                                         ip, ban_time, s.violations)
            return False, 0.0, "rate_limited"

    async def dec_conn(self, ip: str) -> None:
        # FIX-D: lock on prefix_key, matching `check_and_acquire`. v28 locked
        # on raw IP while acquire locked on /24 prefix — counters could
        # desync under concurrent traffic from 2+ IPs in the same /24.
        prefix_key = self._prefix_key(ip)
        lock = self._shard_lock(prefix_key)
        async with lock:
            s = self._store.get(ip)
            if s and s.active_conns > 0:
                s.active_conns -= 1

    async def force_ban(self, ip: str, duration: Optional[float] = None,
                        request_id: Optional[str] = None) -> None:
        """Force-ban ONLY called on explicit WAF HITS (not infrastructure errors)."""
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
        _METRICS.bans += 1
        if audit_logger is not None:
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

    def save_bans(self) -> None:
        try:
            data = {}
            now = time.monotonic()
            for k, (val, _) in self._ban_store.items_snapshot():
                if isinstance(val, (int, float)) and val > now:
                    data[k] = float(val - now)
            tmp = self.cfg.ban_persist_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.cfg.ban_persist_file)
        except Exception as e:
            if logger is not None:
                logger.error("save_bans failed: %s", e)

    def load_bans(self) -> int:
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
            if logger is not None:
                logger.error("load_bans failed: %s", e)
            return 0


# ====================================================================== #
# CircuitBreaker
# ====================================================================== #
class CircuitBreaker:
    __slots__ = ("err_thr", "window", "probe_timeout",
                 "_errors", "_last_failure", "_state",
                 "_probe_in_progress", "_probe_start_time", "_lock")

    def __init__(self, err_thr: int, window: float, probe_timeout: float) -> None:
        self.err_thr = err_thr
        self.window = window
        self.probe_timeout = probe_timeout
        self._errors: deque = deque(maxlen=err_thr * 12)
        self._last_failure = time.monotonic()
        self._state = "CLOSED"
        self._probe_in_progress = False
        self._probe_start_time = 0.0
        self._lock = asyncio.Lock()

    def record_error(self) -> None:
        now = time.monotonic()
        self._errors.append(now)
        self._last_failure = now
        if self._state == "HALF_OPEN":
            self._state = "OPEN"
            self._probe_in_progress = False
            if logger is not None:
                logger.warning("Circuit breaker OPEN (probe failed)")
        elif self._state == "CLOSED" and len(self._errors) >= self.err_thr:
            self._state = "OPEN"
            if logger is not None:
                logger.warning("Circuit breaker OPEN (error threshold %d)", self.err_thr)

    def record_success(self) -> None:
        if self._state == "HALF_OPEN":
            self._state = "CLOSED"
            self._errors.clear()
            self._probe_in_progress = False
            if logger is not None:
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
        if now - self._probe_start_time > self.probe_timeout:
            async with self._lock:
                if self._state == "HALF_OPEN":
                    self._state = "OPEN"
                    self._probe_in_progress = False
                    self._last_failure = now
                    if logger is not None:
                        logger.error("Circuit breaker probe timed out")
            return False
        return False


# ====================================================================== #
# Non-blocking async acquire — public asyncio API ONLY (FIX-A)
# ====================================================================== #
async def _try_acquire_async(primitive) -> bool:
    """Public-API non-blocking acquire for `asyncio.Lock` AND `Semaphore`.

    v28 used CPython-private attributes (`lock._locked`, `sem._value`,
    `sem._waiters`) to probe availability. Those break under `uvloop`,
    PyPy, and asyncio internal refactors (e.g. Python 3.13 redesigned
    Future waking). This implementation:

      1. Schedules `primitive.acquire()` as a Task.
      2. Yields ONE event-loop tick via `await asyncio.sleep(0)`.
      3. If the primitive is available, the Task completes in that tick
         and we return `True`.
      4. Otherwise we cancel and return `False`.

    Worst cost: 1 event-loop cycle. Worst memory: 1 transient Task.
    No private attribute access. Fully portable.
    """
    if primitive is None:
        return False
    fut = asyncio.ensure_future(primitive.acquire())
    try:
        await asyncio.sleep(0)
    except BaseException:
        pass
    if fut.done() and not fut.cancelled():
        return True
    fut.cancel()
    # Drain cancellation so no Future is left dangling.
    for _ in range(2):
        if fut.done():
            break
        try:
            await asyncio.sleep(0)
        except BaseException:
            break
    return False


def try_acquire_lock(lock) -> bool:  # pragma: no cover — migration stub
    """Removed in v29. Use `await _try_acquire_async(lock)` instead.
    Raising surfaces accidental sync use during code-review / migration."""
    raise RuntimeError(
        "try_acquire_lock was retired in v29 (CPython-private API removed). "
        "Use `await _try_acquire_async(lock)` at the call site."
    )


def try_acquire_sem(sem) -> bool:  # pragma: no cover — migration stub
    """Removed in v29. Use `await _try_acquire_async(sem)` instead.
    Raising surfaces accidental sync use during code-review / migration."""
    raise RuntimeError(
        "try_acquire_sem was retired in v29 (CPython-private API removed). "
        "Use `await _try_acquire_async(sem)` at the call site."
    )


# ====================================================================== #
# Proof-of-Work challenge ("I'm Under Attack" mode, v30)
# ====================================================================== #
# A stateless, HMAC-signed proof-of-work interstitial — the single biggest
# L7 anti-DDoS capability v29 lacked. Un-cleared browser navigations are made
# to solve a SHA-256 partial pre-image in the browser before being proxied;
# a signed clearance cookie then bypasses the challenge for its lifetime.
# Volumetric L7 floods almost never execute JavaScript, so this sheds the
# overwhelming majority of application-layer flood traffic while genuine
# browsers pass transparently in a fraction of a second.
POW_VERIFY_PATH = "/__sentinel/verify"


def _leading_zero_bits(digest: bytes) -> int:
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        b = byte
        while b < 128:
            n += 1
            b <<= 1
        break
    return n


class ChallengeManager:
    """Issues/verifies PoW challenges and clearance cookies. Everything is
    self-authenticating via one HMAC key, so there is no per-client state and
    multiple instances that share POW_SECRET interoperate seamlessly."""

    __slots__ = ("_secret", "bits", "ttl", "clearance_ttl", "cookie_name", "secure")

    def __init__(self, cfg: "Config", secure: bool = False) -> None:
        if cfg.pow_secret:
            self._secret = hashlib.sha256(cfg.pow_secret.encode("utf-8")).digest()
        else:
            self._secret = secrets.token_bytes(32)
        self.bits          = cfg.pow_bits
        self.ttl           = cfg.pow_ttl
        self.clearance_ttl = cfg.pow_clearance_ttl
        self.cookie_name   = cfg.pow_cookie
        self.secure        = secure

    def _sign(self, msg: str) -> str:
        return hmac.new(self._secret, msg.encode("utf-8"),
                        hashlib.sha256).hexdigest()[:32]

    def make_challenge(self, prefix: str, now: Optional[float] = None) -> Dict[str, Any]:
        ts = int(now if now is not None else time.time())
        salt = secrets.token_hex(8)
        challenge = f"{prefix}|{ts}|{salt}"
        return {"challenge": challenge, "sig": self._sign("C:" + challenge),
                "bits": self.bits, "verify": POW_VERIFY_PATH,
                "cookie": self.cookie_name}

    def verify_solution(self, challenge: str, sig: str, nonce: str,
                        prefix: str, now: Optional[float] = None) -> bool:
        if not challenge or not sig or nonce is None:
            return False
        if not hmac.compare_digest(sig, self._sign("C:" + challenge)):
            return False
        parts = challenge.split("|")
        if len(parts) != 3:
            return False
        c_prefix, c_ts, _salt = parts
        if c_prefix != prefix:            # cookie/challenge bound to /prefix
            return False
        try:
            ts = int(c_ts)
        except ValueError:
            return False
        cur = now if now is not None else time.time()
        if cur - ts > self.ttl or ts - cur > 60:   # expired / clock-skew
            return False
        digest = hashlib.sha256(
            (challenge + str(nonce)).encode("utf-8", "ignore")).digest()
        return _leading_zero_bits(digest) >= self.bits

    def issue_clearance(self, prefix: str, now: Optional[float] = None) -> str:
        exp = int((now if now is not None else time.time()) + self.clearance_ttl)
        return f"{exp}.{self._sign(f'K:{prefix}:{exp}')}"

    def verify_clearance(self, token: str, prefix: str,
                         now: Optional[float] = None) -> bool:
        if not token or "." not in token:
            return False
        exp_s, _, mac = token.partition(".")
        try:
            exp = int(exp_s)
        except ValueError:
            return False
        cur = now if now is not None else time.time()
        if exp < cur:
            return False
        return hmac.compare_digest(mac, self._sign(f"K:{prefix}:{exp}"))

    def cookie_header(self, token: str) -> str:
        attrs = [f"{self.cookie_name}={token}", f"Max-Age={self.clearance_ttl}",
                 "Path=/", "HttpOnly", "SameSite=Lax"]
        if self.secure:
            attrs.append("Secure")
        return "; ".join(attrs)


# Self-contained interstitial: compact synchronous SHA-256 in pure JS (Web
# Crypto's async digest is far too slow for a tight PoW loop), a chunked solver
# that keeps the UI responsive, and a <noscript> fallback. __CHALLENGE_JSON__
# is substituted per request.
_CHALLENGE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser…</title>
<style>
 html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  background:#0b1020;color:#e7ecff}
 .wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}
 .card{max-width:420px;text-align:center;background:#141b31;border:1px solid #24304f;
  border-radius:16px;padding:32px 28px;box-shadow:0 10px 40px rgba(0,0,0,.35)}
 .spin{width:44px;height:44px;margin:0 auto 18px;border:4px solid #2a3860;
  border-top-color:#6ea8fe;border-radius:50%;animation:s 1s linear infinite}
 @keyframes s{to{transform:rotate(360deg)}}
 h1{font-size:19px;margin:0 0 8px}p{font-size:14px;color:#9fb0d9;margin:6px 0}
 .st{font-size:12px;color:#6f82b3;margin-top:14px;min-height:16px}
 code{color:#8ab4ff}
</style></head>
<body><div class="wrap"><div class="card">
 <div class="spin"></div>
 <h1>Checking your browser before proceeding</h1>
 <p>This automatic check protects the site against automated attacks.
    It runs once and takes a moment.</p>
 <p class="st" id="st">Initializing…</p>
 <noscript><p style="color:#ff9a9a">JavaScript is required to continue.</p></noscript>
</div></div>
<script id="sentinel-challenge" type="application/json">__CHALLENGE_JSON__</script>
<script>
(function(){
 function sha256(bytes){
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l=bytes.length,withOne=l+1,k=(56-withOne%64+64)%64,total=withOne+k+8;
  var m=new Uint8Array(total);m.set(bytes);m[l]=0x80;
  var dv=new DataView(m.buffer),bit=l*8;
  dv.setUint32(total-4,bit>>>0,false);dv.setUint32(total-8,Math.floor(bit/4294967296)>>>0,false);
  var w=new Int32Array(64),i,off;
  for(off=0;off<total;off+=64){
   for(i=0;i<16;i++)w[i]=dv.getUint32(off+i*4,false);
   for(i=16;i<64;i++){var x=w[i-15],y=w[i-2];
    var s0=((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3);
    var s1=((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10);
    w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
   var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
   for(i=0;i<64;i++){
    var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    var ch=(e&f)^((~e)&g),t1=(h+S1+ch+K[i]+w[i])|0;
    var S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    var mj=(a&b)^(a&c)^(b&c),t2=(S0+mj)|0;
    h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
   H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
   H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;}
  var out=new Uint8Array(32),od=new DataView(out.buffer);
  for(i=0;i<8;i++)od.setUint32(i*4,H[i]>>>0,false);return out;}
 function lz(d){var n=0;for(var i=0;i<d.length;i++){var b=d[i];if(b===0){n+=8;continue;}
  while(b<128){n++;b<<=1;}break;}return n;}
 function st(t){var e=document.getElementById('st');if(e)e.textContent=t;}
 var C;try{C=JSON.parse(document.getElementById('sentinel-challenge').textContent);}catch(e){return;}
 var enc=new TextEncoder(),nonce=0,t0=Date.now();
 function submit(n){
  fetch(C.verify,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({challenge:C.challenge,sig:C.sig,nonce:String(n)})})
  .then(function(r){if(r.ok){st('Verified. Loading…');location.reload();}
   else{st('Verification failed — refresh to retry.');}})
  .catch(function(){st('Network error — refresh to retry.');});}
 function work(){
  var end=(typeof performance!=='undefined'?performance.now():Date.now())+250;
  while((typeof performance!=='undefined'?performance.now():Date.now())<end){
   if(lz(sha256(enc.encode(C.challenge+nonce)))>=C.bits){
    st('Solved in '+((Date.now()-t0)/1000).toFixed(1)+'s.');submit(nonce);return;}
   nonce++;}
  st('Verifying your browser… '+nonce+' attempts');
  setTimeout(work,0);}
 st('Verifying your browser…');setTimeout(work,30);
})();
</script></body></html>"""


def _challenge_html(params: Dict[str, Any]) -> str:
    return _CHALLENGE_PAGE.replace("__CHALLENGE_JSON__", json.dumps(params))


# ====================================================================== #
# SentinelApp — the proxy + pipeline
# ====================================================================== #
class _Ctx:
    """Mutable request-handling state passed through the pipeline."""
    __slots__ = ("ip", "ip_class", "rid", "started", "body_chunk",
                 "outbound_sem", "response_started")

    def __init__(self, ip: str, ip_class: str, rid: str,
                 started: float, body_chunk: Optional[bytes],
                 outbound_sem: Optional["asyncio.Semaphore"]) -> None:
        self.ip = ip
        self.ip_class = ip_class
        self.rid = rid
        self.started = started
        self.body_chunk = body_chunk
        self.outbound_sem = outbound_sem
        # True once bytes have been flushed to the client. After this point
        # the pipeline can no longer substitute a fresh error Response.
        self.response_started = False


class SentinelApp:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session: Optional[ClientSession] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.cb: Optional[CircuitBreaker] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._health_task: Optional[asyncio.Task] = None
        self._persist_task: Optional[asyncio.Task] = None
        self._backend_healthy = True
        self._active_inbound = 0
        self._active_outbound = 0

        # Proof-of-Work challenge state (v30).
        self.challenge: Optional[ChallengeManager] = None
        self._attack_task: Optional[asyncio.Task] = None
        self._under_attack_until = 0.0

        # counters are dict ops under GIL — no asyncio.Lock needed (FIX-07)
        self.ip_obj_cache           = FastTTLCache(100000, 3600)
        self.ip_class_cache         = FastTTLCache(100000, 3600)
        self.per_ip_endpoint_cache  = FastTTLCache(_STATE_STORE_MAXSIZE, 60)
        self.global_per_ip_cache    = FastTTLCache(_STATE_STORE_MAXSIZE, 60)
        self.unique_query_cache     = FastTTLCache(50000, 300)
        self._per_ip_outbound_cache = FastTTLCache(_STATE_STORE_MAXSIZE, 300)

        parsed = urlparse(cfg.backend_url)
        host = parsed.hostname or "localhost"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        self.backend_host = host

        self.waf_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None

    # ---- lifecycle ---- #
    async def startup(self, app: web.Application) -> None:
        global INBOUND_CONN_SEM, WAF_SEM, OUTBOUND_REQ_SEM
        if self._shutdown_event is None:
            self._shutdown_event = asyncio.Event()
        if INBOUND_CONN_SEM is None:
            INBOUND_CONN_SEM = asyncio.Semaphore(min(MAX_SAFE_CONNS, 65535))
        if WAF_SEM is None:
            WAF_SEM = asyncio.Semaphore(self.cfg.backend_pool_size * WAF_SEM_MULTIPLIER)
        if OUTBOUND_REQ_SEM is None:
            OUTBOUND_REQ_SEM = asyncio.Semaphore(self.cfg.backend_pool_size)

        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(self.cfg)
            n = self.rate_limiter.load_bans()
            if logger is not None:
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

        if self.challenge is None and self.cfg.pow_mode != "off":
            self.challenge = ChallengeManager(
                self.cfg, secure=(URL_SCHEME == "https"))
            if not self.cfg.pow_secret and logger is not None:
                logger.warning("POW_SECRET unset — using a random per-process "
                               "key; set POW_SECRET for multi-instance clearance")
            if self.cfg.pow_mode == "auto":
                self._attack_task = asyncio.create_task(self._attack_monitor_loop())
            if logger is not None:
                logger.info("PoW challenge enabled (mode=%s, bits=%d)",
                            self.cfg.pow_mode, self.cfg.pow_bits)

        connector = TCPConnector(limit=self.cfg.backend_pool_size, ttl_dns_cache=300,
                                 enable_cleanup_closed=True)
        # FIX (v30): NO `total` cap. A total-response timeout truncates large
        # legitimate downloads streamed through the proxy (v29 cut every
        # response at backend_timeout seconds). Bound the backend by connect +
        # idle-read timeouts instead — the same model as nginx's
        # proxy_read_timeout / haproxy's timeout server.
        timeout = ClientTimeout(total=None,
                                connect=min(5.0, self.cfg.backend_timeout),
                                sock_connect=min(5.0, self.cfg.backend_timeout),
                                sock_read=max(self.cfg.backend_timeout,
                                              self.cfg.stream_idle_timeout))
        self.session = ClientSession(connector=connector, timeout=timeout,
                                     auto_decompress=False)
        app["session"] = self.session
        app["waf_executor"] = self.waf_executor
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._persist_task = asyncio.create_task(self._persist_loop())
        if self.cfg.health_check_enabled:
            self._health_task = asyncio.create_task(self._health_check_loop())
        if logger is not None:
            logger.info("Startup complete — v%s on %s:%d → %s",
                        VERSION, self.cfg.listen_host, self.cfg.listen_port,
                        self.cfg.backend_url)

    async def shutdown(self, app: web.Application) -> None:
        if self._shutdown_event:
            self._shutdown_event.set()
        for t in (self._health_task, self._cleanup_task, self._persist_task,
                  self._attack_task):
            if t:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        if self.rate_limiter:
            self.rate_limiter.save_bans()
        if logger is not None:
            logger.info("Shutdown: waiting for in-flight requests...")
        deadline = time.monotonic() + self.cfg.shutdown_timeout
        while time.monotonic() < deadline:
            if self._active_inbound == 0 and self._active_outbound == 0:
                break
            await asyncio.sleep(0.05)
        if self._active_inbound > 0 or self._active_outbound > 0:
            if logger is not None:
                logger.warning("Shutdown deadline hit with %d/%d in flight",
                               self._active_inbound, self._active_outbound)
        if self.session:
            await self.session.close()
        if self.waf_executor:
            self.waf_executor.shutdown(wait=True)

    async def _persist_loop(self) -> None:
        while self._shutdown_event and not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=self.cfg.ban_persist_interval)
                break
            except asyncio.TimeoutError:
                pass
            if self.rate_limiter:
                self.rate_limiter.save_bans()

    async def _cleanup_loop(self) -> None:
        while self._shutdown_event and not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(),
                                       timeout=self.cfg.cleanup_interval)
                break
            except asyncio.TimeoutError:
                pass
            for c in (self.rate_limiter._store, self.rate_limiter._ban_store,
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

    async def _health_check_loop(self) -> None:
        while self._shutdown_event and not self._shutdown_event.is_set():
            ok = await self._backend_health_check()
            if ok != self._backend_healthy:
                self._backend_healthy = ok
                if ok:
                    if logger is not None:
                        logger.info("Backend healthy again")
                else:
                    if logger is not None:
                        logger.warning("Backend unhealthy — shedding traffic")
            await asyncio.sleep(30 + random.uniform(-5, 5))

    # ---- proof-of-work / under-attack ---- #
    def _challenge_active(self) -> bool:
        """Whether the PoW gate should challenge un-cleared navigations now."""
        if self.challenge is None:
            return False
        m = self.cfg.pow_mode
        if m == "on":
            return True
        if m == "auto":
            return time.monotonic() < self._under_attack_until
        return False

    async def _attack_monitor_loop(self) -> None:
        """Auto-engage PoW when the block RATE spikes. Keyed on blocks (not raw
        request volume) so organic traffic bursts don't trip challenges — only
        genuine attack behaviour (rate-limit/ban/burst/scraper blocks) does."""

        def total_blocks() -> int:
            return (_METRICS.rate_blocked + _METRICS.burst_window_blocks
                    + _METRICS.global_blocks + _METRICS.scraper_blocks
                    + _METRICS.bans + _METRICS.blocked)

        # Seed a zero baseline at t0 so a spike that lands *before* the first
        # sampling tick is still measured as growth from zero (else the first
        # sample already contains the spike and delta is stuck at ~0).
        samples: deque = deque([(time.monotonic(), total_blocks())], maxlen=128)
        prev_engaged = False
        while self._shutdown_event and not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=2.0)
                break
            except asyncio.TimeoutError:
                pass
            now = time.monotonic()
            cur = total_blocks()
            window = self.cfg.auto_pow_window
            # Baseline = oldest PAST sample still inside the window (computed
            # before appending the current sample).
            base = cur
            for t, v in samples:
                if now - t <= window:
                    base = v
                    break
            delta = cur - base
            samples.append((now, cur))
            if delta >= self.cfg.auto_pow_blocks:
                self._under_attack_until = now + self.cfg.auto_pow_cooldown
            engaged = now < self._under_attack_until
            _METRICS.under_attack = 1 if engaged else 0
            if engaged and not prev_engaged:
                _METRICS.under_attack_engaged += 1
                if logger is not None:
                    logger.warning("UNDER ATTACK — PoW challenge engaged "
                                   "(%d blocks / %.0fs)", delta, window)
                if audit_logger is not None:
                    audit_logger.warning("UNDER_ATTACK_ON blocks=%d window=%.0f",
                                         delta, window)
            elif prev_engaged and not engaged:
                if logger is not None:
                    logger.info("Attack subsided — PoW challenge disengaged")
            prev_engaged = engaged

    # ---- helpers ---- #
    @staticmethod
    def _err(request, status, text: str = "", retry_after: Optional[float] = None,
             extra_headers: Optional[Dict[str, str]] = None) -> web.Response:
        h = dict(BLOCK_HEADERS)
        h["X-Request-ID"] = request.get("request_id", "")
        if extra_headers:
            h.update(extra_headers)
        if retry_after is not None:
            h["Retry-After"] = str(max(1, int(retry_after)))
        return web.Response(status=status, text=text, headers=h)

    @staticmethod
    def _safe_abort(transport) -> None:
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
    def _split_host_port(host_str: str) -> Tuple[str, str]:
        """Parse `Host` header into (hostname, port_str).

        Handles:
          - 'example.com'      -> ('example.com', '')
          - 'example.com:443'  -> ('example.com', '443')
          - '127.0.0.1:9999'   -> ('127.0.0.1', '9999')
          - '[::1]:9999'       -> ('::1', '9999')
          - '[::1]'            -> ('::1', '')
          - '::1'              -> ('::1', '')  (no port in unbracketed IPv6)

        Fixes false-positive 400 when legit clients send `Host: ip:port`
        and listen_host is set to the bare IP — v29 compared the entire
        header, so `Host: 127.0.0.1:9999` failed equality vs `127.0.0.1`.
        """
        if not host_str:
            return ("", "")
        if host_str.startswith("["):
            idx = host_str.find("]")
            if idx != -1:
                h = host_str[1:idx]
                p = host_str[idx + 2:] if (
                    len(host_str) > idx + 1 and host_str[idx + 1] == ":"
                ) else ""
                return (h, p)
            return (host_str[1:], "")
        if host_str.count(":") == 1:
            h, p = host_str.split(":", 1)
            return (h, p)
        return (host_str, "")

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

        # FIX-10: only honour Cf-Connecting-Ip when remote is a Cloudflare IP.
        if SentinelApp._ip_matches(normalized, CFG.cloudflare_proxies):
            cf = request.headers.getall("Cf-Connecting-Ip", [])
            for v in cf:
                cand = SentinelApp._normalize_ip(v.strip())
                try:
                    ipaddress.ip_address(cand)
                    return cand
                except ValueError:
                    continue

        if not SentinelApp._ip_matches(normalized, CFG.trusted_proxies):
            return normalized

        candidates: List[str] = []
        for fwd in request.headers.getall("X-Forwarded-For", []):
            for p in (x.strip().split("%")[0] for x in fwd.split(",")):
                if p:
                    candidates.append(SentinelApp._normalize_ip(p))
        for ip in reversed(candidates[-XFF_MAX_IPS:]):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not SentinelApp._ip_matches(ip, CFG.trusted_proxies):
                return ip
        return normalized

    @staticmethod
    def filter_request_headers(headers) -> None:
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
    def filter_response_headers(headers) -> None:
        drop = {"transfer-encoding", "connection", "keep-alive",
                "proxy-authenticate", "proxy-authorization", "te",
                "trailers", "trailer", "upgrade",
                "server", "x-powered-by"}
        for v in headers.getall("Connection", []):
            for d in v.split(","):
                drop.add(d.strip().lower())
        for k in list(headers.keys()):
            if k.lower() in drop:
                del headers[k]

    @staticmethod
    def _is_text_content(content_type: Optional[str]) -> bool:
        if not content_type:
            return False
        ct = content_type.lower().split(";")[0].strip()
        if ct.startswith("text/"):
            return True
        return ct in ("application/json", "application/xml",
                      "application/x-www-form-urlencoded",
                      "application/javascript", "application/x-json")

    @staticmethod
    def _is_valid_transfer_encoding(headers) -> bool:
        te = headers.getall("Transfer-Encoding", [])
        if len(te) > 1:
            return False
        if not te:
            return True
        toks = [t.strip().lower() for t in te[0].split(",") if t.strip()]
        return len(toks) == 1 and toks[0] == "chunked"

    def _classify_ip(self, ip_str: str) -> str:
        cached = self.ip_class_cache.get(ip_str)
        if cached is not None:
            return cached
        cls = self._direct_classify(ip_str)
        self.ip_class_cache.set(ip_str, cls)
        return cls

    def _direct_classify(self, ip_str: str) -> str:
        cfg = self.cfg
        if SentinelApp._ip_matches(ip_str, cfg.blacklist_ips):
            return "blacklist"
        if SentinelApp._ip_matches(ip_str, cfg.whitelist_ips):
            return "whitelist"
        return "normal"

    async def _blackhole(self, request, ip: str, reason: str = "Banned") -> web.Response:
        _METRICS.blocked += 1
        remote = request.remote or "0.0.0.0"
        is_trusted = self._ip_matches(self._normalize_ip(remote), self.cfg.trusted_proxies)
        if logger is not None:
            logger.info("BLACKHOLE ip=%s reason=%s trusted=%s",
                       ip, reason, is_trusted,
                       extra={"request_id": request.get("request_id", ""),
                              "ip": ip, "reason": reason})
        if not is_trusted:
            self._safe_abort(request.transport)
            return web.Response(status=444, body=b"")
        return self._err(request, 403, f"Denied ({reason})")

    # ===== Pipeline steps ===== #
    async def _step_basic_request_sanity(self, request, ctx: _Ctx) -> Optional[web.Response]:
        try:
            ver = request.version
            if (ver.major, ver.minor) not in ALLOWED_HTTP_VERSIONS:
                return self._err(request, 400, "Bad HTTP version")
        except (AttributeError, KeyError):
            pass

        host_hdr = request.headers.get("Host", "")
        if not host_hdr or len(host_hdr) > 256 or len(host_hdr) < 3 \
                or any(c in host_hdr for c in " \t\r\n"):
            return self._err(request, 400, "Invalid Host header")
        host_lc = host_hdr.lower()
        # FIX-HOST: compare only the hostname portion of the Host header.
        # Real clients always send `Host: domain:port`. v29 did a literal
        # string equality check so `Host: 127.0.0.1:9999` was rejected vs
        # listen_host `127.0.0.1`. Now we strip the port + IPv6 brackets.
        host_no_port, _port = self._split_host_port(host_lc)
        listen_lc = (self.cfg.listen_host or "").lower()
        listen_stripped = listen_lc.strip("[]") if listen_lc else ""
        if self.cfg.allowed_hosts:
            if not any(host_no_port == h or host_no_port.endswith("." + h)
                       for h in self.cfg.allowed_hosts):
                return self._err(request, 400, "Host not allowed")
        elif listen_lc not in ("0.0.0.0", "::"):
            if host_no_port not in (listen_lc, listen_stripped,
                                     "localhost", "127.0.0.1", "::1", "[::1]"):
                return self._err(request, 400, "Invalid Host header")
        return None

    async def _step_te_cl_smuggling(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if not self._is_valid_transfer_encoding(request.headers):
            return self._err(request, 400, "Bad Transfer-Encoding")
        if request.headers.get("Transfer-Encoding") and request.headers.get("Content-Length"):
            return self._err(request, 400, "TE + CL conflict")
        cl = request.headers.getall("Content-Length", [])
        if len(cl) > 1:
            return self._err(request, 400, "Multiple Content-Length")
        if cl:
            try:
                v = int(cl[0])
                if v < 0:
                    return self._err(request, 400, "Invalid Content-Length")
                if v > self.cfg.max_body_size:
                    return self._err(request, 413, "Request Entity Too Large")
            except (ValueError, TypeError):
                return self._err(request, 400, "Invalid Content-Length")
        return None

    async def _step_header_uri_caps(self, request, ctx: _Ctx) -> Optional[web.Response]:
        try:
            total = sum(len(k) + len(v) + 2 for k, v in request.headers.items())
        except Exception:
            total = 0
        if total > self.cfg.max_total_headers_size:
            return self._err(request, 431, "Headers too large")
        if len(request.path_qs or "") > self.cfg.max_uri_size:
            return self._err(request, 414, "URI Too Long")
        if len(request.headers) > self.cfg.max_headers:
            return self._err(request, 431, "Too Many Headers")
        for k, v in request.headers.items():
            if len(k) > 256 or len(v) > self.cfg.max_header_size:
                return self._err(request, 431, "Header Too Large")
            if "\x00" in k or "\n" in k or "\r" in k:
                return self._err(request, 400, "Bad header name")
            if "\x00" in v or "\n" in v or "\r" in v:
                return self._err(request, 400, "Bad header value")
        if "\x00" in (request.path or "") or "\x00" in (request.query_string or ""):
            return self._err(request, 400, "Bad Request")
        return None

    async def _step_method(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if request.method.upper() not in self.cfg.allowed_methods:
            if audit_logger is not None:
                audit_logger.warning("METHOD_BLOCKED %s %s", ctx.ip, request.method,
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            return self._err(request, 405, "Method Not Allowed")
        return None

    async def _step_built_in_endpoints(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if self.challenge is not None and request.path == POW_VERIFY_PATH:
            return await self._handle_pow_verify(request, ctx)

        if request.path == "/health":
            return await self._handle_health(request, ctx)

        if request.path == "/metrics":
            if self.cfg.metrics_token:
                tok = request.query.get("token", "")
                if not (tok and hmac_compare(tok, self.cfg.metrics_token)):
                    return self._err(request, 403, "Forbidden")
            elif request.remote and not self._ip_matches(
                self._normalize_ip(request.remote or "0.0.0.0"),
                self.cfg.trusted_proxies,
            ):
                return self._err(request, 403, "Forbidden")
            fmt = request.query.get("format", "json").lower()
            if fmt == "prom":
                return web.Response(text=self._metrics_text(),
                                    content_type="text/plain; version=0.0.4")
            return web.Response(text=json.dumps(self._metrics_dict()),
                                content_type="application/json")

        return None

    async def _handle_health(self, request, ctx: _Ctx) -> web.Response:
        health_key = f"health:{ctx.ip}"
        cnt = self.per_ip_endpoint_cache.get(health_key) or 0
        if cnt > HEALTH_CHECK_LIMIT:
            return self._err(request, 429, "Too Many Health Checks", retry_after=60)
        self.per_ip_endpoint_cache.set(health_key, cnt + 1, keep_ttl=True)
        return web.Response(
            text="OK" if self._backend_healthy else "DEGRADED",
            status=200 if self._backend_healthy else 503,
        )

    async def _handle_pow_verify(self, request, ctx: _Ctx) -> web.Response:
        """Accept a PoW solution and, if valid, mint a clearance cookie. This
        endpoint runs before the rate limiter (it must work while under
        attack), so it carries its own cheap per-IP cap. Verification is a
        single HMAC + single SHA-256 — O(1) and impossible to amplify."""
        cm = self.challenge
        vkey = f"powv:{ctx.ip}"
        cnt = self.per_ip_endpoint_cache.get(vkey) or 0
        if cnt > self.cfg.pow_verify_limit:
            return self._err(request, 429, "Too Many Attempts", retry_after=30)
        self.per_ip_endpoint_cache.set(vkey, cnt + 1, keep_ttl=True)

        challenge = sig = nonce = None
        try:
            ctype = request.content_type or ""
            if "application/json" in ctype:
                data = await asyncio.wait_for(request.json(), timeout=2.0)
                if isinstance(data, dict):
                    challenge, sig, nonce = (data.get("challenge"),
                                             data.get("sig"), data.get("nonce"))
            elif request.method == "POST":
                data = await asyncio.wait_for(request.post(), timeout=2.0)
                challenge, sig, nonce = (data.get("challenge"),
                                         data.get("sig"), data.get("nonce"))
        except Exception:
            pass
        if challenge is None:
            challenge = request.query.get("challenge")
            sig = request.query.get("sig")
            nonce = request.query.get("nonce")

        prefix = self.rate_limiter._prefix_key(ctx.ip)
        if cm.verify_solution(str(challenge or ""), str(sig or ""),
                              str(nonce or ""), prefix):
            _METRICS.pow_solved += 1
            _METRICS.clearance_granted += 1
            token = cm.issue_clearance(prefix)
            headers = {"Cache-Control": "no-store", "Connection": "close",
                       "X-Request-ID": ctx.rid,
                       "Set-Cookie": cm.cookie_header(token)}
            return web.Response(status=200, text='{"status":"ok"}',
                                content_type="application/json", headers=headers)
        _METRICS.pow_failed += 1
        return self._err(request, 403, '{"status":"failed"}')

    async def _step_outbound_queue(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if not await _try_acquire_async(OUTBOUND_REQ_SEM):  # FIX-A
            _METRICS.blocked += 1
            return self._err(request, 503, "Proxy Outbound Queue Full", retry_after=10)
        # FIX-15: stash on ctx, _run_pipeline releases in finally on every path.
        ctx.outbound_sem = OUTBOUND_REQ_SEM
        return None

    async def _step_global_ip_cap(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if ctx.ip_class == "whitelist":
            return None
        gkey = f"glob:{ctx.ip}"
        gcnt = self.global_per_ip_cache.get(gkey) or 0
        if gcnt > self.cfg.global_per_ip_limit:
            _METRICS.global_blocks += 1
            await self.rate_limiter.force_ban(ctx.ip, self.cfg.ban_max, ctx.rid)
            if audit_logger is not None:
                audit_logger.warning("GLOBAL_LIMIT_BAN %s", ctx.ip,
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            return await self._blackhole(request, ctx.ip, "Global IP Limit Exceeded")
        self.global_per_ip_cache.set(gkey, gcnt + 1, keep_ttl=True)
        return None

    async def _step_unique_query_scrape(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if ctx.ip_class == "whitelist" or not request.query_string:
            return None
        uq_key = f"uq:{ctx.ip}"
        seen: Set[int] = self.unique_query_cache.get(uq_key)
        if seen is None:
            seen = set()
            self.unique_query_cache.set(uq_key, seen)
        # FIX-08: 64-bit blake2b hash, not raw query string. RAM cap = O(seen).
        sig = int(hashlib.blake2b(request.query_string.encode("utf-8", "ignore"),
                                   digest_size=8).hexdigest(), 16)
        seen.add(sig)
        if len(seen) > self.cfg.unique_query_hard_limit:
            _METRICS.scraper_blocks += 1
            await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
            if audit_logger is not None:
                audit_logger.warning("SCRAPER_HARD_LIMIT %s queries=%d",
                                     ctx.ip, len(seen),
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            seen.clear()
            return await self._blackhole(request, ctx.ip, "Scraper Hard Limit")
        if len(seen) > self.cfg.unique_query_threshold:
            _METRICS.scraper_blocks += 1
            await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
            if audit_logger is not None:
                audit_logger.warning("SCRAPER_PATTERN %s unique=%d",
                                     ctx.ip, len(seen),
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            seen.clear()
            return await self._blackhole(request, ctx.ip, "Scraper Pattern")
        return None

    async def _step_endpoint_cap(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if ctx.ip_class == "whitelist":
            return None
        endpoint_hash = hash(request.path) & 0xFFFFFFFF
        endpoint_key = f"{ctx.ip}:{request.method}:{endpoint_hash}"
        ecnt = self.per_ip_endpoint_cache.get(endpoint_key) or 0
        if ecnt > self.cfg.per_ip_endpoint_limit:
            return await self._blackhole(request, ctx.ip, "Endpoint Spam")
        self.per_ip_endpoint_cache.set(endpoint_key, ecnt + 1, keep_ttl=True)
        return None

    async def _step_ip_classify_and_ban_check(self, request, ctx: _Ctx) -> Optional[web.Response]:
        try:
            ip_obj_cache = self.ip_obj_cache.get(ctx.ip)
            if ip_obj_cache is None:
                ip_obj_cache = ipaddress.ip_address(ctx.ip)
                self.ip_obj_cache.set(ctx.ip, ip_obj_cache)
        except ValueError:
            return self._err(request, 400, "Invalid IP")
        if ctx.ip_class == "blacklist":
            if audit_logger is not None:
                audit_logger.warning("BLACKLIST_HIT %s %s", ctx.ip, request.path,
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            return await self._blackhole(request, ctx.ip, "Blacklisted")
        return None

    async def _step_rate_limit(self, request, ctx: _Ctx) -> Optional[web.Response]:
        allowed, _, reason = await self.rate_limiter.check_and_acquire(ctx.ip, ctx.ip_class)
        if allowed:
            return None

        rr_extra: Dict[str, str] = {}
        ban_remaining = self.rate_limiter.ban_status(ctx.ip)
        if ban_remaining is not None:
            rr_extra["X-RateLimit-Remaining"] = "0"
            rr_extra["X-RateLimit-Reset"] = str(max(1, int(ban_remaining - time.monotonic())))

        if reason == "banned":
            return await self._blackhole(request, ctx.ip, "Banned")
        if reason == "too_many_connections":
            return self._err(request, 429, "Too many connections",
                             retry_after=5, extra_headers=rr_extra)
        if reason == "burst_window":
            return await self._blackhole(request, ctx.ip, "Burst Flood")
        if reason in ("global_rate_limited", "system_overloaded"):
            return self._err(request, 503, "Service Overloaded",
                             retry_after=10, extra_headers=rr_extra)
        return self._err(request, 429, "Too Many Requests",
                         retry_after=5, extra_headers=rr_extra)

    @staticmethod
    def _scan_request_headers(request) -> Optional[str]:
        """Bounded, low-false-positive scan of header VALUES for header-borne
        injection (Log4Shell/JNDI, SSRF, traversal, XXE). Skips opaque/secret
        headers and caps total bytes examined to keep it O(1) per request."""
        budget = HEADER_WAF_SCAN_BUDGET
        for name, val in request.headers.items():
            if not val:
                continue
            nl = name.lower()
            if nl in ("cookie", "authorization", "proxy-authorization",
                      "x-request-id", "if-none-match", "if-match", "etag"):
                continue
            seg = val[:HEADER_WAF_VALUE_CAP]
            res = waf_check_headers_text(seg)
            if res:
                return res
            budget -= len(seg)
            if budget <= 0:
                break
        return None

    async def _step_waf_filter(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if not self.cfg.enable_waf:
            ctx.body_chunk = None
            return None

        # UA + method-level checks
        ua = request.headers.get("User-Agent", "") or ""
        if not ua:
            if (self.rate_limiter.is_new_ip(ctx.ip)
                    and not request.headers.get("Accept")
                    and request.method not in ("GET", "HEAD", "OPTIONS")):
                return self._err(request, 403, "Empty User-Agent")
        else:
            ua_low = ua.lower()
            # FIX-04: word-boundary regex (no substring leak)
            if self.cfg.bad_ua_regex.search(ua_low):
                if audit_logger is not None:
                    audit_logger.warning("UA_BLOCKED %s ua=%r", ctx.ip, ua[:128],
                                         extra={"request_id": ctx.rid, "ip": ctx.ip,
                                                "method": request.method,
                                                "path": (request.path_qs or "")[:512]})
                return self._err(request, 403, "Forbidden")

        # Header WAF (v30) — Log4Shell/JNDI, SSRF and traversal payloads
        # frequently arrive via headers (User-Agent, Referer, X-Api-Version,
        # X-Forwarded-For, …), which v29 never inspected. Bounded, synchronous,
        # low-false-positive (no SQLi/XSS rules on header values).
        hdr_hit = self._scan_request_headers(request)
        if hdr_hit:
            _METRICS.waf_hits += 1
            if audit_logger is not None:
                audit_logger.warning("WAF_HIT_HEADER %s %s %s", ctx.ip, hdr_hit, request.path,
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
            return self._err(request, 403, "WAF Blocked")

        # Path + query WAF
        combined = f"{request.path or ''}\x00{request.query_string or ''}"[:WAF_INSPECT_SIZE]
        waf_res = await async_waf_check(combined, self.waf_executor,
                                         WAF_SEM if WAF_SEM else None, self.cfg)
        if waf_res in ("WAF_OVERLOAD", "WAF_TIMEOUT", "ERROR"):
            # FIX-01: NEVER ban a legitimate user because WAF infra failed.
            # An attacker must not be able to nuke the ban-list by overloading
            # the WAF. We shed traffic with 503/400 instead.
            if logger is not None:
                logger.warning("WAF_INFRA_ERROR %s %s", ctx.ip, waf_res,
                               extra={"request_id": ctx.rid, "ip": ctx.ip})
            retry = 30 if waf_res == "WAF_TIMEOUT" else 5
            return self._err(request, 503 if waf_res == "WAF_OVERLOAD" else 400,
                             "Service Overloaded" if waf_res == "WAF_OVERLOAD" else "WAF Error",
                             retry_after=retry)
        if waf_res in WAF_ATTACK_LABELS:
            _METRICS.waf_hits += 1
            if audit_logger is not None:
                audit_logger.warning("WAF_HIT %s %s %s", ctx.ip, waf_res, request.path,
                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                            "method": request.method,
                                            "path": (request.path_qs or "")[:512]})
            await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
            return self._err(request, 403, "WAF Blocked")

        # Body WAF — single try/finally releases WAF_SEM exactly once.
        body_chunk: Optional[bytes] = None
        if request.can_read_body and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if self._is_text_content(request.content_type):
                if WAF_SEM is not None and not await _try_acquire_async(WAF_SEM):  # FIX-A
                    _METRICS.waf_overloads += 1
                    if logger is not None:
                        logger.warning("WAF queue full – shedding %s", ctx.ip)
                    return await self._blackhole(request, ctx.ip, "WAF Overloaded")
                try:
                    try:
                        body_chunk = await asyncio.wait_for(
                            request.content.read(WAF_INSPECT_SIZE),
                            timeout=self.cfg.waf_body_timeout,
                        )
                    except web.HTTPRequestEntityTooLarge:
                        return self._err(request, 413, "Payload Too Large")
                    except (asyncio.TimeoutError, TimeoutError):
                        _METRICS.waf_overloads += 1
                        return await self._blackhole(request, ctx.ip, "Body Read Timeout")
                    except (ClientPayloadError, ClientDisconnectedError,
                            asyncio.IncompleteReadError, ConnectionResetError) as e:
                        if logger is not None:
                            logger.debug("Client disconnect during body read: %s", e)
                        return await self._blackhole(request, ctx.ip, "Client disconnect")
                    except Exception as e:
                        if logger is not None:
                            logger.error("Body read error: %s", e)
                        return self._err(request, 400, "Bad Request: body read")

                    if body_chunk:
                        try:
                            text = body_chunk[:WAF_INSPECT_SIZE].decode("utf-8", "ignore")
                        except Exception:
                            text = ""
                        # pass None so async_waf_check does not re-acquire WAF_SEM
                        waf_res = await async_waf_check(text, self.waf_executor, None, self.cfg)
                        if waf_res in ("WAF_OVERLOAD", "WAF_TIMEOUT", "ERROR"):
                            if logger is not None:
                                logger.warning("WAF_BODY_INFRA_ERROR %s %s",
                                               ctx.ip, waf_res,
                                               extra={"request_id": ctx.rid, "ip": ctx.ip})
                            return self._err(
                                request,
                                503 if waf_res == "WAF_OVERLOAD" else 400,
                                "Service Overloaded" if waf_res == "WAF_OVERLOAD" else "WAF Error",
                                retry_after=5,
                            )
                        if waf_res in WAF_ATTACK_LABELS:
                            _METRICS.waf_hits += 1
                            if audit_logger is not None:
                                audit_logger.warning("WAF_HIT_BODY %s %s %s",
                                                     ctx.ip, waf_res, request.path,
                                                     extra={"request_id": ctx.rid, "ip": ctx.ip,
                                                            "method": request.method,
                                                            "path": (request.path_qs or "")[:512]})
                            await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
                            return self._err(request, 403, "WAF Blocked")
                        if request.content_type and "application/json" in request.content_type:
                            loop = asyncio.get_running_loop()
                            pre = await loop.run_in_executor(
                                self.waf_executor, _json_preflight, text)
                            if pre:
                                _METRICS.waf_hits += 1
                                if audit_logger is not None:
                                    audit_logger.warning("WAF_HIT_JSON_PREFLIGHT %s %s",
                                                         ctx.ip, pre,
                                                         extra={"request_id": ctx.rid, "ip": ctx.ip,
                                                                "method": request.method,
                                                                "path": (request.path_qs or "")[:512]})
                                return self._err(request, 413, f"{pre} — payload rejected")
                            try:
                                json_res = await asyncio.wait_for(
                                    loop.run_in_executor(self.waf_executor,
                                                         _json_parse_and_scan, text),
                                    timeout=self.cfg.waf_regex_timeout,
                                )
                            except asyncio.TimeoutError:
                                return self._err(request, 413, "JSON too large")
                            if json_res in WAF_JSON_LABELS:
                                _METRICS.waf_hits += 1
                                if audit_logger is not None:
                                    audit_logger.warning("WAF_HIT_JSON %s %s %s",
                                                         ctx.ip, json_res, request.path,
                                                         extra={"request_id": ctx.rid, "ip": ctx.ip,
                                                                "method": request.method,
                                                                "path": (request.path_qs or "")[:512]})
                                await self.rate_limiter.force_ban(ctx.ip, request_id=ctx.rid)
                                return self._err(request, 403, "WAF Blocked JSON")
                finally:
                    # FIX-14: release WAF_SEM EXACTLY once on every exit path.
                    if WAF_SEM is not None:
                        try:
                            WAF_SEM.release()
                        except (ValueError, AssertionError):
                            pass

        ctx.body_chunk = body_chunk
        return None

    async def _step_backend_shed(self, request, ctx: _Ctx) -> Optional[web.Response]:
        if self.cfg.health_check_enabled and not self._backend_healthy:
            _METRICS.blocked += 1
            return self._err(request, 503, "Backend Unavailable", retry_after=15)
        return None

    async def _step_forward(self, request, ctx: _Ctx) -> web.Response:
        sem = self._per_ip_outbound_ensure(ctx.ip)  # FIX-17: no lock
        if not await _try_acquire_async(sem):  # FIX-A
            _METRICS.blocked += 1
            return self._err(request, 503, "Too many concurrent requests from this IP",
                             retry_after=5)
        try:
            return await self._forward(request, ctx)
        finally:
            try:
                sem.release()
            except (ValueError, AssertionError):
                pass

    def _per_ip_outbound_ensure(self, ip: str) -> "asyncio.Semaphore":
        """FIX-17: dict ops under GIL are atomic. Race-replaced creation is
        benign — second Sem is discarded by LRU. No asyncio.Lock needed."""
        sem = self._per_ip_outbound_cache.get(ip)
        if sem is None:
            sem = asyncio.Semaphore(self.cfg.per_ip_backend_limit)
            self._per_ip_outbound_cache.set(ip, sem)
        return sem

    # ---- main handler ---- #
    async def handler(self, request) -> web.Response:
        _METRICS.requests += 1
        request["request_id"] = str(uuid.uuid4())
        ip = self.get_real_ip(request)
        ip_class = self._classify_ip(ip)
        ctx = _Ctx(ip=ip, ip_class=ip_class, rid=request["request_id"],
                   started=time.monotonic(), body_chunk=None, outbound_sem=None)

        if self._shutdown_event is not None and self._shutdown_event.is_set():
            self._safe_abort(request.transport)
            return web.Response(status=503, body=b"")

        if not await _try_acquire_async(INBOUND_CONN_SEM):  # FIX-A
            self._safe_abort(request.transport)
            _METRICS.blocked += 1
            return web.Response(status=444, body=b"")
        self._active_inbound += 1

        try:
            return await self._run_pipeline(request, ctx)
        except asyncio.CancelledError:
            raise
        except web.HTTPException:
            raise
        except Exception as e:
            if logger is not None:
                logger.critical("Unhandled error: %s", e, exc_info=True)
            # FIX (v30): once streaming has begun we cannot substitute a
            # fresh Response (the status line + headers are already on the
            # wire). Tear the socket down instead of raising a confusing
            # "prepare twice" error.
            if ctx.response_started:
                self._safe_abort(request.transport)
                raise
            return await self._blackhole(request, ip, "Internal Error")
        finally:
            self._active_inbound -= 1
            try:
                INBOUND_CONN_SEM.release()
            except (ValueError, AssertionError):
                pass
            if self.rate_limiter is not None:
                try:
                    await self.rate_limiter.dec_conn(ip)
                except Exception:
                    pass

    # Analysis steps run under a bounded timeout (slowloris defence). The
    # forward/stream step is deliberately NOT in this list — it runs after,
    # governed by per-chunk idle timeouts, so large legit downloads complete.
    _ANALYSIS_STEP_NAMES = (
        "_step_built_in_endpoints",
        "_step_basic_request_sanity",
        "_step_method",
        "_step_te_cl_smuggling",
        "_step_header_uri_caps",
        "_step_outbound_queue",
        "_step_global_ip_cap",
        "_step_unique_query_scrape",
        "_step_endpoint_cap",
        "_step_ip_classify_and_ban_check",
        "_step_rate_limit",
        "_step_challenge",       # v30 proof-of-work (no-op unless enabled)
        "_step_waf_filter",
        "_step_backend_shed",
    )

    async def _run_pipeline(self, request, ctx: _Ctx) -> web.Response:
        steps = [getattr(self, n) for n in self._ANALYSIS_STEP_NAMES]
        try:
            # Phase 1 — analysis, bounded by analysis_timeout.
            try:
                resp = await asyncio.wait_for(
                    self._run_analysis(request, ctx, steps),
                    timeout=self.cfg.analysis_timeout,
                )
            except asyncio.TimeoutError:
                _METRICS.slow_aborts += 1
                return await self._blackhole(request, ctx.ip, "Slowloris/Timeout")

            if resp is not None:
                self._augment_rl_headers(resp, ctx)
                return resp

            # Phase 2 — forward + stream (idle-timeout governed, no total cap).
            return await self._step_forward(request, ctx)
        finally:
            # FIX-15: release OUTBOUND_REQ_SEM EXACTLY once on EVERY exit path.
            if ctx.outbound_sem is not None:
                try:
                    ctx.outbound_sem.release()
                except (ValueError, AssertionError):
                    pass
                ctx.outbound_sem = None

    async def _run_analysis(self, request, ctx: _Ctx, steps) -> Optional[web.Response]:
        for step in steps:
            try:
                resp = await step(request, ctx)
            except web.HTTPException:
                raise
            except Exception as e:
                if logger is not None:
                    logger.critical("Pipeline step %s failed: %s",
                                    step.__name__, e, exc_info=True)
                return await self._blackhole(request, ctx.ip, "Internal Error")
            if resp is not None:
                return resp
        return None

    def _augment_rl_headers(self, resp, ctx: _Ctx) -> None:
        if ctx.ip_class == "whitelist":
            return
        try:
            rl_headers = {
                "X-RateLimit-Limit": str(int(self.cfg.rate_limit * self.cfg.burst_limit)),
            }
            ban_remaining = self.rate_limiter.ban_status(ctx.ip) if self.rate_limiter else None
            if ban_remaining is not None:
                rl_headers["X-RateLimit-Remaining"] = "0"
                rl_headers["X-RateLimit-Reset"] = str(
                    max(1, int(ban_remaining - time.monotonic())))
            resp.headers.update(rl_headers)
        except Exception:
            pass

    async def _step_challenge(self, request, ctx: _Ctx) -> Optional[web.Response]:
        """Proof-of-work gate (v30). Only top-level browser navigations
        (GET/HEAD with `Accept: text/html`) without a valid clearance cookie
        are served the interstitial — API/XHR/asset traffic is untouched and
        still faces every other defence. Whitelisted IPs always bypass."""
        cm = self.challenge
        if cm is None or not self._challenge_active():
            return None
        if ctx.ip_class == "whitelist":
            return None
        if request.method not in ("GET", "HEAD"):
            return None
        if "text/html" not in (request.headers.get("Accept", "") or ""):
            return None

        prefix = self.rate_limiter._prefix_key(ctx.ip)
        token = request.cookies.get(cm.cookie_name, "")
        if token and cm.verify_clearance(token, prefix):
            return None

        _METRICS.pow_challenges += 1
        if audit_logger is not None:
            audit_logger.warning("POW_CHALLENGE %s %s", ctx.ip, request.path,
                                 extra={"request_id": ctx.rid, "ip": ctx.ip,
                                        "method": request.method,
                                        "path": (request.path_qs or "")[:512]})
        html = _challenge_html(cm.make_challenge(prefix))
        headers = dict(BLOCK_HEADERS)
        headers["X-Request-ID"] = ctx.rid
        headers["Retry-After"] = "3"
        return web.Response(status=503, text=html,
                            content_type="text/html", headers=headers)

    # ---- forward ---- #
    async def _forward(self, request, ctx: _Ctx) -> web.Response:
        url = urljoin(self.cfg.backend_url + "/", (request.path_qs or "").lstrip("/"))
        headers = request.headers.copy()
        headers["Host"] = self.backend_host
        self.filter_request_headers(headers)
        headers["X-Request-ID"] = ctx.rid

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
        try:
            headers["X-Forwarded-Proto"] = request.scheme or URL_SCHEME
        except AttributeError:
            headers["X-Forwarded-Proto"] = URL_SCHEME

        can_retry = request.method in ("GET", "HEAD")
        max_attempts = BACKEND_MAX_RETRIES + 1 if can_retry else 1
        has_body = request.method in ("POST", "PUT", "PATCH", "DELETE")

        last_exc: Optional[Exception] = None
        self._active_outbound += 1
        try:
            for attempt in range(max_attempts):
                if not await self.cb.allow():
                    if attempt == 0:
                        _METRICS.circuit_rejects += 1
                        return self._err(request, 503,
                                         "Service Unavailable (circuit open)", retry_after=30)
                    break
                data = self._make_body_stream(ctx.body_chunk, request) if has_body else None
                try:
                    async with self.session.request(
                        request.method, url, headers=headers, data=data,
                        allow_redirects=False, ssl=self.cfg.verify_ssl,
                    ) as resp:
                        if resp.status >= 500:
                            self.cb.record_error()
                            if logger is not None:
                                logger.warning("Backend %d for %s attempt=%d",
                                               resp.status, ctx.ip, attempt + 1)
                        else:
                            self.cb.record_success()

                        bheaders = resp.headers.copy()
                        self.filter_response_headers(bheaders)
                        if self.cfg.server_header:
                            bheaders["Server"] = self.cfg.server_header
                        bheaders["Connection"] = "close"

                        client_resp = web.StreamResponse(status=resp.status, headers=bheaders)
                        # From here the status line + headers are on the wire;
                        # we can no longer swap in a fresh error Response.
                        ctx.response_started = True
                        await client_resp.prepare(request)

                        # FIX (v30): stream with a per-chunk IDLE timeout, not a
                        # total-duration timeout. v29 wrapped the whole stream in
                        # `wait_for(timeout=backend_timeout)`, which truncated any
                        # legit download longer than that (throttle * size), then
                        # tried — and failed — to send a fresh response over an
                        # already-prepared stream. Now a stalled peer is cut but a
                        # steady large transfer completes.
                        idle = self.cfg.stream_idle_timeout
                        max_bps = self.cfg.resp_max_bps  # 0 = unthrottled
                        try:
                            tokens = float(max_bps)
                            last_refill = time.monotonic()
                            while True:
                                try:
                                    chunk = await asyncio.wait_for(
                                        resp.content.readany(), timeout=idle)
                                except asyncio.TimeoutError:
                                    if logger is not None:
                                        logger.debug("Backend stream idle timeout: %s", ctx.ip)
                                    self._safe_abort(request.transport)
                                    client_resp.force_close()
                                    return client_resp
                                if not chunk:
                                    break
                                if max_bps:
                                    cost = len(chunk)
                                    now = time.monotonic()
                                    tokens = min(float(max_bps),
                                                 tokens + (now - last_refill) * max_bps)
                                    last_refill = now
                                    if tokens < cost:
                                        await asyncio.sleep((cost - tokens) / max_bps)
                                        tokens = 0.0
                                    else:
                                        tokens -= cost
                                try:
                                    await asyncio.wait_for(
                                        client_resp.write(chunk), timeout=idle)
                                except (ConnectionResetError, BrokenPipeError,
                                        ConnectionAbortedError):
                                    return client_resp
                                except asyncio.TimeoutError:
                                    if logger is not None:
                                        logger.debug("Client write idle timeout: %s", ctx.ip)
                                    self._safe_abort(request.transport)
                                    client_resp.force_close()
                                    return client_resp
                            await client_resp.write_eof()
                        except (ConnectionResetError, ConnectionAbortedError,
                                BrokenPipeError, asyncio.IncompleteReadError,
                                ClientError) as e:
                            if logger is not None:
                                logger.debug("Client connection interrupted: %s (%s)",
                                             ctx.ip, e)
                            self._safe_abort(request.transport)
                            client_resp.force_close()
                            return client_resp
                        return client_resp
                except (ClientError, asyncio.TimeoutError, ConnectionError) as e:
                    last_exc = e
                    if attempt < max_attempts - 1:
                        if logger is not None:
                            logger.warning("Backend attempt %d failed for %s: %s",
                                           attempt + 1, ctx.ip, e)
                        await asyncio.sleep(0.1 * (attempt + 1))
                    else:
                        break

            self.cb.record_error()
            if isinstance(last_exc, asyncio.TimeoutError):
                if logger is not None:
                    logger.error("Backend timeout after %d attempts for %s",
                                max_attempts, ctx.ip)
                return self._err(request, 504, "Gateway Timeout", retry_after=30)
            if logger is not None:
                logger.error("Backend connection error after %d attempts for %s: %s",
                            max_attempts, ctx.ip, last_exc)
            return self._err(request, 502, "Bad Gateway", retry_after=30)
        finally:
            self._active_outbound -= 1

    @staticmethod
    def _make_body_stream(body_chunk, request):
        """FIX-B: `raise ConnectionError` on every error path (instead of
        v28's silent `return`). a silent return inside an async generator
        yields `StopAsyncIteration` which aiohttp interprets as a CLEAN
        end-of-stream — the backend happily parses the partial payload
        that the attacker/teaser client actually sent. We now `raise`
        after `transport.abort()` so:

          • aiohttp sees the broken stream and tears down the upstream request.
          • the `_forward` try/except catches `ConnectionError` ⇒ 502/504.
          • the attacker's partial payload is NEVER processed by the backend.

        Every error path also closes the inbound transport to release
        the client-side socket promptly."""
        async def _stream():
            total = 0
            if body_chunk:
                total = len(body_chunk)
                yield body_chunk
            start_time = time.monotonic()
            while True:
                if time.monotonic() - start_time > MAX_TOTAL_BODY_READ_SECONDS:
                    if logger is not None:
                        logger.warning("Body upload exceeded %ds — aborting",
                                       MAX_TOTAL_BODY_READ_SECONDS)
                    if request.transport is not None:
                        try:
                            request.transport.abort()
                        except Exception:
                            pass
                    raise ConnectionError("sentinel: body upload timed out")
                try:
                    chunk = await asyncio.wait_for(
                        request.content.read(STREAM_CHUNK_SIZE),
                        timeout=SLOW_REQUEST_TIMEOUT,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    if logger is not None:
                        logger.warning("Body chunk read timed out — aborting")
                    if request.transport is not None:
                        try:
                            request.transport.abort()
                        except Exception:
                            pass
                    raise ConnectionError("sentinel: body chunk timeout") from None
                except (ClientError, ConnectionError, asyncio.IncompleteReadError) as e:
                    if logger is not None:
                        logger.warning("Body chunk client error — aborting: %s", e)
                    if request.transport is not None:
                        try:
                            request.transport.abort()
                        except Exception:
                            pass
                    raise ConnectionError("sentinel: body chunk error") from None
                if not chunk:
                    break
                total += len(chunk)
                if total > CFG.max_body_size:
                    if logger is not None:
                        logger.warning("Body exceeded max_body_size (%d) — aborting", total)
                    if request.transport is not None:
                        try:
                            request.transport.abort()
                        except Exception:
                            pass
                    raise ConnectionError("sentinel: body too large") from None
                yield chunk
        return _stream()

    # ---- metrics exposition ---- #
    def _metrics_dict(self) -> Dict[str, int]:
        return {k: getattr(_METRICS, k) for k in (
            "requests", "blocked", "waf_hits", "waf_overloads", "waf_errors",
            "bans", "slow_aborts", "circuit_rejects", "rate_blocked",
            "burst_window_blocks", "scraper_blocks", "global_blocks",
            "log_drops", "audit_log_drops",
            "pow_challenges", "pow_solved", "pow_failed", "clearance_granted",
            "under_attack", "under_attack_engaged",
        )}

    def _metrics_text(self) -> str:
        return "\n".join(f"sentinel_{k} {v}" for k, v in self._metrics_dict().items()) + "\n"


# ====================================================================== #
# Helpers
# ====================================================================== #
URL_SCHEME = os.getenv("URL_SCHEME", "http")


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison.

    v29 hand-rolled the compare and early-returned on a length mismatch,
    which leaks the secret length via timing. v30 delegates to the stdlib
    `hmac.compare_digest`, which is constant-time over the shorter operand
    and does not branch on length."""
    if not a or not b:
        return False
    try:
        return hmac.compare_digest(a.encode("utf-8", "ignore"),
                                   b.encode("utf-8", "ignore"))
    except Exception:
        return False


# ====================================================================== #
# Module-level state (only set at startup, references to None are guarded)
# ====================================================================== #
INBOUND_CONN_SEM: Optional[asyncio.Semaphore] = None
WAF_SEM: Optional[asyncio.Semaphore] = None
OUTBOUND_REQ_SEM: Optional[asyncio.Semaphore] = None
logger: Optional[logging.Logger] = None
audit_logger: Optional[logging.Logger] = None
CFG: Optional[Config] = None


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


def _print_help() -> None:
    help_txt = f"""\
Sentinel Guard v{VERSION} — single-file anti-DDoS L7 reverse proxy

  --dry-run     validate config and exit
  --self-test   run the built-in unit suite and exit (0=pass)
  --help        this text

Environment variables (all optional):
  SENTINEL_HOST, SENTINEL_PORT   bind address (default 0.0.0.0:9999)
  BACKEND_URL                    backend upstream (default http://127.0.0.1:8888)
  RATE_LIMIT, BURST_LIMIT        per-IP token bucket (200/s, burst 400)
  MAX_CONN_IP                    concurrent conns per IP (default 30)
  MAX_BODY_SIZE                  bytes (default 1MB)
  BAN_BASE, BAN_MULT, BAN_MAX    ban scheduler (60s * 2^n, capped 1h)
  VIOLATIONS_DECAY               seconds before violations decay
  PER_IP_BURST_WINDOW, _LIMIT    rolling burst window (40 req / 10s default)
  TRUSTED_PROXIES, WHITELIST, BLACKLIST
                                 comma-separated CIDR lists
  CF_PROXIES                     Cloudflare egress CIDRs (defaults to public list)
  ALLOWED_METHODS                default: GET,POST,HEAD,PUT,DELETE,OPTIONS,PATCH
  ENABLE_WAF                     bool (1/0); scans path/query/body + headers
  BACKEND_HEALTH_CHECK, BACKEND_HEALTH_PATH
                                 optional backend health shedding
  WAF_BODY_TIMEOUT, WAF_REGEX_TIMEOUT
                                 WAF timeouts (default 5s, 0.5s)
  BAN_PERSIST_FILE, BAN_PERSIST_INTERVAL
                                 bans-on-disk (default sentinel_bans.json / 5min)
  METRICS_TOKEN                  if set, /metrics?token=... is required

  Streaming (v30):
  RESP_MAX_BPS                   per-response throttle, bytes/s (0=off, default 2MiB)
  STREAM_IDLE_TIMEOUT            max idle gap while streaming (default 15s)
  ANALYSIS_TIMEOUT               cap on the pre-forward analysis phase

  Proof-of-Work "I'm Under Attack" (v30):
  POW_MODE                       off | on | auto   (default auto)
  POW_BITS                       PoW difficulty in leading zero bits (default 18)
  POW_TTL, POW_CLEARANCE_TTL     challenge / clearance-cookie lifetimes (s)
  POW_SECRET                     shared HMAC key (REQUIRED for multi-instance)
  POW_COOKIE                     clearance cookie name (default __sentinel_clr)
  POW_VERIFY_LIMIT               per-IP verify attempts / min (default 60)
  AUTO_POW_BLOCKS                blocks within the window that engage auto mode
  AUTO_POW_WINDOW, AUTO_POW_COOLDOWN
                                 detection window / hold time (default 10s / 120s)
"""
    print(help_txt)


def _parse_args(argv):
    out: Dict[str, str] = {}
    dry_run = False
    self_test = False
    for arg in argv[1:]:
        if arg in ("--help", "-h"):
            _print_help()
            sys.exit(0)
        if arg == "--dry-run":
            dry_run = True
            continue
        if arg == "--self-test":
            self_test = True
            continue
        if arg.startswith("--config="):
            kv = arg[len("--config="):]
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k] = v
            continue
    return out, dry_run, self_test


def main() -> None:
    global CFG, logger, audit_logger
    overrides, dry_run, self_test = _parse_args(sys.argv)

    if self_test:
        sys.exit(_self_test())

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
        print(f"  waf            : enabled={CFG.enable_waf} regex_to={CFG.waf_regex_timeout}s")
        print(f"  pow            : mode={CFG.pow_mode} bits={CFG.pow_bits}")
        print(f"  fd_limit       : {MAX_SAFE_CONNS}")
        print(f"  platform       : {sys.platform} ({platform.release()})")
        sys.exit(0)

    logger, audit_logger, listener, audit_listener = setup_logging(CFG)

    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    app = create_app(CFG)

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
