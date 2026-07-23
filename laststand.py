#!/usr/bin/env python3
"""
protect.py - a single-file, dependency-free HTTP/1.1 L7 reverse proxy.

It listens on 0.0.0.0:9999 and forwards to 127.0.0.1:8888.  The proxy is
deliberately opinionated: it accepts every source address, does not implement
per-address quotas/rate limits, browser challenges, CAPTCHA, JavaScript, or a
referer check.  Instead it makes each accepted request cheap and unambiguous:

* strict request/response framing (CL/TE ambiguity is rejected);
* bounded headers, bodies, chunks, queues, and connection lifetimes;
* streaming uploads/downloads, including Ollama/SSE style responses;
* hop-by-hop header removal and a fixed upstream destination (no SSRF);
* an application-layer risk engine.  It blocks high-confidence scanners and
  malformed/ambiguous JSON, while merely observing low-confidence automation
  signals so normal curl/SDK clients continue to work.

There are intentionally no command-line or environment configuration knobs:
running ``python3 protect.py`` is sufficient.  Network/volumetric DDoS still
requires capacity and upstream/OS protection; an application process cannot
stop packets before they reach its socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import signal
import socket
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple
from collections import deque


# ---------------------------------------------------------------------------
# Fixed deployment policy.  These are deliberately constants rather than
# command-line/environment options, as requested.

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9999
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 80

# A global admission cap is a resource/backpressure guard, not an IP allowlist
# or a request-rate limiter.  Every source address is treated identically.
MAX_CLIENT_CONNECTIONS = 1024
MAX_UPSTREAM_CONNECTIONS = 256

MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 100
MAX_HEADER_LINE_BYTES = 8 * 1024
MAX_REQUEST_LINE_BYTES = 8 * 1024
MAX_TARGET_BYTES = 8 * 1024
MAX_HEADER_VALUE_BYTES = 8 * 1024
MAX_REQUEST_BODY = 64 * 1024 * 1024
MAX_RESPONSE_BODY = 512 * 1024 * 1024
MAX_TRAILER_BYTES = 16 * 1024
MAX_TRAILERS = 32

HEADER_READ_TIMEOUT = 5.0
BODY_IDLE_TIMEOUT = 15.0
BODY_TOTAL_TIMEOUT = 120.0
UPSTREAM_CONNECT_TIMEOUT = 4.0
UPSTREAM_QUEUE_TIMEOUT = 3.0
UPSTREAM_HEADER_TIMEOUT = 180.0
RESPONSE_IDLE_TIMEOUT = 180.0
RESPONSE_TOTAL_TIMEOUT = 2 * 60 * 60.0
CLIENT_WRITE_TIMEOUT = 20.0
UPSTREAM_WRITE_TIMEOUT = 20.0

READ_CHUNK = 64 * 1024
BODY_PREFETCH_BYTES = 64 * 1024
MAX_JSON_INSPECT_BYTES = 1 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000


# ---------------------------------------------------------------------------
# Errors and small protocol helpers


class ProxyError(Exception):
    """An error that can be reported to the client before a response starts."""

    def __init__(self, status: int, message: str, *, code: str = "bad_request"):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


class ClientClosed(Exception):
    pass


class UpstreamError(Exception):
    pass


class BodyError(ProxyError):
    pass


STATUS_REASONS = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    206: "Partial Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    414: "URI Too Long",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    417: "Expectation Failed",
    421: "Misdirected Request",
    422: "Unprocessable Content",
    426: "Upgrade Required",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
}

TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
SCANNER_UA_RE = re.compile(
    r"(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|"
    r" nessus|openvas|acunetix|burpsuite|zap(?:roxy)?|httpx|whatweb|"
    r" ffuf|havij|qualys|censys|expanse)",
    re.IGNORECASE,
)

HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
FORWARDED_INBOUND = {
    "forwarded",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-request-id",
}


def _contains_bad_ctl(value: bytes, *, allow_htab: bool = False) -> bool:
    for byte in value:
        if byte == 0x7F:
            return True
        if byte < 0x20 and not (allow_htab and byte == 0x09):
            return True
    return False


def _is_token_bytes(value: bytes) -> bool:
    """Validate a token without silently dropping non-ASCII bytes."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return False
    return bool(TOKEN_RE.fullmatch(text))


def _header_tokens(values: Sequence[str]) -> List[str]:
    result: List[str] = []
    for value in values:
        for token in value.split(","):
            token = token.strip(" \t").lower()
            if not token or not TOKEN_RE.fullmatch(token):
                raise ProxyError(400, "invalid connection header", code="invalid_header")
            result.append(token)
    return result


def _parse_content_length(values: Sequence[str], *, maximum: int = MAX_REQUEST_BODY) -> Optional[int]:
    if not values:
        return None
    parsed: List[int] = []
    for value in values:
        pieces = value.split(",")
        if not pieces:
            raise ProxyError(400, "invalid content length", code="invalid_framing")
        for piece in pieces:
            piece = piece.strip(" \t")
            if not piece or not piece.isdigit():
                raise ProxyError(400, "invalid content length", code="invalid_framing")
            # Avoid converting unbounded decimal strings on hostile input.
            if len(piece) > 20:
                if maximum == MAX_REQUEST_BODY:
                    raise ProxyError(413, "request body is too large", code="body_too_large")
                raise ProxyError(502, "upstream response is too large", code="upstream_too_large")
            number = int(piece, 10)
            if number > maximum:
                status = 413 if maximum == MAX_REQUEST_BODY else 502
                code = "body_too_large" if maximum == MAX_REQUEST_BODY else "upstream_too_large"
                raise ProxyError(status, "message body is too large", code=code)
            parsed.append(number)
    if len(set(parsed)) != 1:
        raise ProxyError(400, "conflicting content length", code="invalid_framing")
    return parsed[0]


def _parse_transfer_encoding(values: Sequence[str]) -> bool:
    if not values:
        return False
    tokens: List[str] = []
    for value in values:
        for piece in value.split(","):
            token = piece.strip(" \t").lower()
            if not token or ";" in token or not TOKEN_RE.fullmatch(token):
                raise ProxyError(400, "invalid transfer encoding", code="invalid_framing")
            tokens.append(token)
    # Only a final, sole chunked coding is accepted.  Decoding other codings
    # here would invite parser differentials with the application server.
    if tokens != ["chunked"]:
        raise ProxyError(400, "unsupported transfer encoding", code="invalid_framing")
    return True


def _safe_reason(reason: str, status: int) -> str:
    if not reason or len(reason) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in reason):
        return STATUS_REASONS.get(status, "Proxy Response")
    return reason


def _peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if peer:
        return str(peer)
    return "unknown"


async def _drain(writer: asyncio.StreamWriter, timeout: float) -> None:
    try:
        await asyncio.wait_for(writer.drain(), timeout)
    except (ConnectionError, BrokenPipeError, asyncio.IncompleteReadError) as exc:
        raise ClientClosed() from exc
    except asyncio.TimeoutError as exc:
        raise ClientClosed() from exc


async def _read_head(
    reader: asyncio.StreamReader,
    *,
    timeout: float,
    what: str,
) -> bytes:
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    except asyncio.LimitOverrunError as exc:
        raise ProxyError(431 if what == "request" else 502, f"{what} headers are too large", code="headers_too_large") from exc
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            raise ClientClosed() if what == "request" else UpstreamError("upstream closed")
        raise ProxyError(400 if what == "request" else 502, f"incomplete {what} headers", code="incomplete_headers") from exc
    except asyncio.TimeoutError as exc:
        raise ProxyError(408 if what == "request" else 504, f"{what} header timeout", code="header_timeout") from exc
    except (ConnectionError, BrokenPipeError) as exc:
        raise ClientClosed() if what == "request" else UpstreamError("upstream read failed") from exc
    if len(data) > MAX_HEADER_BYTES:
        raise ProxyError(431 if what == "request" else 502, f"{what} headers are too large", code="headers_too_large")
    return data


async def _read_crlf_line(
    reader: asyncio.StreamReader,
    *,
    timeout: float,
    max_bytes: int,
    what: str,
) -> bytes:
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
    except asyncio.LimitOverrunError as exc:
        raise BodyError(400 if what == "request" else 502, f"{what} line is too large", code="line_too_large") from exc
    except asyncio.IncompleteReadError as exc:
        raise BodyError(400 if what == "request" else 502, f"incomplete {what} line", code="incomplete_body") from exc
    except asyncio.TimeoutError as exc:
        raise BodyError(408 if what == "request" else 504, f"{what} body timeout", code="body_timeout") from exc
    if len(line) > max_bytes:
        raise BodyError(400 if what == "request" else 502, f"{what} line is too large", code="line_too_large")
    return line


# ---------------------------------------------------------------------------
# HTTP request/response parsing


@dataclass
class Request:
    method: str
    target: bytes
    version: str
    headers: List[Tuple[str, str]]
    header_map: Dict[str, List[str]]
    content_length: Optional[int]
    chunked: bool
    expect_continue: bool
    request_id: str

    @property
    def has_body(self) -> bool:
        return self.chunked or (self.content_length is not None and self.content_length > 0)

    @property
    def content_type(self) -> str:
        return self.header_map.get("content-type", [""])[0].lower()


@dataclass
class ResponseHead:
    version: str
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    header_map: Dict[str, List[str]]
    content_length: Optional[int]
    chunked: bool
    no_body: bool = False


def _parse_header_lines(lines: Sequence[bytes], *, request: bool) -> Tuple[List[Tuple[str, str]], Dict[str, List[str]]]:
    if len(lines) > MAX_HEADER_COUNT:
        raise ProxyError(431 if request else 502, "too many headers", code="too_many_headers")
    headers: List[Tuple[str, str]] = []
    mapping: Dict[str, List[str]] = {}
    total = 0
    for raw in lines:
        if len(raw) > MAX_HEADER_LINE_BYTES:
            raise ProxyError(431 if request else 502, "header line is too large", code="header_line_too_large")
        if not raw:
            raise ProxyError(400 if request else 502, "unexpected empty header", code="invalid_header")
        # Obsolete line folding is rejected rather than silently joined.
        if raw[:1] in (b" ", b"\t"):
            raise ProxyError(400 if request else 502, "folded headers are not accepted", code="obs_fold")
        colon = raw.find(b":")
        if colon <= 0:
            raise ProxyError(400 if request else 502, "malformed header", code="invalid_header")
        name_bytes = raw[:colon]
        value_bytes = raw[colon + 1 :].strip(b" \t")
        if len(name_bytes) > 128 or not _is_token_bytes(name_bytes):
            raise ProxyError(400 if request else 502, "invalid header name", code="invalid_header")
        if _contains_bad_ctl(value_bytes, allow_htab=True):
            raise ProxyError(400 if request else 502, "invalid header value", code="invalid_header")
        if len(value_bytes) > MAX_HEADER_VALUE_BYTES:
            raise ProxyError(431 if request else 502, "header value is too large", code="header_value_too_large")
        total += len(raw) + 2
        if total > MAX_HEADER_BYTES:
            raise ProxyError(431 if request else 502, "headers are too large", code="headers_too_large")
        name = name_bytes.decode("ascii").lower()
        value = value_bytes.decode("latin-1")
        headers.append((name, value))
        mapping.setdefault(name, []).append(value)
    return headers, mapping


def parse_request_head(data: bytes) -> Request:
    if not data.endswith(b"\r\n\r\n"):
        raise ProxyError(400, "malformed request headers", code="invalid_headers")
    lines = data[:-4].split(b"\r\n")
    if not lines or len(lines[0]) > MAX_REQUEST_LINE_BYTES:
        raise ProxyError(414, "request line is too large", code="request_line_too_large")
    request_line = lines[0]
    if _contains_bad_ctl(request_line) or request_line.count(b" ") != 2:
        raise ProxyError(400, "malformed request line", code="invalid_request_line")
    method_b, target, version_b = request_line.split(b" ")
    if not method_b or len(method_b) > 32 or not _is_token_bytes(method_b):
        raise ProxyError(400, "invalid method", code="invalid_method")
    if len(target) == 0 or len(target) > MAX_TARGET_BYTES or _contains_bad_ctl(target) or b"#" in target:
        raise ProxyError(400, "invalid request target", code="invalid_target")
    if target != b"*" and not target.startswith(b"/"):
        # Absolute-form would turn this generic proxy into an open proxy.
        raise ProxyError(400, "only origin-form request targets are accepted", code="invalid_target")
    if b"\\" in target:
        raise ProxyError(403, "request target rejected", code="bot_probe")
    if version_b not in (b"HTTP/1.0", b"HTTP/1.1"):
        raise ProxyError(505, "HTTP version not supported", code="http_version")
    headers, mapping = _parse_header_lines(lines[1:], request=True)
    host_values = mapping.get("host", [])
    if version_b == b"HTTP/1.1" and (len(host_values) != 1 or not host_values[0].strip()):
        raise ProxyError(400, "exactly one host header is required", code="invalid_host")
    if len(host_values) > 1:
        raise ProxyError(400, "duplicate host header", code="invalid_host")
    if host_values and (len(host_values[0]) > 255 or any(ch.isspace() for ch in host_values[0])):
        raise ProxyError(400, "invalid host header", code="invalid_host")

    cl = _parse_content_length(mapping.get("content-length", []), maximum=MAX_REQUEST_BODY)
    chunked = _parse_transfer_encoding(mapping.get("transfer-encoding", []))
    if cl is not None and chunked:
        raise ProxyError(400, "content length and transfer encoding cannot be combined", code="invalid_framing")
    expect_values = mapping.get("expect", [])
    expect_tokens = _header_tokens(expect_values) if expect_values else []
    if expect_tokens and expect_tokens != ["100-continue"]:
        raise ProxyError(417, "unsupported expectation", code="unsupported_expectation")
    if mapping.get("upgrade"):
        raise ProxyError(426, "protocol upgrades are not supported", code="upgrade_not_supported")
    # A request with neither CL nor TE has no delimited body.  This is safer
    # than guessing based on the method and avoids request-smuggling splits.
    return Request(
        method=method_b.decode("ascii"),
        target=target,
        version=version_b.decode("ascii"),
        headers=headers,
        header_map=mapping,
        content_length=cl,
        chunked=chunked,
        expect_continue=bool(expect_tokens),
        request_id=uuid.uuid4().hex[:16],
    )


def parse_response_head(data: bytes, request_method: str) -> ResponseHead:
    if not data.endswith(b"\r\n\r\n"):
        raise UpstreamError("malformed upstream response headers")
    lines = data[:-4].split(b"\r\n")
    if not lines:
        raise UpstreamError("empty upstream response")
    status_line = lines[0]
    if len(status_line) > MAX_REQUEST_LINE_BYTES or _contains_bad_ctl(status_line):
        raise UpstreamError("invalid upstream status line")
    pieces = status_line.split(b" ", 2)
    if len(pieces) < 2 or pieces[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
        raise UpstreamError("unsupported upstream HTTP version")
    if len(pieces[1]) != 3 or not pieces[1].isdigit():
        raise UpstreamError("invalid upstream status")
    status = int(pieces[1])
    if status < 100 or status > 599:
        raise UpstreamError("invalid upstream status")
    reason = pieces[2].decode("latin-1") if len(pieces) == 3 else ""
    headers, mapping = _parse_header_lines(lines[1:], request=False)
    cl = _parse_content_length(mapping.get("content-length", []), maximum=MAX_RESPONSE_BODY)
    chunked = _parse_transfer_encoding(mapping.get("transfer-encoding", []))
    if cl is not None and chunked:
        raise UpstreamError("ambiguous upstream response framing")
    no_body = (
        request_method.upper() == "HEAD"
        or 100 <= status < 200
        or status in (204, 304)
    )
    if no_body:
        # A body on these statuses is never forwarded.  Keeping framing
        # headers would make a persistent peer disagree, so normalize them.
        cl = cl if request_method.upper() == "HEAD" else None
        chunked = False
    if status == 101:
        raise UpstreamError("upstream protocol upgrade is not supported")
    return ResponseHead(
        version=pieces[0].decode("ascii"),
        status=status,
        reason=_safe_reason(reason, status),
        headers=headers,
        header_map=mapping,
        content_length=cl,
        chunked=chunked,
        no_body=no_body,
    )


# ---------------------------------------------------------------------------
# Framed request body reader.  It de-chunks input and gives the upstream a
# single canonical framing, eliminating CL/TE and chunk-extension surprises.


class RequestBody:
    def __init__(self, reader: asyncio.StreamReader, request: Request):
        self.reader = reader
        self.mode = "chunked" if request.chunked else ("length" if request.content_length is not None else "none")
        self.remaining = request.content_length or 0
        self.total = 0
        self.chunk_remaining = 0
        self.finished = self.mode == "none" or (self.mode == "length" and self.remaining == 0)
        self.deadline = time.monotonic() + BODY_TOTAL_TIMEOUT
        self.pending: Deque[bytes] = deque()

    def _timeout(self, base: float) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise BodyError(408, "request body timeout", code="body_timeout")
        return min(base, left)

    async def _read_exact(self, amount: int) -> bytes:
        if amount < 0:
            raise BodyError(400, "invalid body length", code="invalid_framing")
        try:
            return await asyncio.wait_for(self.reader.readexactly(amount), self._timeout(BODY_IDLE_TIMEOUT))
        except asyncio.IncompleteReadError as exc:
            raise BodyError(400, "incomplete request body", code="incomplete_body") from exc
        except asyncio.TimeoutError as exc:
            raise BodyError(408, "request body timeout", code="body_timeout") from exc

    async def _read_line(self, max_bytes: int = 128) -> bytes:
        try:
            line = await asyncio.wait_for(self.reader.readuntil(b"\r\n"), self._timeout(BODY_IDLE_TIMEOUT))
        except asyncio.LimitOverrunError as exc:
            raise BodyError(400, "chunk line is too large", code="invalid_chunk") from exc
        except asyncio.IncompleteReadError as exc:
            raise BodyError(400, "incomplete chunk framing", code="invalid_chunk") from exc
        except asyncio.TimeoutError as exc:
            raise BodyError(408, "request body timeout", code="body_timeout") from exc
        if len(line) > max_bytes:
            raise BodyError(400, "chunk line is too large", code="invalid_chunk")
        return line[:-2]

    def push_front(self, data: bytes) -> None:
        if data:
            self.pending.appendleft(data)

    async def read_chunk(self) -> Optional[bytes]:
        if self.pending:
            return self.pending.popleft()
        if self.finished:
            return None
        if self.mode == "length":
            if self.remaining == 0:
                self.finished = True
                return None
            amount = min(READ_CHUNK, self.remaining)
            data = await self._read_exact(amount)
            self.remaining -= len(data)
            self.total += len(data)
            if self.total > MAX_REQUEST_BODY:
                raise BodyError(413, "request body is too large", code="body_too_large")
            if self.remaining == 0:
                self.finished = True
            return data
        if self.mode == "chunked":
            if self.chunk_remaining == 0:
                line = await self._read_line(128)
                # Chunk extensions are not needed by an API and are rejected
                # to keep all parsers in agreement about the size.
                if b";" in line:
                    raise BodyError(400, "chunk extensions are not accepted", code="invalid_chunk")
                if not line or not HEX_RE.fullmatch(line.decode("ascii", "ignore")):
                    raise BodyError(400, "invalid chunk size", code="invalid_chunk")
                try:
                    size = int(line, 16)
                except ValueError as exc:
                    raise BodyError(400, "invalid chunk size", code="invalid_chunk") from exc
                if size > MAX_REQUEST_BODY or self.total + size > MAX_REQUEST_BODY:
                    raise BodyError(413, "request body is too large", code="body_too_large")
                if size == 0:
                    await self._read_trailers()
                    self.finished = True
                    return None
                self.chunk_remaining = size
            amount = min(READ_CHUNK, self.chunk_remaining)
            data = await self._read_exact(amount)
            self.chunk_remaining -= len(data)
            self.total += len(data)
            if self.chunk_remaining == 0:
                ending = await self._read_exact(2)
                if ending != b"\r\n":
                    raise BodyError(400, "invalid chunk terminator", code="invalid_chunk")
            return data
        self.finished = True
        return None

    async def _read_trailers(self) -> None:
        total = 0
        count = 0
        while True:
            line = await self._read_line(MAX_HEADER_LINE_BYTES)
            if not line:
                return
            count += 1
            total += len(line) + 2
            if count > MAX_TRAILERS or total > MAX_TRAILER_BYTES:
                raise BodyError(400, "too many trailers", code="invalid_trailer")
            # Validate trailer syntax but do not forward attacker-controlled
            # trailer fields to the application.
            if line[:1] in (b" ", b"\t") or b":" not in line:
                raise BodyError(400, "invalid trailer", code="invalid_trailer")
            name, value = line.split(b":", 1)
            if not _is_token_bytes(name) or _contains_bad_ctl(value, allow_htab=True):
                raise BodyError(400, "invalid trailer", code="invalid_trailer")


async def prefetch_body(body: RequestBody, target: int) -> Tuple[List[bytes], bool]:
    """Read a bounded prefix before opening the upstream connection.

    Small JSON requests are fully read and can be structurally inspected.  A
    larger/unknown body is only sampled, then streamed without buffering it.
    """
    if body.mode == "none":
        return [], True
    target = max(0, target)
    chunks: List[bytes] = []
    collected = 0
    while collected < target:
        chunk = await body.read_chunk()
        if chunk is None:
            break
        need = target - collected
        if len(chunk) > need:
            chunks.append(chunk[:need])
            body.push_front(chunk[need:])
            collected += need
            break
        chunks.append(chunk)
        collected += len(chunk)
    # For chunked bodies, consume the zero-size marker when the sampled body
    # ended exactly on the target; any next data is kept as a pending chunk.
    if body.mode == "chunked" and not body.finished and collected >= target:
        extra = await body.read_chunk()
        if extra is not None:
            body.push_front(extra)
    complete = body.finished
    return chunks, complete


# ---------------------------------------------------------------------------
# Application-layer bot/anomaly detector


class DuplicateJSONKey(ValueError):
    pass


def _pairs_no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _json_lexical_depth(text: str) -> int:
    depth = 0
    maximum = 0
    in_string = False
    escaped = False
    for char in text:
        code = ord(char)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            elif code < 0x20:
                raise ValueError("control character in JSON string")
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            maximum = max(maximum, depth)
            if maximum > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting is too deep")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced JSON")
    if in_string or escaped or depth != 0:
        raise ValueError("incomplete JSON")
    return maximum


def _json_node_count(value: Any) -> int:
    count = 0
    stack = [value]
    while stack:
        current = stack.pop()
        count += 1
        if count > MAX_JSON_NODES:
            raise ValueError("JSON has too many values")
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return count


@dataclass
class BotDecision:
    allow: bool
    score: int
    reasons: List[str] = field(default_factory=list)
    status: int = 403
    message: str = "request rejected"
    code: str = "bot_detected"


def assess_request(request: Request, body_prefix: bytes, body_complete: bool) -> BotDecision:
    """Score high-confidence automation/scanning signals after acceptance.

    This is intentionally not an IP reputation or rate-limit system.  Missing
    browser headers and ordinary SDK/curl user agents are *not* sufficient to
    block an API caller.  Only deterministic exploit/scanner indicators reach
    the blocking threshold; medium signals are retained for logs/telemetry.
    """
    score = 0
    reasons: List[str] = []
    method = request.method.upper()
    target_text = request.target.decode("latin-1")
    path_raw = target_text.split("?", 1)[0]
    query_raw = target_text.split("?", 1)[1] if "?" in target_text else ""
    try:
        decoded_path = urllib.parse.unquote_to_bytes(path_raw).decode("latin-1", "ignore").lower()
    except Exception:
        decoded_path = path_raw.lower()
    compact_path = re.sub(r"/+", "/", decoded_path)
    ua = request.header_map.get("user-agent", [""])[0]
    ua_lower = ua.lower()

    if SCANNER_UA_RE.search(ua_lower):
        score += 100
        reasons.append("known_scanner_user_agent")
    # These paths are overwhelmingly automated reconnaissance and have no
    # purpose on an Ollama/API endpoint.  Matching is case-insensitive after
    # one percent-decoding pass, but the original target is still forwarded
    # unchanged for all allowed requests.
    scanner_markers = (
        "/.env",
        "/.git",
        "/.svn",
        "/wp-admin",
        "/wp-login.php",
        "/xmlrpc.php",
        "/phpmyadmin",
        "/pma/",
        "/cgi-bin/",
        "/server-status",
        "/actuator/env",
        "/vendor/phpunit",
        "/boaform/",
        "/shell?",
    )
    if any(marker in compact_path or marker in (compact_path + ("?" + query_raw.lower() if query_raw else "")) for marker in scanner_markers):
        score += 100
        reasons.append("reconnaissance_path")
    if ".." in compact_path.split("/") or "%" in compact_path and "%2e" in path_raw.lower():
        score += 100
        reasons.append("path_traversal_probe")
    if any(token in target_text.lower() for token in ("%00", "%0d", "%0a", "${jndi:", "..%2f", "%2f..")):
        score += 100
        reasons.append("encoded_exploit_probe")
    if len(query_raw) > 6000:
        score += 25
        reasons.append("oversized_query")
    if query_raw and query_raw.count("&") + 1 > 300:
        score += 50
        reasons.append("query_parameter_flood")
    if len(ua) > 1024:
        score += 20
        reasons.append("oversized_user_agent")
    if request.version == "HTTP/1.0":
        score += 5
        reasons.append("legacy_http_client")
    # A few headers are common in proxy-smuggling/scanner traffic.  They are
    # observed as a signal, not blocked alone, to avoid breaking real APIs.
    if any(name in request.header_map for name in ("x-original-url", "x-rewrite-url", "x-http-method-override")):
        score += 20
        reasons.append("rewrite_override_header")

    # Structural JSON inspection runs only after the request body has been
    # accepted and bounded.  Incomplete large bodies are streamed and logged,
    # never buffered merely to classify them.
    if body_complete and body_prefix and "json" in request.content_type:
        if len(body_prefix) > MAX_JSON_INSPECT_BYTES:
            reasons.append("json_sample_too_large")
        else:
            try:
                text = body_prefix.decode("utf-8")
                _json_lexical_depth(text)
                parsed = json.loads(
                    text,
                    object_pairs_hook=_pairs_no_duplicates,
                    parse_constant=_reject_json_constant,
                )
                _json_node_count(parsed)
            except DuplicateJSONKey:
                raise ProxyError(400, "duplicate JSON object key", code="invalid_json")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
                raise ProxyError(400, "invalid or unsafe JSON body", code="invalid_json") from exc

    # Do not treat curl, Python SDKs, missing User-Agent, or missing browser
    # navigation headers as proof of a bot: those are valid API clients.
    # Medium score is observable, while only high-confidence signals block.
    if score >= 100:
        return BotDecision(False, score, reasons)
    return BotDecision(True, score, reasons)


# ---------------------------------------------------------------------------
# Proxy framing and forwarding


def _connection_remove_set(headers: Sequence[Tuple[str, str]]) -> set[str]:
    values = [value for name, value in headers if name == "connection"]
    if not values:
        return set()
    return set(_header_tokens(values))


def _request_outbound_headers(request: Request, peer_ip: str) -> List[Tuple[str, str]]:
    remove = HOP_BY_HOP | FORWARDED_INBOUND | _connection_remove_set(request.headers)
    output: List[Tuple[str, str]] = []
    saw_host = False
    for name, value in request.headers:
        if name in remove or name in ("content-length", "transfer-encoding", "expect", "trailer"):
            continue
        if name == "host":
            saw_host = True
        output.append((name, value))
    if not saw_host:
        output.append(("host", f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"))
    if request.chunked:
        output.append(("transfer-encoding", "chunked"))
    elif request.content_length is not None:
        output.append(("content-length", str(request.content_length)))
    # The incoming forwarding headers are discarded above and rebuilt from the
    # actual socket peer, so a client cannot spoof its identity to the backend.
    output.append(("x-forwarded-for", peer_ip))
    output.append(("x-forwarded-proto", "http"))
    output.append(("via", "1.1 protect.py"))
    output.append(("x-request-id", request.request_id))
    output.append(("connection", "close"))
    return output


def _response_outbound_headers(head: ResponseHead, request: Request) -> List[Tuple[str, str]]:
    remove = HOP_BY_HOP | _connection_remove_set(head.headers)
    output: List[Tuple[str, str]] = []
    for name, value in head.headers:
        if name in remove or name in ("content-length", "transfer-encoding", "trailer"):
            continue
        output.append((name, value))
    if not head.no_body:
        if head.chunked:
            output.append(("transfer-encoding", "chunked"))
        elif head.content_length is not None:
            output.append(("content-length", str(head.content_length)))
    elif request.method.upper() == "HEAD" and head.content_length is not None:
        output.append(("content-length", str(head.content_length)))
    output.append(("connection", "close"))
    output.append(("x-request-id", request.request_id))
    return output


def _serialize_head(start: bytes, headers: Iterable[Tuple[str, str]]) -> bytes:
    chunks = [start]
    for name, value in headers:
        # Names/values have already been validated.  latin-1 round-trips the
        # original HTTP octets, including legal obs-text.
        chunks.append(name.encode("ascii") + b": " + value.encode("latin-1") + b"\r\n")
    chunks.append(b"\r\n")
    return b"".join(chunks)


async def send_upstream_request_head(writer: asyncio.StreamWriter, request: Request, peer_ip: str) -> None:
    start = request.method.encode("ascii") + b" " + request.target + b" HTTP/1.1\r\n"
    writer.write(_serialize_head(start, _request_outbound_headers(request, peer_ip)))
    await _drain(writer, UPSTREAM_WRITE_TIMEOUT)


async def upload_request_body(
    body: RequestBody,
    upstream_writer: asyncio.StreamWriter,
    prefetched: Sequence[bytes],
) -> int:
    sent = 0

    async def send_piece(piece: bytes) -> None:
        nonlocal sent
        if not piece:
            return
        if sent + len(piece) > MAX_REQUEST_BODY:
            raise BodyError(413, "request body is too large", code="body_too_large")
        if body.mode == "chunked":
            upstream_writer.write(format(len(piece), "x").encode("ascii") + b"\r\n" + piece + b"\r\n")
        else:
            upstream_writer.write(piece)
        await _drain(upstream_writer, UPSTREAM_WRITE_TIMEOUT)
        sent += len(piece)

    for piece in prefetched:
        await send_piece(piece)
    while True:
        piece = await body.read_chunk()
        if piece is None:
            break
        await send_piece(piece)
    if body.mode == "chunked":
        upstream_writer.write(b"0\r\n\r\n")
        await _drain(upstream_writer, UPSTREAM_WRITE_TIMEOUT)
    if body.mode == "length" and body.remaining != 0:
        raise BodyError(400, "incomplete request body", code="incomplete_body")
    return sent


async def _read_response_head_final(
    reader: asyncio.StreamReader,
    request_method: str,
) -> Tuple[ResponseHead, List[ResponseHead]]:
    interim: List[ResponseHead] = []
    for _ in range(8):
        raw = await _read_head(reader, timeout=UPSTREAM_HEADER_TIMEOUT, what="upstream")
        try:
            head = parse_response_head(raw, request_method)
        except ProxyError as exc:
            raise UpstreamError(exc.message) from exc
        if 100 <= head.status < 200:
            if head.status == 101:
                raise UpstreamError("upstream protocol upgrade is not supported")
            interim.append(head)
            continue
        return head, interim
    raise UpstreamError("too many informational responses")


def _response_start(head: ResponseHead) -> bytes:
    return f"HTTP/1.1 {head.status} {_safe_reason(head.reason, head.status)}\r\n".encode("latin-1")


async def _send_interim(writer: asyncio.StreamWriter, head: ResponseHead) -> None:
    # Informational headers are filtered just like final headers, but never
    # carry a body/framing field.
    remove = HOP_BY_HOP | _connection_remove_set(head.headers) | {"content-length", "transfer-encoding", "trailer"}
    headers = [(name, value) for name, value in head.headers if name not in remove]
    writer.write(_serialize_head(f"HTTP/1.1 {head.status} {_safe_reason(head.reason, head.status)}\r\n".encode("latin-1"), headers))
    await _drain(writer, CLIENT_WRITE_TIMEOUT)


async def _read_upstream_exact(reader: asyncio.StreamReader, amount: int, deadline: float) -> bytes:
    left = deadline - time.monotonic()
    if left <= 0:
        raise UpstreamError("upstream response timeout")
    try:
        return await asyncio.wait_for(reader.readexactly(amount), min(RESPONSE_IDLE_TIMEOUT, left))
    except asyncio.IncompleteReadError as exc:
        raise UpstreamError("truncated upstream response") from exc
    except asyncio.TimeoutError as exc:
        raise UpstreamError("upstream response timeout") from exc


async def _read_upstream_line(reader: asyncio.StreamReader, deadline: float) -> bytes:
    left = deadline - time.monotonic()
    if left <= 0:
        raise UpstreamError("upstream response timeout")
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), min(RESPONSE_IDLE_TIMEOUT, left))
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise UpstreamError("invalid upstream chunk framing") from exc
    except asyncio.TimeoutError as exc:
        raise UpstreamError("upstream response timeout") from exc
    if len(line) > 128:
        raise UpstreamError("upstream chunk line is too large")
    return line[:-2]


async def _write_client(writer: asyncio.StreamWriter, data: bytes) -> None:
    if not data:
        return
    try:
        writer.write(data)
        await asyncio.wait_for(writer.drain(), CLIENT_WRITE_TIMEOUT)
    except (ConnectionError, BrokenPipeError, asyncio.TimeoutError) as exc:
        raise ClientClosed() from exc


async def relay_response_body(
    upstream_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    head: ResponseHead,
) -> int:
    if head.no_body:
        return 0
    deadline = time.monotonic() + RESPONSE_TOTAL_TIMEOUT
    total = 0

    async def account(data: bytes) -> None:
        nonlocal total
        total += len(data)
        if total > MAX_RESPONSE_BODY:
            raise UpstreamError("upstream response is too large")
        await _write_client(client_writer, data)

    if head.content_length is not None:
        remaining = head.content_length
        while remaining:
            amount = min(READ_CHUNK, remaining)
            data = await _read_upstream_exact(upstream_reader, amount, deadline)
            remaining -= len(data)
            await account(data)
        return total
    if head.chunked:
        while True:
            line = await _read_upstream_line(upstream_reader, deadline)
            if b";" in line or not line or not HEX_RE.fullmatch(line.decode("ascii", "ignore")):
                raise UpstreamError("invalid upstream chunk size")
            size = int(line, 16)
            if size > MAX_RESPONSE_BODY or total + size > MAX_RESPONSE_BODY:
                raise UpstreamError("upstream response is too large")
            if size == 0:
                await _consume_response_trailers(upstream_reader, deadline)
                await _write_client(client_writer, b"0\r\n\r\n")
                return total
            data = await _read_upstream_exact(upstream_reader, size, deadline)
            ending = await _read_upstream_exact(upstream_reader, 2, deadline)
            if ending != b"\r\n":
                raise UpstreamError("invalid upstream chunk terminator")
            # Reframe without extensions/trailers, keeping streaming semantics.
            await _write_client(client_writer, format(size, "x").encode("ascii") + b"\r\n")
            await account(data)
            await _write_client(client_writer, b"\r\n")
    # Close-delimited response.  The proxy always closes the client side after
    # this request, so no additional framing is required.
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise UpstreamError("upstream response timeout")
        try:
            data = await asyncio.wait_for(upstream_reader.read(READ_CHUNK), min(RESPONSE_IDLE_TIMEOUT, left))
        except asyncio.TimeoutError as exc:
            raise UpstreamError("upstream response timeout") from exc
        if not data:
            return total
        await account(data)


async def _consume_response_trailers(reader: asyncio.StreamReader, deadline: float) -> None:
    total = 0
    count = 0
    while True:
        line = await _read_upstream_line(reader, deadline)
        if not line:
            return
        count += 1
        total += len(line) + 2
        if count > MAX_TRAILERS or total > MAX_TRAILER_BYTES:
            raise UpstreamError("upstream trailers are too large")
        if line[:1] in (b" ", b"\t") or b":" not in line:
            raise UpstreamError("invalid upstream trailer")
        name, value = line.split(b":", 1)
        if not _is_token_bytes(name) or _contains_bad_ctl(value, allow_htab=True):
            raise UpstreamError("invalid upstream trailer")


# ---------------------------------------------------------------------------
# Error responses, logging, and server lifecycle


async def send_error(
    writer: asyncio.StreamWriter,
    status: int,
    message: str,
    *,
    request_id: Optional[str] = None,
    retry_after: Optional[int] = None,
) -> None:
    body_obj = {"error": message}
    if request_id:
        body_obj["request_id"] = request_id
    body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers: List[Tuple[str, str]] = [
        ("content-type", "application/json; charset=utf-8"),
        ("content-length", str(len(body))),
        ("cache-control", "no-store"),
        ("connection", "close"),
    ]
    if retry_after is not None:
        headers.append(("retry-after", str(retry_after)))
    start = f"HTTP/1.1 {status} {STATUS_REASONS.get(status, 'Error')}\r\n".encode("ascii")
    try:
        writer.write(_serialize_head(start, headers) + body)
        await asyncio.wait_for(writer.drain(), CLIENT_WRITE_TIMEOUT)
    except Exception:
        pass


def _set_socket_options(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class Proxy:
    def __init__(self) -> None:
        self.active_clients = 0
        self.active_tasks: set[asyncio.Task[Any]] = set()
        self.upstream_slots = asyncio.Semaphore(MAX_UPSTREAM_CONNECTIONS)
        self.stop_event = asyncio.Event()
        self.metrics: Dict[str, int] = {
            "accepted": 0,
            "overloaded": 0,
            "completed": 0,
            "blocked": 0,
            "client_errors": 0,
            "upstream_errors": 0,
        }

    def accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        _set_socket_options(writer)
        self.metrics["accepted"] += 1
        if self.active_clients >= MAX_CLIENT_CONNECTIONS:
            self.metrics["overloaded"] += 1
            task = asyncio.create_task(self._reject_overload(writer))
            task.set_name("overload-reject")
        else:
            self.active_clients += 1
            task = asyncio.create_task(self.handle_client(reader, writer))
        self.active_tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[Any]) -> None:
        self.active_tasks.discard(task)
        # Overload tasks do not increment active_clients.
        if not task.get_name().startswith("overload"):
            self.active_clients = max(0, self.active_clients - 1)
        with contextlib.suppress(asyncio.CancelledError, Exception):
            task.result()

    async def _reject_overload(self, writer: asyncio.StreamWriter) -> None:
        await send_error(writer, 503, "proxy capacity is temporarily exhausted", retry_after=1)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request: Optional[Request] = None
        upstream_writer: Optional[asyncio.StreamWriter] = None
        response_started = False
        status_for_log = 0
        score = 0
        reasons: List[str] = []
        request_bytes = 0
        response_bytes = 0
        started = time.monotonic()
        peer = _peer_ip(writer)
        try:
            raw_head = await _read_head(reader, timeout=HEADER_READ_TIMEOUT, what="request")
            request = parse_request_head(raw_head)
            status_for_log = 200
            if request.method.upper() in {"CONNECT", "TRACE", "TRACK", "DEBUG"}:
                raise ProxyError(405, "method is not available through this API proxy", code="method_not_allowed")
            if request.header_map.get("content-encoding"):
                encodings = _header_tokens(request.header_map["content-encoding"])
                if encodings != ["identity"]:
                    raise ProxyError(415, "compressed request bodies are not accepted", code="unsupported_encoding")

            # If the client asked for 100-continue, acknowledge only after the
            # request head has passed all framing/policy checks.
            if request.expect_continue:
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await _drain(writer, CLIENT_WRITE_TIMEOUT)

            body = RequestBody(reader, request)
            if request.content_length is not None and request.content_length <= MAX_JSON_INSPECT_BYTES:
                inspect_target = request.content_length
            elif request.has_body:
                inspect_target = BODY_PREFETCH_BYTES
            else:
                inspect_target = 0
            prefetched, complete = await prefetch_body(body, inspect_target)
            body_prefix = b"".join(prefetched)
            request_bytes = body.total
            decision = assess_request(request, body_prefix, complete)
            score = decision.score
            reasons = decision.reasons
            if not decision.allow:
                status_for_log = decision.status
                raise ProxyError(decision.status, decision.message, code=decision.code)

            # A bounded global slot prevents an unbounded upstream connection
            # storm while remaining independent of source IP and request rate.
            try:
                await asyncio.wait_for(self.upstream_slots.acquire(), UPSTREAM_QUEUE_TIMEOUT)
            except asyncio.TimeoutError as exc:
                status_for_log = 503
                raise ProxyError(503, "upstream capacity is temporarily exhausted", code="capacity") from exc
            try:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT, limit=MAX_HEADER_BYTES + 4096),
                        UPSTREAM_CONNECT_TIMEOUT,
                    )
                except (OSError, asyncio.TimeoutError) as exc:
                    self.metrics["upstream_errors"] += 1
                    status_for_log = 502
                    raise ProxyError(502, "upstream service is unavailable", code="upstream_unavailable") from exc

                await send_upstream_request_head(upstream_writer, request, peer)
                upload_task: Optional[asyncio.Task[int]] = None
                if request.has_body:
                    upload_task = asyncio.create_task(upload_request_body(body, upstream_writer, prefetched))
                else:
                    # There can be a legal Content-Length: 0 body, already
                    # represented in the request head; no upload is needed.
                    upload_task = asyncio.create_task(asyncio.sleep(0, result=0))
                response_task = asyncio.create_task(_read_response_head_final(upstream_reader, request.method))
                try:
                    done, _ = await asyncio.wait(
                        {upload_task, response_task}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if response_task in done:
                        try:
                            response_head, interim = response_task.result()
                        finally:
                            if not upload_task.done():
                                upload_task.cancel()
                                with contextlib.suppress(asyncio.CancelledError):
                                    await upload_task
                    else:
                        # Upload completed first; surface body errors before
                        # waiting for the final upstream response.
                        await upload_task
                        response_head, interim = await response_task
                except BodyError as exc:
                    status_for_log = exc.status
                    if not response_task.done():
                        response_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await response_task
                    raise
                except (UpstreamError, ProxyError):
                    if not upload_task.done():
                        upload_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await upload_task
                    if not response_task.done():
                        response_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await response_task
                    raise
                except asyncio.CancelledError:
                    raise

                for interim_head in interim:
                    if not writer.is_closing():
                        await _send_interim(writer, interim_head)
                response_started = True
                status_for_log = response_head.status
                response_headers = _response_outbound_headers(response_head, request)
                writer.write(_serialize_head(_response_start(response_head), response_headers))
                await _drain(writer, CLIENT_WRITE_TIMEOUT)
                response_bytes = await relay_response_body(upstream_reader, writer, response_head)
                self.metrics["completed"] += 1
            finally:
                self.upstream_slots.release()
        except ClientClosed:
            self.metrics["client_errors"] += 1
            status_for_log = status_for_log or 499
        except ProxyError as exc:
            status_for_log = exc.status
            if exc.code == "bot_detected":
                self.metrics["blocked"] += 1
            if not response_started and not writer.is_closing():
                await send_error(writer, exc.status, exc.message, request_id=request.request_id if request else None)
        except UpstreamError:
            self.metrics["upstream_errors"] += 1
            status_for_log = status_for_log or 502
            if not response_started and not writer.is_closing():
                await send_error(writer, 502, "invalid or unavailable upstream response", request_id=request.request_id if request else None)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.metrics["upstream_errors"] += 1
            status_for_log = status_for_log or 500
            logging.exception("unexpected proxy failure peer=%s", peer)
            if not response_started and not writer.is_closing():
                await send_error(writer, 500, "proxy failure", request_id=request.request_id if request else None)
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                with contextlib.suppress(Exception):
                    await upstream_writer.wait_closed()
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            elapsed_ms = int((time.monotonic() - started) * 1000)
            method = request.method if request else "-"
            target = request.target.decode("latin-1", "replace")[:200] if request else "-"
            logging.info(
                "request peer=%s method=%s target=%s status=%s score=%s reasons=%s "
                "request_bytes=%s response_bytes=%s elapsed_ms=%s",
                peer,
                method,
                target,
                status_for_log or "-",
                score,
                ",".join(reasons) if reasons else "-",
                request_bytes,
                response_bytes,
                elapsed_ms,
            )

    async def shutdown(self) -> None:
        self.stop_event.set()
        tasks = list(self.active_tasks)
        if not tasks:
            return
        done, pending = await asyncio.wait(tasks, timeout=10.0)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    proxy = Proxy()
    try:
        server = await asyncio.start_server(
            proxy.accept,
            host=LISTEN_HOST,
            port=LISTEN_PORT,
            limit=MAX_HEADER_BYTES + 4096,
            backlog=2048,
            reuse_address=True,
        )
    except OSError as exc:
        logging.error("cannot listen on %s:%s: %s", LISTEN_HOST, LISTEN_PORT, exc)
        raise
    sockets = server.sockets or []
    bound = ", ".join(str(sock.getsockname()) for sock in sockets)
    logging.info("L7 proxy listening on %s; upstream=%s:%s", bound, UPSTREAM_HOST, UPSTREAM_PORT)

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def request_stop() -> None:
        if not stop.is_set():
            stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, request_stop)
    try:
        async with server:
            await stop.wait()
    finally:
        server.close()
        await server.wait_closed()
        await proxy.shutdown()
        logging.info("proxy stopped metrics=%s", proxy.metrics)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
