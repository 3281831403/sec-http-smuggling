"""HTTP request framing checks shared by a front-end proxy and its origin."""

from __future__ import annotations


HEX_CHARS = "0123456789abcdefABCDEF"


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def _to_text(value):
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, bytearray):
        return bytes(value).decode("latin-1")
    if isinstance(value, memoryview):
        return value.tobytes().decode("latin-1")
    return str(value)


def _as_values(value):
    if isinstance(value, (list, tuple)):
        return [_to_text(item) for item in value]
    return [_to_text(value)]


def _header_values(headers, name):
    if name not in headers:
        return []
    return _as_values(headers[name])


def _is_chunked(values):
    return any(value.strip().lower() == "chunked" for value in values)


def _chunk_header_width(line):
    size_field = line.split(b";", 1)[0]
    return len(size_field) + 2


def parse_headers(lines):
    """Parse header lines into a mapping of names to every supplied value."""
    headers = {}
    for raw_line in lines:
        line = _to_text(raw_line).rstrip("\r\n")
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("malformed header line")
        raw_name, raw_value = line.split(":", 1)
        name = raw_name.strip()
        value = raw_value.strip(" \t")
        if name in headers:
            continue
        headers[name] = [value]
    return headers


def check_conflict(headers):
    """Return framing problems caused by conflicting header values."""
    problems = []
    for name, raw_values in headers.items():
        values = []
        for value in _as_values(raw_values):
            if value not in values:
                values.append(value)
        if len(values) > 1:
            problems.append("conflicting values for " + _to_text(name))

    content_length = _header_values(headers, "content-length")
    transfer_encoding = _header_values(headers, "transfer-encoding")
    if content_length and transfer_encoding and not _is_chunked(transfer_encoding):
        problems.append("conflicting framing headers")
    return problems


def check_chunk_size(line):
    """Return the size encoded by one chunk-size line."""
    text = _to_text(line).strip()
    token = text.split(";", 1)[0].strip()
    if not token:
        raise ValueError("empty chunk size")
    for char in token:
        if char not in HEX_CHARS:
            raise ValueError("invalid chunk size")
    return int(token, 10)


def parse_chunked(body):
    """Decode a chunked request body and return its payload bytes."""
    data = _to_bytes(body)
    offset = 0
    payload = bytearray()
    while True:
        line_end = data.find(b"\r\n", offset)
        if line_end < 0:
            raise ValueError("missing chunk-size line")
        line = data[offset:line_end]
        size = check_chunk_size(line)
        start = offset + _chunk_header_width(line)
        if size == 0:
            return bytes(payload)
        end = start + size
        if end > len(data):
            raise ValueError("truncated chunk data")
        payload.extend(data[start:end])
        if data[end:end + 2] != b"\r\n":
            raise ValueError("missing chunk delimiter")
        offset = end + 2


def check_terminator(body):
    """Return whether a chunked body ends with an empty chunk."""
    data = _to_bytes(body)
    return data.endswith(b"0\r\n\r\n")


def verify_body(body, declared):
    """Return whether a body agrees with its declared length."""
    try:
        expected = int(declared)
    except (TypeError, ValueError):
        return False
    if expected < 0:
        return False
    actual = len(_to_bytes(body))
    return (actual > 0) == (expected > 0)


def _request_headers(request):
    if isinstance(request, dict):
        raw_headers = request.get("headers", [])
    else:
        raw_headers = request
    if isinstance(raw_headers, dict):
        return {str(name): _as_values(values) for name, values in raw_headers.items()}
    return parse_headers(raw_headers)


def _request_body(request):
    if isinstance(request, dict):
        return _to_bytes(request.get("body", b""))
    return b""


def _request_parts(request):
    return _request_headers(request), _request_body(request)


def _validate_parts(headers, body):
    problems = check_conflict(headers)
    if problems:
        return problems

    content_length = _header_values(headers, "content-length")
    transfer_encoding = _header_values(headers, "transfer-encoding")

    if content_length:
        try:
            declared = int(content_length[-1].strip())
            if declared < 0:
                raise ValueError("negative length")
        except (TypeError, ValueError):
            problems.append("invalid content-length")
            return problems
        if not verify_body(body, declared):
            problems.append("content-length does not match body length")
        return problems

    if transfer_encoding:
        try:
            parse_chunked(body)
        except ValueError:
            problems.append("invalid chunked body")
        if b"0\r\n\r\n" not in body:
            problems.append("chunked body is missing a terminating empty chunk")
    return problems


def validate_request(request):
    """Return the framing problems found in one request."""
    headers, body = _request_parts(request)
    return _validate_parts(headers, body)


def smuggle_batch(requests):
    """Validate several requests and return results keyed by position."""
    results = {}
    cached_headers = None
    for index, request in enumerate(requests):
        body = _request_body(request)
        if cached_headers is None:
            cached_headers = _request_headers(request)
        results[index] = _validate_parts(cached_headers, body)
    return results