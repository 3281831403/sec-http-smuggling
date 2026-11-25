"""HTTP request framing checks shared by a front-end proxy and its origin.

Both sides of a proxy/origin hop must derive exactly the same boundary for
every request they accept.  Every rule below therefore fails closed: any
ambiguity a sender could exploit to make the two parsers disagree is reported
as a framing problem instead of being tolerated.
"""

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


def check_chunk_size(line):
    """Return the size encoded by one chunk-size line.

    Chunk extensions (``;name=value``) are framing metadata, not payload: they
    are stripped here so the caller can locate the chunk data precisely.  The
    size itself must be pure hexadecimal; anything else is rejected so a
    decimal-only parser and a hex parser can never disagree on the boundary.
    """
    text = _to_text(line).strip()
    token = text.split(";", 1)[0].strip()
    if not token:
        raise ValueError("empty chunk size")
    for char in token:
        if char not in HEX_CHARS:
            raise ValueError("invalid chunk size")
    return int(token, 16)


def parse_headers(lines):
    """Parse header lines into a mapping of names to every supplied value.

    Header names are case-insensitive in HTTP, so they are normalised to
    lower case: ``Content-Length`` and ``content-length`` are the same
    header and must be compared as such.  Repeated lines are retained in
    order so conflicting duplicate values can be detected downstream.
    """
    headers = {}
    for raw_line in lines:
        line = _to_text(raw_line).rstrip("\r\n")
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("malformed header line")
        raw_name, raw_value = line.split(":", 1)
        name = raw_name.strip().lower()
        if not name:
            raise ValueError("malformed header line")
        value = raw_value.strip(" \t")
        headers.setdefault(name, []).append(value)
    return headers


def check_conflict(headers):
    """Return framing problems caused by conflicting header values.

    Two rules are enforced:

    * The same header appearing more than once with different values is a
      conflict (identical duplicates are allowed).
    * ``Content-Length`` and ``Transfer-Encoding`` must never appear
      together: one side may honour the length header while the other
      switches to chunked framing, which is the canonical request
      smuggling disagreement.
    """
    problems = []
    for name, raw_values in headers.items():
        seen = []
        for value in _as_values(raw_values):
            normalized = value.strip()
            if normalized not in seen:
                seen.append(normalized)
        if len(seen) > 1:
            problems.append("conflicting values for " + _to_text(name))

    content_length = _header_values(headers, "content-length")
    transfer_encoding = _header_values(headers, "transfer-encoding")
    if content_length and transfer_encoding:
        problems.append("conflicting framing headers")
    return problems


def parse_chunked(body):
    """Decode a chunked request body and return its payload bytes.

    The whole body must be consumed by the chunked framing: every chunk has
    an exact hex size, chunk extensions are skipped rather than read as
    data, each data chunk is followed by CRLF, and the body must finish with
    exactly one zero-size chunk immediately followed by the terminating
    empty line.  Any byte left over after that terminator would be the start
    of a second request on a connection-persistent parser, so it is an
    error rather than silently ignored data.
    """
    data = _to_bytes(body)
    offset = 0
    payload = bytearray()
    while True:
        line_end = data.find(b"\r\n", offset)
        if line_end < 0:
            raise ValueError("missing chunk-size line")
        line = data[offset:line_end]
        size = check_chunk_size(line)
        # Skip the entire chunk-size line, including any ";extensions".
        data_start = offset + len(line) + 2
        if size == 0:
            # Empty chunk: the next line must be empty (no trailer section)
            # and it must be the end of the body.
            if data[data_start:data_start + 2] != b"\r\n":
                raise ValueError("missing chunk terminator")
            if data_start + 2 != len(data):
                raise ValueError("data after final empty chunk")
            return bytes(payload)
        end = data_start + size
        if end > len(data):
            raise ValueError("truncated chunk data")
        payload.extend(data[data_start:end])
        if data[end:end + 2] != b"\r\n":
            raise ValueError("missing chunk delimiter")
        offset = end + 2


def check_terminator(body):
    """Return whether a chunked body ends with exactly one empty chunk.

    Delegates to :func:`parse_chunked` so there is a single definition of
    the chunked boundary: a body accepted here is a body whose framing
    parses cleanly end to end with nothing trailing.
    """
    try:
        parse_chunked(body)
    except ValueError:
        return False
    return True


def verify_body(body, declared):
    """Return whether a body agrees with its declared length exactly."""
    try:
        expected = int(declared)
    except (TypeError, ValueError):
        return False
    if expected < 0:
        return False
    return len(_to_bytes(body)) == expected


def _request_headers(request):
    if isinstance(request, dict):
        raw_headers = request.get("headers", [])
    else:
        raw_headers = request
    if isinstance(raw_headers, dict):
        return {
            str(name).strip().lower(): _as_values(values)
            for name, values in raw_headers.items()
        }
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
        if not check_terminator(body):
            problems.append("chunked body is missing a terminating empty chunk")
    return problems


def validate_request(request):
    """Return the framing problems found in one request.

    Pure and deterministic: validating the same request twice always yields
    the same result, and no state is shared between calls.
    """
    headers, body = _request_parts(request)
    return _validate_parts(headers, body)


def smuggle_batch(requests):
    """Validate several requests and return results keyed by position.

    Each request is validated independently with its own headers and body;
    one request's framing can never influence the verdict of another.
    """
    results = {}
    for index, request in enumerate(requests):
        results[index] = validate_request(request)
    return results
