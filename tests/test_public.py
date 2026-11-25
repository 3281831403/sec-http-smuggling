from smuggle import (
    parse_chunked,
    parse_headers,
    smuggle_batch,
    validate_request,
    verify_body,
)


def test_header_parse_retains_same_name_values():
    headers = parse_headers(
        [
            "host: example.test",
            "x-probe: first",
            "x-probe: second",
        ]
    )
    assert headers.get("host") == ["example.test"]
    assert headers.get("x-probe") == ["first", "second"]


def test_single_chunk_payload_ignores_extension():
    body = b"5;source=proxy\r\nhello\r\n0\r\n\r\n"
    try:
        payload = parse_chunked(body)
    except ValueError:
        payload = None
    assert payload == b"hello"


def test_declared_length_matches_body():
    assert verify_body(b"hello", 5) is True
    assert verify_body(b"hello", 4) is False


def test_conflicting_framing_headers_reported():
    request = {
        "headers": ["content-length: 5", "transfer-encoding: chunked"],
        "body": b"hello",
    }
    errors = validate_request(request)
    assert any("conflicting framing" in error for error in errors), errors


def test_batch_requests_are_independent():
    requests = [
        {
            "headers": ["transfer-encoding: chunked"],
            "body": b"5\r\nhello\r\n",
        },
        {
            "headers": ["content-length: 5"],
            "body": b"hello",
        },
    ]
    results = smuggle_batch(requests)
    assert results[0], results
    assert results[1] == [], results