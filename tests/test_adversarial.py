"""Hostile-input and local-exposure safeguards."""

import io


def test_foreign_host_header_rejected(client):
    response = client.get("/api/health", headers={"host": "evil.example.com"})
    assert response.status_code == 403


def test_local_hosts_accepted(client):
    for host in ("localhost", "127.0.0.1:8000", "[::1]:8000"):
        assert client.get("/api/health", headers={"host": host}).status_code == 200


def test_foreign_origin_state_change_rejected(client, phish_raw):
    for origin in ("https://evil.example.com", "http://localhost.evil.com"):
        response = client.post(
            "/api/analyze",
            data={"raw": phish_raw.decode("utf-8", errors="replace")},
            headers={"origin": origin},
        )
        assert response.status_code == 403


def test_local_origin_state_change_accepted(client, phish_raw):
    for origin in ("http://localhost:8000", "http://127.0.0.1", "http://[::1]:8000"):
        response = client.post(
            "/api/analyze",
            data={"raw": phish_raw.decode("utf-8", errors="replace")},
            headers={"origin": origin},
        )
        assert response.status_code == 200


def test_missing_origin_still_accepted(client, phish_raw):
    # Non-browser clients (curl, scripts) send no Origin header.
    response = client.post(
        "/api/analyze", data={"raw": phish_raw.decode("utf-8", errors="replace")}
    )
    assert response.status_code == 200


def test_oversized_declared_body_refused_before_read(client, phish_raw):
    from phishlens.api import MAX_REQUEST_BYTES

    response = client.post(
        "/api/analyze",
        data={"raw": phish_raw.decode("utf-8", errors="replace")},
        headers={"content-length": str(MAX_REQUEST_BYTES + 1)},
    )
    assert response.status_code == 413
    # The ceiling itself still fits.
    response = client.post(
        "/api/analyze",
        data={"raw": phish_raw.decode("utf-8", errors="replace")},
        headers={"content-length": str(MAX_REQUEST_BYTES)},
    )
    assert response.status_code != 413


def test_oversized_upload_rejected(client):
    big = io.BytesIO(b"x" * (10 * 1024 * 1024 + 1))
    files = [("files", ("big.eml", big, "message/rfc822"))]
    assert client.post("/api/analyze", files=files).status_code == 413


def test_batch_limit_enforced(client, phish_raw):
    files = [
        ("files", (f"f{i}.eml", io.BytesIO(phish_raw), "message/rfc822"))
        for i in range(21)
    ]
    assert client.post("/api/analyze", files=files).status_code == 400


def test_deeply_nested_mime_does_not_crash(client):
    part = b"Content-Type: text/plain\r\n\r\ninnermost\r\n"
    for i in range(40):
        part = (
            f"Content-Type: multipart/mixed; boundary=\"N{i}\"\r\n\r\n".encode()
            + f"--N{i}\r\n".encode()
            + part
            + f"--N{i}--\r\n".encode()
        )
    raw = b"From: a@b.co.za\r\nSubject: nested\r\n" + part
    response = client.post("/api/analyze", data={"raw": raw.decode("ascii")})
    assert response.status_code == 200


def test_empty_and_header_only_messages(client):
    for raw in ("From: a@b.co.za\r\n\r\n", "Subject: only a subject\r\n"):
        assert client.post("/api/analyze", data={"raw": raw}).status_code == 200


def test_json_export_roundtrip(client, phish_raw):
    case_id = client.post(
        "/api/analyze",
        files=[("files", ("p.eml", io.BytesIO(phish_raw), "message/rfc822"))],
    ).json()["cases"][0]["case_id"]
    response = client.get(f"/api/cases/{case_id}/report.json")
    assert response.status_code == 200
    assert "attachment" in response.headers.get("content-disposition", "")
    body = response.json()
    assert body["verdict"] == "likely_phish"
    assert body["case_id"] == case_id


def test_script_injection_in_subject_stays_inert(client, store):
    raw = (
        b"From: a@b.co.za\r\n"
        b"Subject: <script>alert(1)</script>\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
    )
    case_id = client.post("/api/analyze", data={"raw": raw.decode()}).json()["cases"][0]["case_id"]
    client.post(
        f"/api/cases/{case_id}/verdict",
        json={"verdict": "suspicious", "reason": "<img src=x onerror=alert(1)>"},
    )
    client.post(f"/api/cases/{case_id}/notes", json={"body": "<svg onload=alert(1)>"})
    html = client.get(f"/api/cases/{case_id}/report.html").text
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html
    # The stored JSON keeps the raw text (inert data); the HTML export escapes it.
    case = client.get(f"/api/cases/{case_id}").json()
    assert case["report"]["subject"] == "<script>alert(1)</script>"
