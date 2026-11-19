import io


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_ui_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishLens" in response.text


def test_rules_endpoint_lists_registry(client):
    rules = client.get("/api/rules").json()["rules"]
    assert len(rules) >= 20
    assert all({"id", "name", "category", "rationale"} <= set(r) for r in rules)


def test_analyze_upload_creates_a_case(client, phish_raw):
    response = client.post(
        "/api/analyze",
        files=[("files", ("phish.eml", io.BytesIO(phish_raw), "message/rfc822"))],
    )
    assert response.status_code == 200
    case = response.json()["cases"][0]
    assert case["verdict"] == "likely_phish"
    assert case["case_id"]
    assert case["route"]
    assert "secure-paypa1.top" in case["iocs"]["domains"]


def test_analyze_batch_upload(client, phish_raw, legit_raw):
    response = client.post(
        "/api/analyze",
        files=[
            ("files", ("a.eml", io.BytesIO(phish_raw), "message/rfc822")),
            ("files", ("b.eml", io.BytesIO(legit_raw), "message/rfc822")),
        ],
    )
    assert response.status_code == 200
    verdicts = {c["verdict"] for c in response.json()["cases"]}
    assert verdicts == {"likely_phish", "no_strong_signals"}


def test_analyze_pasted_text(client, legit_raw):
    response = client.post("/api/analyze", data={"raw": legit_raw.decode("utf-8")})
    assert response.status_code == 200
    assert response.json()["cases"][0]["verdict"] == "no_strong_signals"


def test_analyze_rejects_empty_request(client):
    assert client.post("/api/analyze", data={}).status_code == 400


def test_analyze_rejects_oversize(client):
    big = b"x" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/api/analyze",
        files=[("files", ("big.eml", io.BytesIO(big), "message/rfc822"))],
    )
    assert response.status_code == 413


def test_case_flow(client, phish_raw):
    created = client.post(
        "/api/analyze",
        files=[("files", ("phish.eml", io.BytesIO(phish_raw), "message/rfc822"))],
    ).json()["cases"][0]
    case_id = created["case_id"]

    listing = client.get("/api/cases").json()["cases"]
    assert [c["id"] for c in listing] == [case_id]

    hits = client.get("/api/cases", params={"search": "suspended"}).json()["cases"]
    assert len(hits) == 1

    response = client.post(
        f"/api/cases/{case_id}/verdict",
        json={"verdict": "likely_phish", "reason": "Client confirmed"},
    )
    assert response.status_code == 200

    response = client.post(f"/api/cases/{case_id}/notes", json={"body": "Blocked domain"})
    assert response.status_code == 200

    case = client.get(f"/api/cases/{case_id}").json()
    assert case["analyst_verdict"] == "likely_phish"
    assert len(case["notes"]) == 2  # verdict reason + free note

    report = client.get(f"/api/cases/{case_id}/report.html")
    assert report.status_code == 200
    assert "PhishLens triage report" in report.text

    iocs = client.get(f"/api/cases/{case_id}/iocs.txt")
    assert iocs.status_code == 200
    assert "hxxps://" in iocs.text


def test_missing_case_is_404(client):
    assert client.get("/api/cases/nope").status_code == 404
    assert client.get("/api/cases/nope/report.html").status_code == 404
    response = client.post("/api/cases/nope/verdict", json={"verdict": "suspicious"})
    assert response.status_code == 404


def test_invalid_verdict_is_400(client, phish_raw):
    case_id = client.post(
        "/api/analyze",
        files=[("files", ("p.eml", io.BytesIO(phish_raw), "message/rfc822"))],
    ).json()["cases"][0]["case_id"]
    response = client.post(f"/api/cases/{case_id}/verdict", json={"verdict": "evil"})
    assert response.status_code == 400
