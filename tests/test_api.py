import io

from fastapi.testclient import TestClient

from phishlens.api import app

client = TestClient(app)


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_ui_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishLens" in response.text


def test_analyze_upload(phish_raw):
    response = client.post(
        "/api/analyze",
        files={"file": ("phish.eml", io.BytesIO(phish_raw), "message/rfc822")},
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "likely_phish"


def test_analyze_pasted_text(legit_raw):
    response = client.post(
        "/api/analyze", data={"raw": legit_raw.decode("utf-8")}
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "no_strong_signals"


def test_analyze_rejects_empty_request():
    response = client.post("/api/analyze", data={})
    assert response.status_code == 400


def test_analyze_rejects_oversize():
    big = b"x" * (2 * 1024 * 1024 + 1)
    response = client.post(
        "/api/analyze",
        files={"file": ("big.eml", io.BytesIO(big), "message/rfc822")},
    )
    assert response.status_code == 413
