"""Queue status, related-case grouping and the copy-only incident handoff."""

import pytest

from phishlens.engine import analyze, report_to_dict


def make_report(raw: bytes) -> dict:
    return report_to_dict(analyze(raw))


def _second_phish(raw: bytes) -> bytes:
    """Same sender domain and links, different subject and message id."""
    text = raw.decode("utf-8", errors="replace")
    text = text.replace(
        "Urgent: your account has been suspended",
        "Action required: verify your account",
    )
    return text.encode()


def test_new_cases_start_as_new(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    assert store.get_case(case_id)["status"] == "new"
    assert store.list_cases()[0]["status"] == "new"


def test_status_lifecycle_and_filter(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    assert store.set_status(case_id, "in_review")
    assert store.get_case(case_id)["status"] == "in_review"
    assert store.list_cases(status="in_review")
    assert not store.list_cases(status="closed")
    assert store.set_status(case_id, "closed")
    assert store.list_cases(status="closed")[0]["id"] == case_id


def test_status_rejects_unknown_and_missing(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    with pytest.raises(ValueError):
        store.set_status(case_id, "done")
    assert store.set_status("nonexistent", "closed") is False


def test_status_column_added_to_existing_db(tmp_path):
    """A database created before statuses existed gains the column."""
    import sqlite3

    from phishlens.store import CaseStore

    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE cases (id TEXT PRIMARY KEY, created_at TEXT NOT NULL,"
            " subject TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '',"
            " verdict TEXT NOT NULL, score INTEGER NOT NULL,"
            " report_json TEXT NOT NULL, analyst_verdict TEXT,"
            " analyst_reason TEXT NOT NULL DEFAULT '',"
            " tags TEXT NOT NULL DEFAULT '')"
        )
        conn.execute(
            "INSERT INTO cases (id, created_at, verdict, score, report_json)"
            " VALUES ('old1', '2026-01-01', 'suspicious', 10, '{}')"
        )
    store = CaseStore(path)
    assert store.get_case("old1")["status"] == "new"


def test_related_groups_shared_sender_domain(store, phish_raw):
    first = store.save_case(make_report(phish_raw))
    second = store.save_case(make_report(_second_phish(phish_raw)))
    related = store.related_cases(first)
    assert [r["id"] for r in related] == [second]
    assert any(s.startswith("domain:") for s in related[0]["shared"])


def test_related_empty_without_shared_indicators(store, phish_raw, legit_raw):
    store.save_case(make_report(phish_raw))
    store.save_case(make_report(legit_raw))
    phish_id = store.list_cases(search="suspended")[0]["id"]
    legit_id = store.list_cases(search="github")[0]["id"]
    assert store.related_cases(phish_id) == []
    assert store.related_cases(legit_id) == []


def test_related_unknown_case_is_none(store):
    assert store.related_cases("nonexistent") is None


def test_api_status_flow(client, phish_raw):
    resp = client.post("/api/analyze", data={"raw": phish_raw.decode("utf-8", "replace")})
    case_id = resp.json()["cases"][0]["case_id"]
    assert client.post(
        f"/api/cases/{case_id}/status", json={"status": "in_review"}
    ).status_code == 200
    assert client.get(f"/api/cases/{case_id}").json()["status"] == "in_review"
    listed = client.get("/api/cases?status=in_review").json()["cases"]
    assert [c["id"] for c in listed] == [case_id]
    bad = client.post(f"/api/cases/{case_id}/status", json={"status": "nope"})
    assert bad.status_code == 400
    missing = client.post("/api/cases/nope/status", json={"status": "closed"})
    assert missing.status_code == 404


def test_api_related_endpoint(client, phish_raw):
    raw = phish_raw.decode("utf-8", "replace")
    first = client.post("/api/analyze", data={"raw": raw}).json()["cases"][0]["case_id"]
    client.post("/api/analyze", data={"raw": _second_phish(phish_raw).decode()})
    body = client.get(f"/api/cases/{first}/related").json()
    assert len(body["related"]) == 1
    assert client.get("/api/cases/nope/related").status_code == 404


def test_handoff_text_is_inert_and_complete(client, phish_raw):
    raw = phish_raw.decode("utf-8", "replace")
    case_id = client.post("/api/analyze", data={"raw": raw}).json()["cases"][0]["case_id"]
    resp = client.get(f"/api/cases/{case_id}/handoff.txt")
    assert resp.status_code == 200
    text = resp.text
    assert "PhishLens incident handoff" in text
    assert "likely phish" in text
    assert "not a calibrated probability" in text
    assert "secure-paypa1[.]top" in text
    assert "https://secure-paypa1" not in text  # indicators stay defanged
    assert client.get("/api/cases/nope/handoff.txt").status_code == 404


def test_handoff_includes_analyst_call(store, client, phish_raw):
    raw = phish_raw.decode("utf-8", "replace")
    case_id = client.post("/api/analyze", data={"raw": raw}).json()["cases"][0]["case_id"]
    client.post(
        f"/api/cases/{case_id}/verdict",
        json={"verdict": "likely_phish", "reason": "Confirmed with the client"},
    )
    text = client.get(f"/api/cases/{case_id}/handoff.txt").text
    assert "Analyst verdict: likely phish - Confirmed with the client" in text
