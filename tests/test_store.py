import pytest

from phishlens.engine import analyze, report_to_dict


def make_report(raw: bytes) -> dict:
    return report_to_dict(analyze(raw))


def test_save_and_get_roundtrip(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    case = store.get_case(case_id)
    assert case is not None
    assert case["id"] == case_id
    assert case["subject"] == "Urgent: your account has been suspended"
    assert case["report"]["verdict"] == "likely_phish"
    assert case["analyst_verdict"] is None


def test_case_id_written_back_into_report(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    assert store.get_case(case_id)["report"]["case_id"] == case_id


def test_list_newest_first_and_search(store, phish_raw, legit_raw):
    store.save_case(make_report(phish_raw))
    store.save_case(make_report(legit_raw))
    cases = store.list_cases()
    assert len(cases) == 2
    assert cases[0]["created_at"] >= cases[1]["created_at"]
    hits = store.list_cases(search="github")
    assert len(hits) == 1
    assert "github" in hits[0]["sender"]
    verdict_hits = store.list_cases(verdict="likely_phish")
    assert len(verdict_hits) == 1


def test_verdict_override_with_reason(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    assert store.set_verdict(case_id, "likely_phish", "Confirmed with the client")
    case = store.get_case(case_id)
    assert case["analyst_verdict"] == "likely_phish"
    assert case["analyst_reason"] == "Confirmed with the client"
    # The reason is also recorded in the note trail.
    assert any("Confirmed with the client" in n["body"] for n in case["notes"])


def test_verdict_rejects_unknown_value(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    with pytest.raises(ValueError):
        store.set_verdict(case_id, "definitely_evil")


def test_verdict_and_notes_on_missing_case(store):
    assert store.set_verdict("nope", "suspicious") is False
    assert store.add_note("nope", "hello") is False
    assert store.get_case("nope") is None


def test_notes_accumulate_in_order(store, phish_raw):
    case_id = store.save_case(make_report(phish_raw))
    store.add_note(case_id, "first")
    store.add_note(case_id, "second")
    bodies = [n["body"] for n in store.get_case(case_id)["notes"]]
    assert bodies == ["first", "second"]
