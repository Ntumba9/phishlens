import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def phish_raw() -> bytes:
    return (FIXTURES / "phish_paypa1.eml").read_bytes()


@pytest.fixture
def legit_raw() -> bytes:
    return (FIXTURES / "legit_newsletter.eml").read_bytes()


@pytest.fixture
def store(tmp_path):
    """An isolated case store per test."""
    from phishlens.store import CaseStore

    return CaseStore(str(tmp_path / "cases.db"))


@pytest.fixture
def client(store):
    """API test client wired to the isolated store."""
    from fastapi.testclient import TestClient

    from phishlens.api import app

    app.state.store = store
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.state.store = None
