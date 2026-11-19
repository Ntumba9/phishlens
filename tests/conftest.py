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
