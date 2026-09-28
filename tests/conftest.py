from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_dir():
    return FIXTURES / "sample_miniapp"