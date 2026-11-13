from pathlib import Path

import pytest

DATA_DIRECTORY = Path(__file__).parent / "data"


@pytest.fixture
def sample_export_path() -> Path:
    """Path of the FAKE mSecure export used by the tests."""
    return DATA_DIRECTORY / "sample_export.csv"


@pytest.fixture
def sample_export_text(sample_export_path: Path) -> str:
    return sample_export_path.read_text(encoding="utf-8")
