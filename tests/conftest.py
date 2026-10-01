import sys
from pathlib import Path
R = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(R / "src"))
import pytest
from uniaethel.config import load_config

@pytest.fixture(scope="session")
def cfg():
    return load_config(R / "configs/default.yaml")
