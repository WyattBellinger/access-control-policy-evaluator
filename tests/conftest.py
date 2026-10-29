import json
from pathlib import Path

import pytest


@pytest.fixture
def load_fixture():
    def load(name):
        return json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text())

    return load
