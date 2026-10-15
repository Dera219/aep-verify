import copy
import json
from pathlib import Path

import pytest

from aep_verify.keys import private_key_from_seed_base64, public_key_from_base64

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "v1.0.3-rc.2"


def load(name: str):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def keys():
    return load("keys.json")


@pytest.fixture(scope="session")
def public_key(keys):
    return public_key_from_base64(keys["public_key_base64"])


@pytest.fixture(scope="session")
def private_key(keys):
    return private_key_from_seed_base64(keys["seed_base64"])


@pytest.fixture(scope="session")
def chain_vector():
    return load("b-chain.json")


@pytest.fixture
def artifacts(chain_vector):
    """A deep copy of the vector (b) artifacts, safe to mutate."""
    return copy.deepcopy(chain_vector["artifacts"])
