import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_chat.config import GroupConfig  # noqa: E402
from secure_chat.identity import Identity, TrustStore  # noqa: E402


@pytest.fixture(scope="session")
def group():
    return GroupConfig(("2411508", "2312075"))


@pytest.fixture(scope="session")
def idents(tmp_path_factory):
    d = tmp_path_factory.mktemp("ids")
    return {u: Identity.load_or_create(str(d), u, 2048) for u in ("alice", "bob", "darth")}


@pytest.fixture()
def stores(tmp_path, idents):
    """Mỗi bên chỉ ghim khóa của đối tác (không ghim darth)."""
    a = TrustStore(str(tmp_path / "ta")); a.pin("bob", idents["bob"].public_der)
    b = TrustStore(str(tmp_path / "tb")); b.pin("alice", idents["alice"].public_der)
    return a, b
