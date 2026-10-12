import os
import time

import pytest

from secure_chat.client import ChatClient, ChatError
from secure_chat.identity import Identity, TrustStore
from secure_chat.server import RelayServer, ServerThread
from tools.mitm_demo import AttackerRelay


class Env:
    def __init__(self, tmp, group, relay):
        self.events = []
        self.st = ServerThread(relay)
        self.port = self.st.start_and_wait()
        self.work = str(tmp)
        ids = {u: Identity.load_or_create(self.work, u, 2048) for u in ("alice", "bob")}
        ts = TrustStore(os.path.join(self.work, "trusted"))
        for u, i in ids.items():
            ts.pin(u, i.public_der)
        self.group = group
        self.a, self.b = self.mk("alice"), self.mk("bob")
        self.a.connect(); self.b.connect()

    def mk(self, u, group=None):
        return ChatClient(u, group or self.group, "127.0.0.1", self.port, self.work, on_event=lambda k, _u=u, **kw: self.events.append((_u, k, kw)), rsa_bits=2048)

    def wait(self, pred, t=5.0):
        end = time.time() + t
        while time.time() < end:
            if any(pred(e) for e in list(self.events)):
                return True
            time.sleep(0.05)
        return False

    def close(self):
        self.a.close(); self.b.close(); self.st.stop()


@pytest.fixture()
def env(tmp_path, group):
    e = Env(tmp_path, group, RelayServer("127.0.0.1", 0))
    yield e
    e.close()


def test_chat_and_file(env, tmp_path):
    assert env.a.handshake_with("bob") and env.b.wait_session("alice")
    assert env.wait(lambda e: e[0] == "alice" and e[1] == "greeting")
    assert env.wait(lambda e: e[0] == "bob" and e[1] == "greeting" and e[2]["text"] == "Hello, We are 2411508, 2312075")
    env.a.send_text("bob", "xin chào 🌏")
    env.b.send_text("alice", "ok")
    assert env.wait(lambda e: e[0] == "bob" and e[1] == "message" and e[2]["text"] == "xin chào 🌏")
    assert env.wait(lambda e: e[0] == "alice" and e[1] == "message" and e[2]["text"] == "ok")
    src = tmp_path / "big.bin"; data = os.urandom(300_000); src.write_bytes(data)
    env.a.send_file("bob", str(src))
    assert env.wait(lambda e: e[1] == "file_received")
    path = [e for e in env.events if e[1] == "file_received"][0][2]["path"]
    assert open(path, "rb").read() == data


def test_send_without_session(env):
    with pytest.raises(ChatError):
        env.a.send_text("bob", "x")


def test_different_mssv_cannot_handshake(env):
    from secure_chat.config import GroupConfig
    c = env.mk("carol", GroupConfig(("2411508", "2099999")))
    Identity.load_or_create(env.work, "carol", 2048)
    TrustStore(os.path.join(env.work, "trusted")).pin("carol", c.identity.public_der)
    c.connect()
    assert not c.handshake_with("alice", timeout=6)
    c.close()


def test_offline_peer(env):
    env.a._relay("nobody", "hs1", {})
    assert env.wait(lambda e: e[1] == "error" and "không online" in e[2]["text"])


@pytest.mark.parametrize("mode", ["swap_dh", "swap_pub"])
def test_active_mitm_blocked(tmp_path, group, mode):
    relay = AttackerRelay(mode, host="127.0.0.1", port=0)
    e = Env(tmp_path, group, relay)
    try:
        if mode == "swap_pub":
            relay.darth_id = Identity.load_or_create(e.work, "darth", 2048)
        assert not e.a.handshake_with("bob", timeout=8)
        assert not e.a.sessions and not e.b.sessions
    finally:
        e.close()


@pytest.mark.parametrize("mode", ["tamper", "replay"])
def test_data_attacks_close_session(tmp_path, group, mode):
    relay = AttackerRelay(mode, host="127.0.0.1", port=0)
    e = Env(tmp_path, group, relay)
    try:
        assert e.a.handshake_with("bob") and e.b.wait_session("alice")
        e.a.send_text("bob", "lệnh nhạy cảm")
        assert e.wait(lambda ev: ev[0] == "bob" and ev[1] == "error" and "bị đóng" in ev[2]["text"])
        assert not e.b.sessions
    finally:
        e.close()
