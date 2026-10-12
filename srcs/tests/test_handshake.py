import base64
import copy

import pytest

from secure_chat.config import GroupConfig
from secure_chat.handshake import HandshakeError, Initiator, Responder
from secure_chat.identity import TrustStore


def run(idents, group, stores, group_b=None):
    ta, tb = stores
    I = Initiator(idents["alice"], "bob", group, ta)
    R = Responder(idents["bob"], "alice", group_b or group, tb)
    hs1 = I.start()
    hs2 = R.on_hs1(hs1)
    hs3, si = I.on_hs2(hs2)
    sr = R.on_hs3(hs3)
    return I, R, hs1, hs2, hs3, si, sr


def test_handshake_ok_and_channel_works(idents, group, stores):
    *_, hs1, hs2, hs3, si, sr = run(idents, group, stores)
    assert hs1["hello"] == "Hello, We are 2411508, 2312075" == hs2["hello"]
    assert si.session_id == sr.session_id
    assert sr.open(si.seal(1, b"abc")) == (1, b"abc")
    assert si.open(sr.seal(1, b"xyz")) == (1, b"xyz")


def test_wrong_group_mssv_rejected(idents, group, stores):
    with pytest.raises(HandshakeError, match="không khớp"):
        run(idents, group, stores, group_b=GroupConfig(("2411508", "2099999")))


def test_swapped_dh_detected(idents, group, stores):
    ta, tb = stores
    I = Initiator(idents["alice"], "bob", group, ta)
    R = Responder(idents["bob"], "alice", group, tb)
    hs1 = I.start()
    from secure_chat import crypto
    evil = copy.deepcopy(hs1)
    evil["dh"] = base64.b64encode(crypto.DHKeyPair().public_bytes).decode()
    hs2 = R.on_hs1(evil)           # Bob không phát hiện được ở bước này...
    with pytest.raises(HandshakeError, match="CHỮ KÝ"):
        I.on_hs2(hs2)              # ...nhưng Alice phát hiện vì transcript khác


def test_hs2_dh_swapped_detected(idents, group, stores):
    ta, tb = stores
    from secure_chat import crypto
    I = Initiator(idents["alice"], "bob", group, ta)
    R = Responder(idents["bob"], "alice", group, tb)
    hs2 = R.on_hs1(I.start())
    hs2["dh"] = base64.b64encode(crypto.DHKeyPair().public_bytes).decode()
    with pytest.raises(HandshakeError, match="CHỮ KÝ"):
        I.on_hs2(hs2)


def test_unknown_peer_rejected_in_strict(idents, group, tmp_path):
    ta = TrustStore(str(tmp_path / "a"))   # rỗng
    tb = TrustStore(str(tmp_path / "b")); tb.pin("alice", idents["alice"].public_der)
    I = Initiator(idents["alice"], "bob", group, ta)
    R = Responder(idents["bob"], "alice", group, tb)
    hs2 = R.on_hs1(I.start())
    with pytest.raises(HandshakeError, match="Chưa tin cậy"):
        I.on_hs2(hs2)


def test_pinned_key_change_rejected_even_in_tofu(idents, group, tmp_path):
    tb = TrustStore(str(tmp_path / "b"), "tofu"); tb.pin("alice", idents["alice"].public_der)
    ta = TrustStore(str(tmp_path / "a"), "tofu")
    # Darth giả danh 'alice' bằng khóa của mình
    I = Initiator(idents["darth"], "bob", group, ta)
    I.ident = idents["darth"]
    R = Responder(idents["bob"], "alice", group, tb)
    hs1 = I.start()
    hs1["id"] = "alice"
    with pytest.raises(HandshakeError, match="KHÁC"):
        R.on_hs1(hs1)


def test_identity_mismatch_envelope(idents, group, stores):
    ta, tb = stores
    I = Initiator(idents["alice"], "bob", group, ta)
    R = Responder(idents["bob"], "mallory", group, tb)  # server khai 'from' = mallory
    with pytest.raises(HandshakeError, match="khác người gửi"):
        R.on_hs1(I.start())


def test_forged_hs3_rejected(idents, group, stores):
    I, R, hs1, hs2, hs3, si, sr = run(idents, group, stores)
    ta, tb = stores
    I2 = Initiator(idents["alice"], "bob", group, ta)
    R2 = Responder(idents["bob"], "alice", group, tb)
    R2.on_hs1(I2.start())
    with pytest.raises(HandshakeError):
        R2.on_hs3(hs3)   # HS3 của phiên khác (replay) không dùng lại được


def test_malformed_messages(idents, group, stores):
    ta, tb = stores
    R = Responder(idents["bob"], "alice", group, tb)
    for bad in ({}, {"v": 2}, {"v": 1, "id": "alice", "hello": "x", "pub": "!!", "nonce": "", "dh": ""}):
        with pytest.raises(HandshakeError):
            R.on_hs1(bad)
