"""Mô phỏng kẻ tấn công (Darth) để phân tích an toàn của giao thức.

  python -m tools.mitm_demo

Kịch bản:
  A. Nghe lén thụ động (server độc hại ghi lại mọi gói)           -> chỉ thấy bản mã
  B. DH TRẦN (không xác thực) bị Man-in-the-Middle phá            -> minh họa vì sao cần chữ ký
  C. MitM chủ động lên giao thức của nhóm: thay giá trị DH         -> chữ ký/HMAC sai, bắt tay bị hủy
  D. MitM thay khóa công khai RSA bằng khóa của Darth              -> bị từ chối do khóa đã ghim
  E. Sửa bit trong bản mã / phát lại gói                           -> phiên bị đóng (fail-closed)
"""
from __future__ import annotations

import base64
import copy
import os
import sys
import tempfile
import time

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from secure_chat import crypto
from secure_chat.client import ChatClient
from secure_chat.config import GroupConfig
from secure_chat.identity import Identity, TrustStore
from secure_chat.server import RelayServer, ServerThread


class AttackerRelay(RelayServer):
    """Relay độc hại. mode: 'record' | 'swap_dh' | 'swap_pub' | 'tamper' | 'replay'."""

    def __init__(self, mode: str, **kw):
        super().__init__(**kw)
        self.mode = mode
        self.captured: list[dict] = []
        self.darth_dh = crypto.DHKeyPair()
        self.darth_id = None  # gán từ ngoài cho mode swap_pub
        self._done = False

    async def intercept(self, sender, to, msg):
        self.captured.append(copy.deepcopy(msg))
        kind, body = msg["kind"], msg["body"]
        if self.mode == "swap_dh" and kind in ("hs1", "hs2"):
            body["dh"] = base64.b64encode(self.darth_dh.public_bytes).decode()
        elif self.mode == "swap_pub" and kind in ("hs1", "hs2") and self.darth_id is not None:
            body["pub"] = base64.b64encode(self.darth_id.public_der).decode()
        elif self.mode == "tamper" and kind == "data" and not self._done and body.get("n", 0) >= 1:
            ct = bytearray(base64.b64decode(body["c"]))
            ct[0] ^= 0x01
            body["c"] = base64.b64encode(bytes(ct)).decode()
            self._done = True
        elif self.mode == "replay" and kind == "data" and body.get("n", 0) == 1 and not self._done:
            self._done = True
            return [(to, msg), (to, copy.deepcopy(msg))]
        return [(to, msg)]


def _setup(mode: str, trust: str = "strict"):
    work = tempfile.mkdtemp(prefix="e2e_mitm_")
    group = GroupConfig(("2411508", "2312075"))
    ids = {u: Identity.load_or_create(work, u, 2048) for u in ("alice", "bob")}
    ts = TrustStore(os.path.join(work, "trusted"))
    for u, i in ids.items():
        ts.pin(u, i.public_der)
    relay = AttackerRelay(mode, host="127.0.0.1", port=0)
    st = ServerThread(relay)
    port = st.start_and_wait()
    events: list[tuple[str, str, dict]] = []

    def mk(u):
        return ChatClient(u, group, "127.0.0.1", port, work, trust_policy=trust,
                          on_event=lambda k, _u=u, **kw: events.append((_u, k, kw)), rsa_bits=2048)

    a, b = mk("alice"), mk("bob")
    a.connect(); b.connect()
    return work, relay, st, a, b, events


def scenario_a():
    print("\n=== A. Nghe lén thụ động ===")
    _, relay, st, a, b, ev = _setup("record")
    secret = "SO-THE-TIN-DUNG-1234-5678"
    assert a.handshake_with("bob") and b.wait_session("alice")
    a.send_text("bob", secret)
    time.sleep(0.4)
    blob = b"".join(str(m).encode() for m in relay.captured)
    print(f"  Số gói server thấy: {len(relay.captured)}; chứa plaintext bí mật? {secret.encode() in blob}")
    data = [m for m in relay.captured if m['kind'] == 'data'][-1]['body']
    print(f"  Mẫu gói data (bản mã): n={data['n']} c={data['c'][:40]}…")
    print("  Lưu ý: chuỗi Hello bắt buộc nằm trong HS1/HS2 (có chủ ý, đề bài yêu cầu) và được ký.")
    a.close(); b.close(); st.stop()


def scenario_b():
    print("\n=== B. DH trần (không xác thực) bị MitM ===")
    alice, bob, darth1, darth2 = (crypto.DHKeyPair() for _ in range(4))
    # Darth chặn, thay y_A bằng y_D1 gửi cho Bob; thay y_B bằng y_D2 gửi cho Alice
    k_alice = alice.exchange(darth2.public_bytes)
    k_bob = bob.exchange(darth1.public_bytes)
    k_d_alice = darth2.exchange(alice.public_bytes)
    k_d_bob = darth1.exchange(bob.public_bytes)
    print(f"  Alice~Darth khớp: {k_alice == k_d_alice}; Bob~Darth khớp: {k_bob == k_d_bob}; "
          f"Alice~Bob khớp: {k_alice == k_bob}")
    print("  => Darth đọc/sửa được mọi tin nhắn mà hai bên không hay biết (đúng slide 'MitM' Chương IV).")


def scenario_c():
    print("\n=== C. MitM chủ động lên giao thức của nhóm: thay giá trị DH ===")
    _, relay, st, a, b, ev = _setup("swap_dh")
    ok = a.handshake_with("bob", timeout=8)
    time.sleep(0.3)
    print(f"  Bắt tay thành công? {ok}")
    for who, kind, kw in ev:
        if kind == "error":
            print(f"  [{who}] {kw['text'][:150]}")
    print(f"  Phiên được tạo? alice={bool(a.sessions)} bob={bool(b.sessions)}")
    a.close(); b.close(); st.stop()


def scenario_d():
    print("\n=== D. MitM thay khóa công khai RSA bằng khóa của Darth ===")
    work, relay, st, a, b, ev = _setup("swap_pub")
    relay.darth_id = Identity.load_or_create(work, "darth", 2048)
    ok = a.handshake_with("bob", timeout=8)
    time.sleep(0.3)
    print(f"  Bắt tay thành công? {ok}")
    for who, kind, kw in ev:
        if kind == "error":
            print(f"  [{who}] {kw['text'][:170]}")
    a.close(); b.close(); st.stop()


def scenario_e():
    print("\n=== E1. Sửa 1 bit của bản mã ===")
    _, relay, st, a, b, ev = _setup("tamper")
    assert a.handshake_with("bob") and b.wait_session("alice")
    a.send_text("bob", "chuyển 10 triệu cho X")
    time.sleep(0.4)
    print("  ", [kw["text"] for w, k, kw in ev if k == "error" and w == "bob"][:1])
    print(f"  Bob còn phiên? {bool(b.sessions)}")
    a.close(); b.close(); st.stop()
    print("=== E2. Phát lại (replay) một gói đã gửi ===")
    _, relay, st, a, b, ev = _setup("replay")
    assert a.handshake_with("bob") and b.wait_session("alice")
    a.send_text("bob", "lệnh chuyển tiền")
    time.sleep(0.4)
    got = [kw["text"] for w, k, kw in ev if k == "message" and w == "bob"]
    err = [kw["text"] for w, k, kw in ev if k == "error" and w == "bob"][:1]
    print(f"  Bob nhận {len(got)} lần (kỳ vọng 1). Lỗi: {err}")
    a.close(); b.close(); st.stop()


if __name__ == "__main__":
    for fn in (scenario_a, scenario_b, scenario_c, scenario_d, scenario_e):
        fn()
    print("\nHoàn tất.")
