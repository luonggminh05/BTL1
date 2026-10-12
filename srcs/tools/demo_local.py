"""Demo tự động: server + 2 client (alice, bob) trên localhost, chat + gửi tệp, in 'góc nhìn server'.

  python -m tools.demo_local --mssv 2411508 2312075
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
import time

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from secure_chat.client import ChatClient
from secure_chat.config import GroupConfig
from secure_chat.crypto import fingerprint
from secure_chat.identity import Identity, TrustStore
from secure_chat.server import RelayServer, ServerThread


class Spy(RelayServer):
    """Relay chỉ để in 'góc nhìn của server': loại gói + bản mã (không có plaintext)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.n = 0

    async def intercept(self, sender, to, msg):
        self.n += 1
        b = msg["body"]
        if msg["kind"] != "data" or self.n <= 8:
            print(f"   [SERVER thấy] #{self.n:<3} {sender}->{to} {msg['kind']:<4} "
                  f"{str(b.get('c', b.get('dh', '')))[:44]}…")
        return [(to, msg)]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mssv", nargs="+", default=["2411508", "2312075"])
    a = ap.parse_args(argv)
    group = GroupConfig(tuple(a.mssv))
    logging.basicConfig(level=logging.WARNING)
    work = tempfile.mkdtemp(prefix="e2e_demo_")
    print(f"Thư mục làm việc: {work}")
    print(f"K0 = SHA256({''.join(group.mssv)}) = {group.initial_key.hex()}\n")

    print("1) Sinh khóa RSA-3072 + ghim chéo (strict)…")
    ids = {u: Identity.load_or_create(work, u) for u in ("alice", "bob")}
    ts = TrustStore(os.path.join(work, "trusted"))
    for u, i in ids.items():
        ts.pin(u, i.public_der)
        print(f"   {u}: {fingerprint(i.public_der)[:47]}…")

    srv = ServerThread(Spy("127.0.0.1", 0))
    port = srv.start_and_wait()
    log: list[str] = []

    def mk(u: str) -> ChatClient:
        def on(kind, **kw):
            if kind == "progress":
                return
            msg = kw.get("text") or {k: v for k, v in kw.items() if k != "sha256"}
            log.append(f"{u:>5} | {kind}: {msg}")
            print(f"   {u:>5} | {kind}: {msg}")
        return ChatClient(u, group, "127.0.0.1", port, work, trust_policy="strict", on_event=on)

    print("\n2) Kết nối & bắt tay (DH + RSA-PSS + HMAC)…")
    alice, bob = mk("alice"), mk("bob")
    alice.connect(); bob.connect()
    assert alice.handshake_with("bob"), "bắt tay thất bại"
    assert bob.wait_session("alice")

    print("\n3) Gửi tin nhắn mã hóa…")
    alice.send_text("bob", "Chào Bob, đây là tin nhắn bí mật số 1")
    bob.send_text("alice", "Chào Alice, Bob đã nhận được!")
    time.sleep(0.5)

    print("\n4) Gửi tệp 1 MiB…")
    src = os.path.join(work, "bao_cao.bin")
    with open(src, "wb") as f:
        f.write(os.urandom(1 << 20))
    alice.send_file("bob", src)
    time.sleep(1.0)

    print("\n5) Kiểm tra kết quả")
    got = [l for l in log if "file_received" in l]
    assert got, "không nhận được tệp"
    print("   => Tệp đã nhận và kiểm tra SHA-256 khớp.")
    print(f"   => Server đã chuyển {srv.server.n} gói nhưng chỉ thấy bản mã (xem [SERVER thấy]).")
    alice.close(); bob.close(); srv.stop()
    time.sleep(0.2)


if __name__ == "__main__":
    main()
