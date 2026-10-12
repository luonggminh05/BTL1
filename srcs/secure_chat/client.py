"""Client chat + truyền tệp mã hóa đầu cuối.

Chạy:
  python -m secure_chat.client --user alice --mssv 2411508 2312075
Lệnh trong chương trình:  /help
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
from typing import Callable

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from . import crypto
from .config import ConfigError, GroupConfig, load_group
from .filetransfer import IncomingFiles, OutgoingFile, TransferError
from .framing import FrameError, recv_frame, send_frame
from .handshake import HandshakeError, Initiator, Responder
from .identity import Identity, TrustError, TrustStore, check_username
from .session import (MSG_FILE_CHUNK, MSG_FILE_END, MSG_FILE_OFFER, MSG_GREETING, MSG_TEXT,
                      Session, SessionError)


class ChatError(Exception):
    pass


class ChatClient:
    def __init__(
        self,
        username: str,
        group: GroupConfig,
        host: str = "127.0.0.1",
        port: int = 5000,
        data_dir: str = "data",
        downloads_dir: str | None = None,
        trust_policy: str = "strict",
        on_event: Callable[..., None] | None = None,
        rsa_bits: int = crypto.RSA_BITS,
    ):
        self.username = check_username(username)
        self.group, self.host, self.port = group, host, port
        self.on_event = on_event or (lambda kind, **kw: None)
        self.identity = Identity.load_or_create(data_dir, username, rsa_bits)
        self.trust = TrustStore(os.path.join(data_dir, "trusted"), trust_policy,
                                notify=lambda s: self._emit("warn", text=s))
        self.files = IncomingFiles(downloads_dir or os.path.join(data_dir, "downloads", username))
        self.sessions: dict[str, Session] = {}
        self._pending: dict[str, Initiator | Responder] = {}
        self._hs_event: dict[str, threading.Event] = {}
        self._hs_ok: dict[str, bool] = {}
        self._state = threading.RLock()
        self._tx = threading.Lock()  # bảo vệ: seal() + gửi socket (giữ seq trùng thứ tự gửi)
        self.sock: socket.socket | None = None
        self._running = False

    # ------------------------------------------------------------------ tiện ích
    def _emit(self, kind: str, **kw) -> None:
        try:
            self.on_event(kind, **kw)
        except Exception:  # noqa: BLE001
            pass

    def _send_raw(self, obj: dict) -> None:
        with self._tx:
            assert self.sock is not None
            send_frame(self.sock, obj)

    def _relay(self, to: str, kind: str, body: dict) -> None:
        self._send_raw({"type": "relay", "to": to, "kind": kind, "body": body})

    def _send_record(self, peer: str, mtype: int, body: bytes) -> None:
        with self._tx:
            s = self.sessions.get(peer)
            if s is None or not s.alive:
                raise ChatError(f"Chưa có phiên bảo mật với '{peer}'. Dùng /connect {peer}")
            assert self.sock is not None
            rec = s.seal(mtype, body)
            send_frame(self.sock, {"type": "relay", "to": peer, "kind": "data", "body": rec})

    # ------------------------------------------------------------------ kết nối
    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        self.sock.settimeout(None)
        send_frame(self.sock, {"type": "register", "user": self.username})
        rep = recv_frame(self.sock)
        if rep.get("type") != "registered":
            self.sock.close()
            raise ChatError(rep.get("msg", "Đăng ký thất bại"))
        self._running = True
        threading.Thread(target=self._recv_loop, daemon=True, name=f"recv-{self.username}").start()

    def close(self) -> None:
        self._running = False
        for s in list(self.sessions.values()):
            s.close()
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()

    def list_users(self) -> None:
        self._send_raw({"type": "list"})

    # ------------------------------------------------------------------ bắt tay (phía khởi tạo)
    def handshake_with(self, peer: str, timeout: float = 20.0) -> bool:
        check_username(peer)
        if peer == self.username:
            raise ChatError("Không thể kết nối với chính mình")
        ev = threading.Event()
        with self._state:
            init = Initiator(self.identity, peer, self.group, self.trust)
            self._pending[peer] = init
            self._hs_event[peer] = ev
            self._hs_ok[peer] = False
        hs1 = init.start()
        self._relay(peer, "hs1", hs1)
        self._emit("info", text=f"Đã gửi HS1 tới {peer}, đang chờ…")
        if not ev.wait(timeout):
            with self._state:
                self._pending.pop(peer, None)
            raise ChatError(f"Hết thời gian bắt tay với {peer}")
        return self._hs_ok.get(peer, False)

    def wait_session(self, peer: str, timeout: float = 10.0) -> bool:
        """Chờ (phía nhận bắt tay) cho tới khi phiên với <peer> được thiết lập."""
        end = time.time() + timeout
        while time.time() < end:
            s = self.sessions.get(peer)
            if s and s.alive:
                return True
            time.sleep(0.02)
        return False

    def _finish(self, peer: str, ok: bool) -> None:
        ev = self._hs_event.get(peer)
        self._hs_ok[peer] = ok
        if ev:
            ev.set()

    def _established(self, peer: str, sess: Session) -> None:
        old = self.sessions.get(peer)
        if old:
            old.close()
        self.sessions[peer] = sess
        self._pending.pop(peer, None)
        self._finish(peer, True)
        self._emit("session", peer=peer, role=sess.role, session_id=sess.session_id.hex())
        self._send_record(peer, MSG_GREETING, self.group.hello.encode("utf-8"))

    # ------------------------------------------------------------------ gửi dữ liệu
    def send_text(self, peer: str, text: str) -> None:
        self._send_record(peer, MSG_TEXT, text.encode("utf-8"))

    def send_file(self, peer: str, path: str) -> None:
        f = OutgoingFile(path)
        self._send_record(peer, MSG_FILE_OFFER, f.offer_body())
        sent = 0
        for blk in f.chunks():
            self._send_record(peer, MSG_FILE_CHUNK, blk)
            sent += len(blk) - 20
            self._emit("progress", peer=peer, name=f.name, sent=sent, total=f.size, direction="send")
        self._send_record(peer, MSG_FILE_END, f.end_body())
        self._emit("file_sent", peer=peer, name=f.name, size=f.size, sha256=f.sha256)

    # ------------------------------------------------------------------ vòng nhận
    def _recv_loop(self) -> None:
        while self._running:
            try:
                frame = recv_frame(self.sock)  # type: ignore[arg-type]
            except (ConnectionError, OSError, FrameError):
                if self._running:
                    self._emit("disconnected")
                self._running = False
                return
            try:
                self._dispatch(frame)
            except Exception as e:  # noqa: BLE001 - không để luồng nhận chết
                self._emit("error", text=f"Lỗi xử lý gói: {e!r}")

    def _dispatch(self, frame: dict) -> None:
        t = frame.get("type")
        if t == "users":
            self._emit("users", users=frame.get("users", []))
        elif t == "error":
            self._emit("error", text=f"Server: {frame.get('msg')}")
        elif t == "relay":
            peer, kind, body = frame.get("from"), frame.get("kind"), frame.get("body")
            if not isinstance(peer, str) or not isinstance(body, dict):
                return
            handler = {"hs1": self._on_hs1, "hs2": self._on_hs2, "hs3": self._on_hs3,
                       "hs_abort": self._on_abort, "data": self._on_data}.get(kind)  # type: ignore[arg-type]
            if handler:
                handler(peer, body)

    def _fail(self, peer: str, why: str, notify_peer: bool = True) -> None:
        with self._state:
            self._pending.pop(peer, None)
            self._finish(peer, False)
        self._emit("error", text=f"Bắt tay với '{peer}' THẤT BẠI: {why}")
        if notify_peer:
            try:
                self._relay(peer, "hs_abort", {"reason": "handshake failed"})
            except Exception:  # noqa: BLE001
                pass

    def _on_hs1(self, peer: str, body: dict) -> None:
        with self._state:
            cur = self._pending.get(peer)
            if isinstance(cur, Initiator):
                if self.username < peer:  # cả hai cùng khởi tạo: tên nhỏ hơn làm Initiator
                    self._emit("info", text=f"Bỏ qua HS1 trùng từ {peer} (glare)")
                    return
                self._pending.pop(peer, None)
            resp = Responder(self.identity, peer, self.group, self.trust)
            try:
                hs2 = resp.on_hs1(body)
            except (HandshakeError, crypto.CryptoError) as e:
                self._fail(peer, str(e))
                return
            self._pending[peer] = resp
        self._relay(peer, "hs2", hs2)

    def _on_hs2(self, peer: str, body: dict) -> None:
        with self._state:
            init = self._pending.get(peer)
            if not isinstance(init, Initiator):
                return
            try:
                hs3, sess = init.on_hs2(body)
            except (HandshakeError, crypto.CryptoError) as e:
                self._fail(peer, str(e))
                return
            self._relay(peer, "hs3", hs3)
            self._established(peer, sess)

    def _on_hs3(self, peer: str, body: dict) -> None:
        with self._state:
            resp = self._pending.get(peer)
            if not isinstance(resp, Responder):
                return
            try:
                sess = resp.on_hs3(body)
            except (HandshakeError, crypto.CryptoError) as e:
                self._fail(peer, str(e))
                return
            self._established(peer, sess)

    def _on_abort(self, peer: str, body: dict) -> None:
        with self._state:
            if self._pending.pop(peer, None) is not None:
                self._finish(peer, False)
                self._emit("error", text=f"'{peer}' đã hủy bắt tay")

    def _kill(self, peer: str, why: str) -> None:
        s = self.sessions.pop(peer, None)
        if s:
            s.close()
        self.files.abort_peer(peer)
        self._emit("error", text=f"Phiên với '{peer}' bị đóng: {why}")

    def _on_data(self, peer: str, body: dict) -> None:
        s = self.sessions.get(peer)
        if s is None:
            self._emit("error", text=f"Nhận dữ liệu từ '{peer}' khi chưa có phiên")
            return
        try:
            mtype, pt = s.open(body)
        except SessionError as e:
            self._kill(peer, str(e))  # fail-closed
            return
        try:
            if mtype == MSG_TEXT:
                self._emit("message", peer=peer, text=pt.decode("utf-8", "replace"))
            elif mtype == MSG_GREETING:
                txt = pt.decode("utf-8", "replace")
                if txt != self.group.hello:
                    self._kill(peer, f"Hello không khớp nhóm MSSV: {txt!r}")
                else:
                    self._emit("greeting", peer=peer, text=txt)
            elif mtype == MSG_FILE_OFFER:
                info = self.files.on_offer(peer, pt)
                self._emit("file_offer", peer=peer, **info)
            elif mtype == MSG_FILE_CHUNK:
                got = self.files.on_chunk(peer, pt)
                self._emit("progress", peer=peer, name="", sent=got, total=0, direction="recv")
            elif mtype == MSG_FILE_END:
                info = self.files.on_end(peer, pt)
                self._emit("file_received", peer=peer, **info)
            else:
                self._emit("error", text=f"Loại thông điệp lạ {mtype}")
        except TransferError as e:
            self._emit("error", text=f"Truyền tệp từ '{peer}' lỗi: {e}")


# ====================================================================== CLI
HELP = """Lệnh:
  /users                    liệt kê người đang online
  /connect <user>           bắt tay bảo mật (DH + RSA) với <user>
  /use <user>               chọn người đang chat (gõ văn bản thường để gửi)
  /send <đường_dẫn> [user]  gửi tệp (mã hóa) tới user hiện tại hoặc [user]
  /sessions                 xem các phiên đang mở
  /fingerprint              vân tay khóa công khai của bạn
  /trust <user> <file.pub>  ghim khóa công khai của <user>
  /quit                     thoát"""


def _cli_events(kind: str, **kw) -> None:
    if kind == "message":
        print(f"\r<{kw['peer']}> {kw['text']}")
    elif kind == "session":
        print(f"\r[+] Phiên bảo mật với {kw['peer']} đã thiết lập (session_id={kw['session_id'][:16]}…)")
    elif kind == "greeting":
        print(f"\r[✓] {kw['peer']} xác nhận nhóm: {kw['text']}")
    elif kind == "file_offer":
        print(f"\r[↓] {kw['peer']} gửi tệp '{kw['name']}' ({kw['size']} B)…")
    elif kind == "file_received":
        print(f"\r[✓] Đã nhận '{kw['name']}' -> {kw['path']} (SHA-256 khớp)")
    elif kind == "file_sent":
        print(f"\r[✓] Đã gửi '{kw['name']}' ({kw['size']} B) tới {kw['peer']}")
    elif kind == "users":
        print("\rOnline:", ", ".join(kw["users"]))
    elif kind in ("error", "warn", "info"):
        print(f"\r[{kind}] {kw['text']}")
    elif kind == "disconnected":
        print("\r[!] Mất kết nối server")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="E2E chat client (BTL1 1.1)")
    ap.add_argument("--user", required=True)
    ap.add_argument("--mssv", nargs="+", help="MSSV các thành viên (đúng thứ tự, cả 2 phía giống nhau)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--trust", choices=["strict", "tofu"], default="strict")
    a = ap.parse_args(argv)
    try:
        group = load_group(a.mssv)
        state: dict[str, str | None] = {"cur": None}

        def on_event(kind: str, **kw) -> None:
            if kind == "session" and state["cur"] is None:
                state["cur"] = kw["peer"]  # tự chọn đối tác đầu tiên
            _cli_events(kind, **kw)

        c = ChatClient(a.user, group, a.host, a.port, a.data_dir, trust_policy=a.trust, on_event=on_event)
        c.connect()
    except (ConfigError, ChatError, OSError, ValueError) as e:
        print(f"Lỗi: {e}", file=sys.stderr)
        return 1
    print(f"Đã kết nối với tư cách '{a.user}'. {group.hello}")
    print(f"Vân tay khóa của bạn: {c.identity.fingerprint}\n(gõ /help để xem lệnh)")
    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            try:
                if not line.startswith("/"):
                    if not state["cur"]:
                        print("Chưa chọn người nhận: /connect <user> hoặc /use <user>")
                    else:
                        c.send_text(state["cur"], line)
                    continue
                cmd, *args = line.split(maxsplit=2)
                if cmd == "/quit":
                    break
                elif cmd == "/help":
                    print(HELP)
                elif cmd == "/users":
                    c.list_users()
                elif cmd == "/connect" and args:
                    if c.handshake_with(args[0]):
                        state["cur"] = state["cur"] or args[0]
                elif cmd == "/use" and args:
                    state["cur"] = args[0]
                    print(f"Đang chat với {args[0]}")
                elif cmd == "/send" and args:
                    target = args[1] if len(args) > 1 else state["cur"]
                    if not target:
                        print("Chưa chọn người nhận: /send <đường_dẫn> <user>")
                    else:
                        c.send_file(target, args[0])
                elif cmd == "/sessions":
                    for p, s in c.sessions.items():
                        print(f"  {p}: role={s.role} sid={s.session_id.hex()[:16]} tx={s.send_seq} rx={s.recv_seq}")
                elif cmd == "/fingerprint":
                    print(c.identity.fingerprint)
                elif cmd == "/trust" and len(args) == 2:
                    print("Đã ghim. Vân tay:", c.trust.pin_file(args[0], args[1]))
                else:
                    print("Lệnh không hợp lệ. /help")
            except (ChatError, TransferError, ValueError, OSError) as e:
                print(f"[lỗi] {e}")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
