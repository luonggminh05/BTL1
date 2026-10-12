"""Relay server (KHÔNG tin cậy): chỉ chuyển tiếp gói giữa các client.

Server không có khóa nào để giải mã nội dung; nó chỉ thấy: ai gửi cho ai, loại gói, kích thước
và bản mã. Chạy:   python -m secure_chat.server --host 0.0.0.0 --port 5000 -v
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import threading

from .framing import FrameError, read_frame, write_frame
from .identity import USERNAME_RE

ALLOWED_KINDS = {"hs1", "hs2", "hs3", "hs_abort", "data"}
log = logging.getLogger("relay")


class RelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, verbose: bool = False):
        self.host, self.port, self.verbose = host, port, verbose
        self.clients: dict[str, tuple[asyncio.StreamWriter, asyncio.Lock]] = {}
        self._server: asyncio.AbstractServer | None = None

    # --- điểm móc để mô phỏng kẻ tấn công (tools/mitm_demo.py ghi đè hàm này)
    async def intercept(self, sender: str, to: str, msg: dict) -> list[tuple[str, dict]]:
        return [(to, msg)]

    async def start(self) -> None:
        self._server = await asyncio.start_server(self.handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("Relay server lắng nghe tại %s:%d", self.host, self.port)

    async def serve_forever(self) -> None:
        await self.start()
        async with self._server:  # type: ignore[union-attr]
            await self._server.serve_forever()  # type: ignore[union-attr]

    async def stop(self) -> None:
        for w, _ in list(self.clients.values()):
            w.close()
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), 1)
            except asyncio.TimeoutError:
                pass

    async def _send(self, user: str, obj: dict) -> bool:
        entry = self.clients.get(user)
        if entry is None:
            return False
        w, lock = entry
        try:
            async with lock:
                await write_frame(w, obj)
            return True
        except (ConnectionError, OSError):
            return False

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        user: str | None = None
        try:
            first = await asyncio.wait_for(read_frame(reader), timeout=15)
            name = first.get("user")
            if first.get("type") != "register" or not isinstance(name, str) or not USERNAME_RE.match(name):
                await write_frame(writer, {"type": "error", "msg": "Đăng ký không hợp lệ"})
                return
            if name in self.clients:
                await write_frame(writer, {"type": "error", "msg": f"Tên '{name}' đã được dùng"})
                return
            user = name
            self.clients[user] = (writer, asyncio.Lock())
            await self._send(user, {"type": "registered", "user": user})
            log.info("+ %s kết nối (%d online)", user, len(self.clients))
            while True:
                await self.dispatch(user, await read_frame(reader))
        except (asyncio.IncompleteReadError, ConnectionError, FrameError, asyncio.TimeoutError, OSError):
            pass
        finally:
            if user and self.clients.get(user, (None,))[0] is writer:
                del self.clients[user]
                log.info("- %s ngắt kết nối", user)
            writer.close()

    async def dispatch(self, sender: str, frame: dict) -> None:
        t = frame.get("type")
        if t == "list":
            await self._send(sender, {"type": "users", "users": sorted(self.clients)})
            return
        if t != "relay":
            await self._send(sender, {"type": "error", "msg": "Loại gói không hỗ trợ"})
            return
        to, kind, body = frame.get("to"), frame.get("kind"), frame.get("body")
        if kind not in ALLOWED_KINDS or not isinstance(to, str) or not isinstance(body, dict):
            await self._send(sender, {"type": "error", "msg": "Gói relay sai định dạng"})
            return
        if to not in self.clients:
            await self._send(sender, {"type": "error", "msg": f"'{to}' không online"})
            return
        if self.verbose:
            if kind in ("hs1", "hs2"):
                log.info("relay %s -> %s kind=%s | PLAINTEXT hello=%r (id=%s)",
                         sender, to, kind, body.get("hello"), body.get("id"))
            else:
                preview = str(body.get("c", body.get("dh", "")))[:48]
                log.info("relay %s -> %s kind=%s | %s…", sender, to, kind, preview)
        out = {"type": "relay", "from": sender, "kind": kind, "body": body}
        for dest, msg in await self.intercept(sender, to, out):
            await self._send(dest, msg)


class ServerThread(threading.Thread):
    """Chạy RelayServer trong luồng riêng (dùng cho test/demo)."""

    def __init__(self, server: RelayServer):
        super().__init__(daemon=True)
        self.server = server
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()

    def run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())
        self.ready.set()
        self.loop.run_forever()

    def start_and_wait(self) -> int:
        self.start()
        self.ready.wait(5)
        return self.server.port

    def stop(self) -> None:
        fut = asyncio.run_coroutine_threadsafe(self.server.stop(), self.loop)
        try:
            fut.result(3)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)


def main() -> None:
    ap = argparse.ArgumentParser(description="E2E chat relay server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("-v", "--verbose", action="store_true", help="in ra các gói (chỉ thấy bản mã)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    try:
        asyncio.run(RelayServer(a.host, a.port, a.verbose).serve_forever())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
