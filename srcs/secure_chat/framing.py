"""Đóng khung thông điệp trên TCP: [4 byte độ dài big-endian][JSON UTF-8].

Dùng chung cho client (socket đồng bộ) và server (asyncio)."""
from __future__ import annotations

import asyncio
import json
import socket
import struct

MAX_FRAME = 1 << 20  # 1 MiB: chặn tấn công cạn bộ nhớ


class FrameError(Exception):
    pass


def encode_frame(obj: dict) -> bytes:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise FrameError("Frame quá lớn")
    return struct.pack(">I", len(data)) + data


def _decode(data: bytes) -> dict:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FrameError("Frame không phải JSON hợp lệ") from e
    if not isinstance(obj, dict):
        raise FrameError("Frame phải là JSON object")
    return obj


# ------------------------------------------------------------ socket đồng bộ (client)
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối đã đóng")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, obj: dict) -> None:
    sock.sendall(encode_frame(obj))


def recv_frame(sock: socket.socket) -> dict:
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise FrameError("Frame vượt quá giới hạn")
    return _decode(_recv_exact(sock, n))


# ------------------------------------------------------------ asyncio (server)
async def read_frame(reader: asyncio.StreamReader) -> dict:
    (n,) = struct.unpack(">I", await reader.readexactly(4))
    if n > MAX_FRAME:
        raise FrameError("Frame vượt quá giới hạn")
    return _decode(await reader.readexactly(n))


async def write_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    writer.write(encode_frame(obj))
    await writer.drain()
