"""Truyền tệp theo từng khối (chunk) qua kênh đã mã hóa.

Mọi gói (OFFER/CHUNK/END) đều là bản ghi AES-GCM của Session nên tự động có bảo mật + toàn vẹn
+ đúng thứ tự. Ngoài ra bên nhận kiểm tra SHA-256 của toàn bộ tệp (đã gửi trong OFFER được mã hóa).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Iterator

from . import crypto

CHUNK_SIZE = 32 * 1024
MAX_FILE_SIZE = 256 * 1024 * 1024
MAX_ACTIVE = 4
ID_LEN = 16


class TransferError(Exception):
    pass


def sanitize_filename(name: str) -> str:
    """Chống path traversal: chỉ giữ tên tệp, bỏ ký tự điều khiển / ký tự cấm."""
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "_", name).strip(" .")
    if not name or name in (".", ".."):
        name = "file.bin"
    return name[:200]


def _unique_path(directory: str, name: str) -> str:
    base, ext = os.path.splitext(name)
    path = os.path.join(directory, name)
    i = 1
    while os.path.exists(path):
        path = os.path.join(directory, f"{base} ({i}){ext}")
        i += 1
    return path


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


class OutgoingFile:
    def __init__(self, path: str):
        if not os.path.isfile(path):
            raise TransferError(f"Không tìm thấy tệp: {path}")
        self.path = path
        self.size = os.path.getsize(path)
        if self.size > MAX_FILE_SIZE:
            raise TransferError("Tệp vượt quá giới hạn kích thước")
        self.id = crypto.random_bytes(ID_LEN)
        self.name = sanitize_filename(os.path.basename(path))
        self.sha256 = sha256_file(path)

    def offer_body(self) -> bytes:
        return json.dumps(
            {"id": self.id.hex(), "name": self.name, "size": self.size, "sha256": self.sha256}
        ).encode("utf-8")

    def chunks(self) -> Iterator[bytes]:
        with open(self.path, "rb") as f:
            idx = 0
            while True:
                blk = f.read(CHUNK_SIZE)
                if not blk:
                    break
                yield self.id + idx.to_bytes(4, "big") + blk
                idx += 1

    def end_body(self) -> bytes:
        return self.id


class _Incoming:
    def __init__(self, tmp_path: str, final_dir: str, name: str, size: int, sha: str):
        self.tmp_path, self.final_dir, self.name, self.size, self.sha = tmp_path, final_dir, name, size, sha
        self.received = 0
        self.next_idx = 0
        self.hasher = hashlib.sha256()
        self.fh = open(tmp_path, "wb")

    def abort(self) -> None:
        try:
            self.fh.close()
        finally:
            if os.path.exists(self.tmp_path):
                os.remove(self.tmp_path)


class IncomingFiles:
    def __init__(self, base_dir: str, max_size: int = MAX_FILE_SIZE):
        self.base_dir = base_dir
        self.max_size = max_size
        self._active: dict[tuple[str, bytes], _Incoming] = {}

    def on_offer(self, peer: str, body: bytes) -> dict:
        try:
            meta = json.loads(body.decode("utf-8"))
            fid = bytes.fromhex(meta["id"])
            size, sha, name = meta["size"], meta["sha256"], meta["name"]
        except Exception as e:  # noqa: BLE001
            raise TransferError("OFFER sai định dạng") from e
        if len(fid) != ID_LEN or not isinstance(size, int) or not (0 <= size <= self.max_size):
            raise TransferError("OFFER: id/kích thước không hợp lệ")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha) or not isinstance(name, str):
            raise TransferError("OFFER: sha256/tên tệp không hợp lệ")
        if (peer, fid) in self._active:
            raise TransferError("OFFER trùng id")
        if sum(1 for k in self._active if k[0] == peer) >= MAX_ACTIVE:
            raise TransferError("Quá nhiều tệp đang nhận đồng thời")
        pdir = os.path.join(self.base_dir, peer)
        os.makedirs(pdir, exist_ok=True)
        safe = sanitize_filename(name)
        tmp = os.path.join(pdir, f".{fid.hex()}.part")
        self._active[(peer, fid)] = _Incoming(tmp, pdir, safe, size, sha)
        return {"name": safe, "size": size}

    def on_chunk(self, peer: str, body: bytes) -> int:
        if len(body) < ID_LEN + 4:
            raise TransferError("CHUNK quá ngắn")
        fid, idx, data = body[:ID_LEN], int.from_bytes(body[ID_LEN : ID_LEN + 4], "big"), body[ID_LEN + 4 :]
        st = self._active.get((peer, fid))
        if st is None:
            raise TransferError("CHUNK cho tệp chưa OFFER")
        try:
            if idx != st.next_idx:
                raise TransferError("CHUNK sai thứ tự")
            if st.received + len(data) > st.size:
                raise TransferError("Nhận vượt quá kích thước đã khai báo")
            st.fh.write(data)
            st.hasher.update(data)
            st.received += len(data)
            st.next_idx += 1
        except TransferError:
            st.abort()
            del self._active[(peer, fid)]
            raise
        return st.received

    def on_end(self, peer: str, body: bytes) -> dict:
        if len(body) != ID_LEN:
            raise TransferError("END sai định dạng")
        st = self._active.pop((peer, body), None)
        if st is None:
            raise TransferError("END cho tệp chưa OFFER")
        st.fh.close()
        if st.received != st.size or st.hasher.hexdigest() != st.sha:
            st.abort()
            raise TransferError("Tệp nhận được KHÔNG khớp SHA-256/kích thước đã khai báo -> đã hủy")
        final = _unique_path(st.final_dir, st.name)
        os.replace(st.tmp_path, final)
        return {"path": final, "name": os.path.basename(final), "size": st.size, "sha256": st.sha}

    def abort_peer(self, peer: str) -> None:
        for key in [k for k in self._active if k[0] == peer]:
            self._active.pop(key).abort()
