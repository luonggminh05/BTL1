"""Cấu hình nhóm: MSSV -> chuỗi Hello + khóa khởi tạo (KDF).

Yêu cầu đề bài:
  * Plaintext của Handshake PHẢI chứa:  "Hello, We are [MSSV_1], [MSSV_2], ..."
  * Khóa khởi tạo:                      Key = SHA256(MSSV_1 || MSSV_2 || ...)
    ('||' là phép NỐI CHUỖI, nối trực tiếp chuỗi ASCII, không có dấu phân cách,
     đúng thứ tự khai báo. Cả hai phía phải khai báo MSSV cùng thứ tự.)
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

_MSSV_RE = re.compile(r"^\d{6,10}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class GroupConfig:
    mssv: tuple[str, ...]

    def __post_init__(self):
        if not self.mssv:
            raise ConfigError("Cần ít nhất 1 MSSV.")
        for m in self.mssv:
            if not _MSSV_RE.match(m):
                raise ConfigError(f"MSSV không hợp lệ: {m!r} (chỉ gồm 6-10 chữ số).")
        if len(set(self.mssv)) != len(self.mssv):
            raise ConfigError("MSSV bị trùng lặp.")

    @property
    def hello(self) -> str:
        """Chuỗi bắt buộc trong Handshake: 'Hello, We are 2411508, 2312075'."""
        return "Hello, We are " + ", ".join(self.mssv)

    @property
    def initial_key(self) -> bytes:
        """K0 = SHA256(MSSV_1 || MSSV_2 || ...)  (32 byte)."""
        return hashlib.sha256("".join(self.mssv).encode("ascii")).digest()


def parse_mssv(items: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    for it in items:
        out += [x for x in re.split(r"[,\s;|]+", it.strip()) if x]
    return tuple(out)


def load_group(cli_values: Sequence[str] | None = None, mssv_file: str = "mssv.txt") -> GroupConfig:
    """Thứ tự ưu tiên: tham số CLI > biến môi trường E2E_MSSV > file mssv.txt."""
    if cli_values:
        return GroupConfig(parse_mssv(cli_values))
    env = os.environ.get("E2E_MSSV")
    if env:
        return GroupConfig(parse_mssv([env]))
    if os.path.isfile(mssv_file):
        with open(mssv_file, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        return GroupConfig(parse_mssv(lines))
    raise ConfigError("Chưa cấu hình MSSV: dùng --mssv 2411508 2312075, biến E2E_MSSV hoặc file mssv.txt")
