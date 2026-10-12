"""Đóng gói bài nộp theo đúng cấu trúc đề bài:

  Assigment1.zip
  ├── README.doc   (từ README.md)
  ├── srcs/        (mã nguồn)
  ├── refs/        (tài liệu tham khảo)
  └── report/      (báo cáo kỹ thuật Word/PDF + docs/PROTOCOL.md, nếu có)

Chạy (từ thư mục srcs/):  python -m tools.package_submission
Kết quả: <gốc dự án>/dist/Assigment1.zip  (thư mục dist/ được sinh tự động, không commit).
"""
from __future__ import annotations

import shutil
import sys
import zipfile
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parents[2]  # e2e_chat/
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", "data", "*.part")


def package() -> Path:
    dist = ROOT / "dist"
    stage = dist / "Assigment1"
    if dist.exists():
        shutil.rmtree(dist)
    stage.mkdir(parents=True)

    shutil.copytree(ROOT / "srcs", stage / "srcs", ignore=IGNORE)
    shutil.copytree(ROOT / "refs", stage / "refs", ignore=IGNORE)
    shutil.copy2(ROOT / "README.md", stage / "README.doc")
    if (ROOT / "report").exists():
        shutil.copytree(ROOT / "report", stage / "report", ignore=IGNORE)
    if (ROOT / "docs").exists():
        (stage / "report").mkdir(exist_ok=True)
        for f in (ROOT / "docs").iterdir():
            shutil.copy2(f, stage / "report" / f.name)

    zip_path = dist / "Assigment1.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(dist))
    print(f"[✓] Đã tạo {zip_path}")
    return zip_path


if __name__ == "__main__":
    package()
