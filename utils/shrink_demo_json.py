#!/usr/bin/env python3
"""
utils/shrink_demo_json.py

把 baseline/demo/ 下很大的 baseline JSON
裁剪成适合给 LLM 当示例的小型 JSON。

输入:
    baseline/demo/*.json   # 现在这些是 20MB 巨大文件

输出:
    baseline/demo_small/<同名>.json   # 只保留前 MAX_PACKETS 个 packet
"""

from pathlib import Path
import json
from typing import List, Dict, Any

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "baseline" / "demo"
OUT_DIR = ROOT / "baseline" / "demo_small"

MAX_PACKETS = 200   # 给 LLM 当 example，用 100~300 都够了


def shrink_one(src: Path, dst: Path) -> None:
    with src.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"{src} is not a JSON list")

    trimmed: List[Dict[str, Any]] = data[:MAX_PACKETS]

    dst.write_text(json.dumps(trimmed, indent=2), encoding="utf-8")
    print(f"[info] {src.name}: {len(data)} -> {len(trimmed)} packets  =>  {dst}")


def main() -> None:
    if not DEMO_DIR.is_dir():
        raise SystemExit(f"demo dir not found: {DEMO_DIR}")

    OUT_DIR.mkdir(exist_ok=True)

    json_files = sorted(DEMO_DIR.glob("*.json"))
    if not json_files:
        raise SystemExit(f"No .json files found in {DEMO_DIR}")

    print(f"[info] Found {len(json_files)} JSON baseline files")

    for src in json_files:
        dst = OUT_DIR / src.name
        shrink_one(src, dst)

    print("[done] All demo JSON files shrunk.")


if __name__ == "__main__":
    main()
