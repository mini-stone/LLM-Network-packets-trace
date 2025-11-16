#!/usr/bin/env python3
"""
llm_generate.py

End-to-end pipeline for the LLM-Network-packets-trace project.

Steps:
  1) Build prompt from README + prompt.txt + baseline/demo examples
  2) Call LLM to generate JSON trace (as a string)
  3) Save JSON under generated/trace_<timestamp>.json
  4) Validate JSON trace via validator/validate_trace.py
       - If validation FAILS -> print errors and exit(1)
       - If validation PASSES -> continue
  5) Convert JSON -> PCAP using utils/json_to_pcap.py
       - Optionally provide a reference PCAP from evaluator/pcap
  6) Evaluate generated PCAP vs baseline PCAP (baseline/*.pcap)
       - Using evaluator/evaluator.py
  7) Save evaluation results under results/eval_<timestamp>.json
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List

# --- project-local imports ---
from validator.validate_trace import validate_trace_file
from utils.json_to_pcap import json_to_pcap
from evaluator.evaluator import evaluate_pcap


# -------------------- Config -------------------- #

ROOT_DIR = Path(__file__).resolve().parent
GENERATED_DIR = ROOT_DIR / "generated"
RESULTS_DIR = ROOT_DIR / "results"

BASELINE_DIR = ROOT_DIR / "baseline"
BASELINE_DEMO_DIR = BASELINE_DIR / "demo"      # you will put demo JSONs here
EVAL_PCAP_DIR = ROOT_DIR / "evaluator" / "pcap"  # reference PCAPs for conversion


# -------------------- Helpers -------------------- #

def _read_text_file(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _collect_demo_json_snippets(max_files: int = 3) -> str:
    """
    Collect a few demo JSON traces from baseline/demo (or baseline/) to
    include in the LLM prompt as in-context examples.

    We only concatenate raw JSON text; how much你让LLM读，后面可以自己再调。
    """
    snippets: List[str] = []

    # 优先使用 baseline/demo
    search_dirs = []
    if BASELINE_DEMO_DIR.is_dir():
        search_dirs.append(BASELINE_DEMO_DIR)
    if BASELINE_DIR.is_dir():
        search_dirs.append(BASELINE_DIR)

    seen = 0
    for d in search_dirs:
        for path in sorted(d.glob("*.json")):
            if seen >= max_files:
                break
            try:
                content = path.read_text(encoding="utf-8")
                snippets.append(f"// Example from {path.relative_to(ROOT_DIR)}:\n{content}")
                seen += 1
            except Exception:
                continue

    if not snippets:
        return ""

    return (
        "\n\n"
        "### Reference JSON Trace Examples (from baseline/demo)\n"
        + "\n\n".join(snippets)
    )


def build_generation_prompt() -> str:
    """
    Build the full prompt that will be sent to the LLM.

    Components:
      - README.md (project description + metrics + format)
      - prompt.txt (your hand-written instruction)
      - baseline/demo JSON examples
    """
    readme_text = _read_text_file(ROOT_DIR / "README.md")
    base_prompt = _read_text_file(ROOT_DIR / "prompt.txt")
    demo_examples = _collect_demo_json_snippets()

    parts = []

    if readme_text:
        parts.append("## Project README\n" + readme_text)

    if base_prompt:
        parts.append("\n\n## Generation Instruction (prompt.txt)\n" + base_prompt)

    if demo_examples:
        parts.append("\n\n" + demo_examples)

    final_prompt = (
        "\n\n".join(parts)
        + "\n\n"
        "### Task\n"
        "You must output ONLY a JSON array of packet objects in the format described above.\n"
        "Do NOT include any additional explanation, comments, or markdown.\n"
    )
    return final_prompt


def call_llm_to_generate_trace(full_prompt: str) -> str:
    """
    实际 LLM 调用在这里实现。

    目前先留一个占位，你可以根据自己用的模型（Gemini / OpenAI / Llama等）
    把 API 调用写进来，最后返回“JSON 字符串”。

    例如（伪代码）：
        import google.generativeai as genai
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        model = genai.GenerativeModel("gemini-1.5-pro")
        resp = model.generate_content(full_prompt)
        return resp.text

    这里先抛异常，防止误调用。
    """
    raise NotImplementedError(
        "Implement LLM API call in call_llm_to_generate_trace(full_prompt)."
    )


def _choose_baseline_pcap() -> str:
    """
    选择一个 baseline PCAP 作为 evaluation 的 real trace 参考。

    优先顺序：
      1) baseline/sample.pcap
      2) baseline/*.pcap 中第一个
    """
    sample = BASELINE_DIR / "sample.pcap"
    if sample.is_file():
        return str(sample)

    for p in sorted(BASELINE_DIR.glob("*.pcap")):
        return str(p)

    raise FileNotFoundError("No baseline .pcap found under baseline/ directory.")


def _choose_reference_pcap_for_conversion() -> str | None:
    """
    在做 JSON->PCAP 转化时，如果你想参考已有 PCAP 的格式，
    可以从 evaluator/pcap 目录里选一个作为参考，传给 json_to_pcap。

    如果没有就返回 None。
    """
    if not EVAL_PCAP_DIR.is_dir():
        return None

    for p in sorted(EVAL_PCAP_DIR.glob("*.pcap")):
        return str(p)

    return None


# -------------------- Main Pipeline -------------------- #

def main() -> None:
    # 确保输出目录存在
    GENERATED_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

    # 1) 构造 prompt
    full_prompt = build_generation_prompt()

    # 2) 调 LLM 生成 JSON 字符串
    try:
        json_str = call_llm_to_generate_trace(full_prompt)
    except NotImplementedError as e:
        # 如果你还没接好 LLM，这里方便 debug
        print(f"[fatal] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[fatal] LLM generation failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 3) 存 JSON 文件（先确认它是合法 JSON）
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = GENERATED_DIR / f"trace_{ts}.json"

    try:
        data = json.loads(json_str)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[info] JSON trace written to {json_path}")
    except Exception as e:
        print(f"[fatal] Invalid JSON returned by LLM: {e}", file=sys.stderr)
        sys.exit(1)

    # 4) 调 validator：不过就直接退出
    try:
        errors = validate_trace_file(str(json_path))
    except Exception as e:
        print(f"[fatal] Validation raised an exception: {e}", file=sys.stderr)
        sys.exit(1)

    if errors:
        print("Validation FAILED. Abort pipeline.")
        print(f"Total errors: {len(errors)}")
        for err in errors:
            print(" -", err)
        sys.exit(1)

    print("Validation PASSED. Continue to JSON→PCAP + evaluation.")

    # 5) JSON -> PCAP 转换
    pcap_path = GENERATED_DIR / f"trace_{ts}.pcap"
    ref_pcap = _choose_reference_pcap_for_conversion()

    try:
        # 你的 json_to_pcap 可以定义为：
        #   json_to_pcap(json_path: str, pcap_path: str, reference_pcap: str | None = None)
        # 如果你现在只有两个参数版本，也可以先忽略 ref_pcap。
        json_to_pcap(
            json_path=str(json_path),
            pcap_path=str(pcap_path),
            reference_pcap=ref_pcap,
        )
        print(f"[info] PCAP written to {pcap_path}")
    except TypeError:
        # 兼容旧版签名 json_to_pcap(json_path, pcap_path)
        try:
            json_to_pcap(str(json_path), str(pcap_path))  # type: ignore
            print(f"[info] PCAP written to {pcap_path} (no reference PCAP used)")
        except Exception as e:
            print(f"[fatal] Failed to convert JSON to PCAP: {e}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"[fatal] Failed to convert JSON to PCAP: {e}", file=sys.stderr)
        sys.exit(1)

    # 6) Evaluation：生成 PCAP vs baseline PCAP
    try:
        baseline_pcap = _choose_baseline_pcap()
    except Exception as e:
        print(f"[fatal] Cannot find baseline PCAP for evaluation: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        metrics = evaluate_pcap(str(pcap_path), baseline_pcap)
    except Exception as e:
        print(f"[fatal] Evaluation failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 7) 保存评测结果
    result_path = RESULTS_DIR / f"eval_{ts}.json"
    try:
        result_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"[info] Evaluation results written to {result_path}")
    except Exception as e:
        print(f"[fatal] Failed to write evaluation results: {e}", file=sys.stderr)
        sys.exit(1)

    print("[done] End-to-end LLM packet trace pipeline finished.")


if __name__ == "__main__":
    main()
