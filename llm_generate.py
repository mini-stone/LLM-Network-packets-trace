# llm_generate.py
# Usage:
#   python llm_generate.py --prompt_file prompts/scenario.txt \
#                          --readme README.md \
#                          --out generated/trace_001.json
#   (optional) --fewshot baseline/demo_json/http_get_demo.json
# Env:
#   pip install google-generativeai
#   setx GOOGLE_API_KEY "xxxxx"  (Windows) / export GOOGLE_API_KEY=xxxxx

import os, re, json, argparse, textwrap
from pathlib import Path
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()  # 自动读取 .env 文件里的内容

def read_file(path: str) -> str:
    if not path: return ""
    p = Path(path)
    return p.read_text(encoding="utf-8") if p.exists() else ""

def extract_schema_from_readme(readme: str) -> str:
    """
    尽量从 README 中抓到你那段字段定义和规则。
    - 优先抓 ``` fenced code block 里包含 "timestamp"/"protocol"/"src_ip" 的块
    - 其次抓出包含这些关键字段的大括号片段
    - 再次抓出包含 'SYN' 'ACK' 等规则行
    """
    # 1) fenced code blocks
    code_blocks = re.findall(r"```(?:json|markdown|[\w-]*)\s*([\s\S]*?)```", readme, flags=re.I)
    for b in code_blocks:
        if all(k in b for k in ["timestamp", "protocol", "src_ip", "dst_ip", "src_port", "dst_port", "flags", "seq", "ack", "payload"]):
            return b.strip()

    # 2) plain brace block
    m = re.search(r"\{\s*\"timestamp\".*?\"payload\".*?\}", readme, flags=re.S)
    brace = m.group(0).strip() if m else ""

    # 3) rules lines (handshake, increasing timestamps, etc.)
    rules_lines = []
    for line in readme.splitlines():
        if any(key in line for key in [
            "SYN", "SYN-ACK", "ACK", "PSH", "FIN", "RST",
            "strictly increasing", "state", "handshake", "SEQ/ACK", "TCP only",
            "JSON array", "no explanations"
        ]):
            rules_lines.append(line.strip())
    rules = "\n".join(rules_lines[-30:])  # keep last ~30 lines w/ rules

    # 合成一个最小“权威约束”
    parts = []
    if brace:
        parts.append(brace)
    if rules:
        parts.append("\nRules excerpt:\n" + rules)
    return "\n".join(parts).strip()

def build_prompt(readme_path: str, scenario_path: str, fewshot_json: str | None) -> str:
    readme = read_file(readme_path)
    scenario = read_file(scenario_path)
    schema_or_rules = extract_schema_from_readme(readme)

    # 兜底的硬约束（防止 README 里没写清）
    fallback_constraints = textwrap.dedent("""
    Output ONLY a valid JSON array of TCP packets. Each element must include:
    {"timestamp": float, "protocol": "TCP", "src_ip": "string", "dst_ip": "string",
     "src_port": int, "dst_port": int, "flags": "string", "seq": int, "ack": int, "payload": "string"}
    Constraints: TCP only; timestamps strictly increasing; follow SYN→SYN-ACK→ACK→PSH/ACK→FIN/ACK; SEQ/ACK consistent.
    """).strip()

    fewshot = ""
    if fewshot_json:
        try:
            demo = json.loads(read_file(fewshot_json))
            if isinstance(demo, list):
                fewshot = "\n\nFew-shot example:\n" + json.dumps(demo, indent=2)
        except Exception:
            pass

    prompt = []
    prompt.append("You are a network packet trace generator. Produce ONLY a JSON array, no prose.")
    if schema_or_rules:
        prompt.append("\n[README constraints] (authoritative)\n" + schema_or_rules)
    else:
        prompt.append("\n[Fallback constraints]\n" + fallback_constraints)
    if scenario:
        prompt.append("\n[Scenario]\n" + scenario)
    if fewshot:
        prompt.append(fewshot)
    prompt.append("\nReturn ONLY the JSON array.")
    return "\n".join(prompt)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt_file", required=True, help="Scenario text (your external prompt).")
    ap.add_argument("--readme", required=True, help="README.md path used as authoritative constraints.")
    ap.add_argument("--out", required=True, help="Output JSON file.")
    ap.add_argument("--fewshot", default=None, help="Optional few-shot JSON.")
    ap.add_argument("--model", default="gemini-1.5-flash")
    ap.add_argument("--temperature", type=float, default=0.0)
    args = ap.parse_args()

    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel(
        model_name=args.model,
        generation_config={
            "temperature": args.temperature,
            "response_mime_type": "application/json",
        },
        system_instruction=(
            "Generate realistic TCP-only packet traces that follow protocol logic. "
            "Obey README constraints. Output must be a JSON array only."
        ),
    )

    prompt_text = build_prompt(args.readme, args.prompt_file, args.fewshot)
    resp = model.generate_content(prompt_text)
    packets = json.loads(resp.text)  # expect pure JSON

    Path(Path(args.out).parent).mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(packets, f, indent=2)
    print(f"✅ Saved JSON trace → {args.out} (packets={len(packets)})")

if __name__ == "__main__":
    main()
