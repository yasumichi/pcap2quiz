import argparse
import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from collections import Counter
import pyshark
import ollama

from parsers import get_default_manager


# --- Python 3.12+ / 3.14 互換性問題への修正パッチ ---
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda watcher: None

if not hasattr(asyncio, "SafeChildWatcher"):
    class DummyChildWatcher:
        def attach_loop(self, loop): pass
        def close(self): pass
    asyncio.SafeChildWatcher = DummyChildWatcher
# ----------------------------------------------------

QUIZ_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "questions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "question": {"type": "string"},
                    "options": {
                        "type": "object",
                        "properties": {
                            "A": {"type": "string"},
                            "B": {"type": "string"},
                            "C": {"type": "string"},
                            "D": {"type": "string"}
                        },
                        "required": ["A", "B", "C", "D"]
                    },
                    "answer": {"type": "string"},
                    "explanation": {"type": "string"}
                },
                "required": ["id", "question", "options", "answer", "explanation"]
            }
        }
    },
    "required": ["title", "description", "questions"]
}


def extract_pcap_summary(pcap_path, max_packets=500):
    """
    PCAPファイルから多角的なプロトコル情報およびフロー統計を抽出
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    print(f"[*] PCAPファイルを解析中: {pcap_path} (最大 {max_packets} パケット)")

    cap = pyshark.FileCapture(pcap_path, keep_packets=False, eventloop=loop)
    manager = get_default_manager()

    packet_count = 0

    for pkt in cap:
        packet_count += 1
        if packet_count > max_packets:
            break

        try:
            manager.process_packet(pkt)
        except Exception:
            continue

    cap.close()

    if packet_count == 0:
        print("[!] 解析可能なパケットデータが存在しませんでした。")
        sys.exit(1)

    summary_text = f"--- 解析概要 (総処理パケット数: {packet_count}) ---\n\n"
    summary_text += manager.generate_full_summary()

    return summary_text


def generate_quiz_with_ollama(summary_text, pcap_filename, num_questions=10, model_name="gemma:4"):
    """
    Ollama経由でJSON Schemaに従ってクイズデータを構造化出力として取得
    """
    print(f"[*] Ollama ({model_name}) にてクイズデータ (JSON) を生成中...")

    prompt = f"""
あなたはSOC（Security Operations Center）のアナリストです。
解析対象のPCAPファイル名: {pcap_filename}
提示された解析サマリを客観的に評価し、Tier 1 / Tier 2 アナリスト向けの実践的な選択式クイズを {num_questions} 問作成してください。

【出力仕様】
- description フィールドには、以下のフォーマットで説明を記述してください:
  "{pcap_filename} の解析サマリに含まれる事実のみに基づき、パケット解析能力とプロトコル理解を評価するための選択式クイズです。"

【重要：客観的解析とハルシネーション防止の絶対遵守事項】
1. **パケット内容から直接確認できる事実のみに基づく問題設定 (最重要):**
   - パケットキャプチャ（PCAPサマリ）に実際に含まれている事実（送信元/送信先IP、ポート番号、通信回数、DNSクエリ名、HTTPリクエストURI/User-Agent、TLS SNI、プロトコル種別等）を直接問う問題、またはそれら事実から論理的に特定できる内容に関する問題のみを作成してください。
   - **「SOCアナリストとして次に取るべき行動」「エスカレーション手順」「端末隔離の要否」など、SOC要員としての一般的行動・運用対応を問う問題は一切含めないでください。**
2. **正常トラフィックに対する制限:**
   - **明確な攻撃や異常（不正ドメイン、既知の攻撃シグネチャ等）が確認できない通信を「攻撃」「攻撃の準備」「偵察」「攻撃の前兆」「不審な通信」と決めつけることを厳密に禁止します。**
   - 正常なWeb閲覧、DNS問い合わせ、標準的なTLS通信などについては、通信されているIPアドレス、ドメイン名、リクエスト内容、標準的なプロトコル挙動などの事実確認・プロトコル理解を問う問題を作成してください。
3. **誤検知（False Positive）防止の視点:**
   - 単なる日常通信や正常なサービス通信であることをパケット情報（ドメインやURI、User-Agent等）からどう判断できるかという、パケット解析・事実確認に基づいた視点の選択肢と解説を用意してください。

【作成要件】
- 問題文、選択肢、および解説はすべて「日本語」で記述してください。
- 4つの選択肢 (A, B, C, D) のうち、正解 (answer) は 'A', 'B', 'C', 'D' のいずれか1つの文字のみを指定してください。
- 解説 (explanation) は根拠を添えて簡潔（2〜3文程度）に記載してください。

【PCAP解析サマリ】
{summary_text}
"""

    response = ollama.chat(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        format=QUIZ_JSON_SCHEMA,
        options={
            "temperature": 0.3,
            "num_predict": 8192,
            "num_ctx": 8192,
        }
    )

    content = response['message']['content']
    try:
        data = json.loads(content)
        return data
    except json.JSONDecodeError as e:
        print(f"[!] Ollamaからの応答をJSONとしてパースできませんでした: {e}")
        print("Raw Content:\n", content)
        sys.exit(1)


def render_html(quiz_data, template_path=None):
    """
    クイズデータからダークモードスタイルのインタラクティブHTMLを生成
    """
    if template_path is None:
        template_path = Path(__file__).parent / "templates" / "quiz_template.html"

    title = quiz_data.get("title", "SOC演習クイズ")
    description = quiz_data.get("description", "PCAP解析に基づく実践クイズ")
    questions_json = json.dumps(quiz_data.get("questions", []), ensure_ascii=False)

    with open(template_path, "r", encoding="utf-8") as f:
        html_template = f.read()

    return (
        html_template
        .replace("{title}", title)
        .replace("{description}", description)
        .replace("{questions_json}", questions_json)
    )


def render_aiken(quiz_data):
    """
    クイズデータからMoodle等にインポート可能なAiken形式テキストを生成
    """
    lines = []
    questions = quiz_data.get("questions", [])

    for q in questions:
        lines.append(q.get("question", ""))
        options = q.get("options", {})
        for key in ["A", "B", "C", "D"]:
            if key in options:
                lines.append(f"{key}) {options[key]}")
        answer = q.get("answer", "A").upper()
        lines.append(f"ANSWER: {answer}")
        lines.append("")  # 各問題の間の空行

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="PCAP SOCクイズ生成ツール (PyShark + Ollama JSON Output)")
    parser.add_argument("pcap", help="解析対象の PCAP ファイルパス")
    parser.add_argument("-f", "--format", choices=["html", "aiken"], default="html", help="出力フォーマット (デフォルト: html)")
    parser.add_argument("-m", "--model", default="gemma:4", help="使用するOllamaモデル名 (デフォルト: gemma:4)")
    parser.add_argument("-n", "--num-questions", type=int, default=10, help="生成する問題数 (デフォルト: 10)")
    parser.add_argument("-o", "--output", help="出力ファイルパス")
    parser.add_argument("--max-packets", type=int, default=500, help="解析する最大パケット数 (デフォルト: 500)")

    args = parser.parse_args()

    pcap_filename = os.path.basename(args.pcap)
    summary = extract_pcap_summary(args.pcap, max_packets=args.max_packets)
    quiz_data = generate_quiz_with_ollama(summary, pcap_filename=pcap_filename, num_questions=args.num_questions, model_name=args.model)

    if args.format == "html":
        output_content = render_html(quiz_data)
        ext = "html"
    else:
        output_content = render_aiken(quiz_data)
        ext = "txt"

    output_filename = args.output if args.output else f"soc_quiz.{ext}"

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(output_content)

    if args.format == "html":
        script_dir = os.path.dirname(os.path.abspath(__file__))
        src_assets = os.path.join(script_dir, "assets")
        output_dir = os.path.dirname(os.path.abspath(output_filename))
        dest_assets = os.path.join(output_dir, "assets")
        if os.path.exists(src_assets):
            os.makedirs(dest_assets, exist_ok=True)
            for item in os.listdir(src_assets):
                s = os.path.join(src_assets, item)
                d = os.path.join(dest_assets, item)
                if os.path.isfile(s):
                    shutil.copy2(s, d)

    print(f"[+] クイズファイルを正常に生成しました: {output_filename}")


if __name__ == "__main__":
    main()
