import argparse
import asyncio
import json
import sys
from collections import Counter
import pyshark
import ollama

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

    ip_pairs = Counter()
    dns_queries = Counter()
    http_requests = []
    tls_snis = Counter()
    smb_commands = Counter()
    general_summary = []

    packet_count = 0

    for pkt in cap:
        packet_count += 1
        if packet_count > max_packets:
            break

        try:
            highest_layer = pkt.highest_layer
            src_ip = getattr(pkt.ip, 'src', 'N/A') if hasattr(pkt, 'ip') else 'N/A'
            dst_ip = getattr(pkt.ip, 'dst', 'N/A') if hasattr(pkt, 'ip') else 'N/A'
            
            if src_ip != 'N/A' and dst_ip != 'N/A':
                ip_pairs[f"{src_ip} -> {dst_ip}"] += 1

            # 1. DNS
            if hasattr(pkt, 'dns'):
                if hasattr(pkt.dns, 'qry_name'):
                    dns_queries[pkt.dns.qry_name] += 1

            # 2. HTTP
            elif hasattr(pkt, 'http'):
                method = getattr(pkt.http, 'request_method', '')
                uri = getattr(pkt.http, 'request_full_uri', getattr(pkt.http, 'request_uri', ''))
                host = getattr(pkt.http, 'host', '')
                ua = getattr(pkt.http, 'user_agent', '')
                if uri or host:
                    http_requests.append(f"{method} {host}{uri} (UA: {ua})".strip())

            # 3. TLS/SSL
            elif hasattr(pkt, 'tls') or hasattr(pkt, 'ssl'):
                tls_layer = pkt.tls if hasattr(pkt, 'tls') else pkt.ssl
                sni = getattr(tls_layer, 'handshake_extensions_server_name', '')
                if sni:
                    tls_snis[sni] += 1

            # 4. SMB
            elif hasattr(pkt, 'smb') or hasattr(pkt, 'smb2'):
                smb_cmd = getattr(pkt.smb2, 'cmd', getattr(pkt, 'smb', {}).get('cmd', 'Command'))
                smb_commands[smb_cmd] += 1

            # パケットサンプル概要
            if len(general_summary) < 50:
                src_port = getattr(pkt[pkt.transport_layer], 'srcport', '') if hasattr(pkt, 'transport_layer') else ''
                dst_port = getattr(pkt[pkt.transport_layer], 'dstport', '') if hasattr(pkt, 'transport_layer') else ''
                port_info = f":{src_port} -> :{dst_port}" if src_port and dst_port else ""
                general_summary.append(f"#{packet_count} {highest_layer} | {src_ip}{port_info} -> {dst_ip}")

        except Exception:
            continue

    cap.close()

    if packet_count == 0:
        print("[!] 解析可能なパケットデータが存在しませんでした。")
        sys.exit(1)

    summary_text = f"--- 解析概要 (総処理パケット数: {packet_count}) ---\n"
    
    summary_text += "\n[Top IP Traffic Pairs]\n"
    for pair, count in ip_pairs.most_common(10):
        summary_text += f"- {pair}: {count} packets\n"

    if dns_queries:
        summary_text += "\n[DNS Queries]\n"
        for qname, count in dns_queries.most_common(15):
            summary_text += f"- {qname}: {count} times\n"

    if http_requests:
        summary_text += "\n[HTTP Requests (Sample)]\n"
        for req in http_requests[:15]:
            summary_text += f"- {req}\n"

    if tls_snis:
        summary_text += "\n[TLS Server Name Indication (SNI)]\n"
        for sni, count in tls_snis.most_common(10):
            summary_text += f"- {sni}: {count} times\n"

    if smb_commands:
        summary_text += "\n[SMB Commands]\n"
        for cmd, count in smb_commands.most_common(10):
            summary_text += f"- {cmd}: {count} times\n"

    summary_text += "\n[Packet Flow Sample]\n"
    summary_text += "\n".join(general_summary[:30])

    return summary_text


def generate_quiz_with_ollama(summary_text, num_questions=10, model_name="gemma:4"):
    """
    Ollama経由でJSON Schemaに従ってクイズデータを構造化出力として取得
    """
    print(f"[*] Ollama ({model_name}) にてクイズデータ (JSON) を生成中...")

    prompt = f"""
あなたはSOC（Security Operations Center）のシニアインシデントアナリストです。
提示されたPCAPキャプチャ解析サマリを客観的に評価し、Tier 1 / Tier 2 アナリスト向けの実践的な選択式クイズを {num_questions} 問作成してください。

【重要：客観的解析とハルシネーション防止の絶対遵守事項】
1. **事実のみに基づく解析:** PCAPサマリに含まれる客観的事実（IP、ポート、ドメイン名、プロトコル、通信回数等）のみに基づいて問題を作成してください。存在しない攻撃やシナリオ、ログを捏造・推測しないでください。
2. **正常トラフィックに対する制限 (最重要):**
   - **明確な攻撃や異常（不正ドメイン、既知の攻撃シグネチャ等）が確認できない通信を「攻撃」「攻撃の準備」「偵察」「攻撃の前兆」「不審な通信」と決めつけることを厳密に禁止します。**
   - 正常なWeb閲覧、DNS問い合わせ、標準的なTLS通信などについては、無理にインシデントと結びつけず、以下のような「正常通信のプロトコル仕様理解や分析手順」を問う問題を作成してください：
     - 通信を行っている主要なIPアドレス、ドメイン名、提供サービスの特定
     - 正常なプロトコル挙動（DNSレコード、HTTPメソッド/ステータスコード、TLS SNI等）の理解
     - 「なぜこの通信を正常と判断できるか」「どのような観点から誤検知（False Positive）を防ぐか」の分析手順
3. **誤検知（False Positive）防止の教育視点:** SOCアナリストとして、一般的な日常通信を過剰にアラート化（過検知）しないための知識・確認手法を問う選択肢と解説を用意してください。

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


def render_html(quiz_data):
    """
    クイズデータからダークモードスタイルのインタラクティブHTMLを生成
    """
    title = quiz_data.get("title", "SOC演習クイズ")
    description = quiz_data.get("description", "PCAP解析に基づく実践クイズ")
    questions_json = json.dumps(quiz_data.get("questions", []), ensure_ascii=False)

    html_template = f"""<!DOCTYPE html>
<html lang="ja" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        soc: {{
                            bg: '#0f172a',
                            card: '#1e293b',
                            border: '#334155',
                            accent: '#38bdf8',
                            correct: '#22c55e',
                            incorrect: '#ef4444'
                        }}
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
    </style>
</head>
<body class="min-h-screen p-4 md:p-8">
    <div class="max-w-4xl mx-auto space-y-6">
        <!-- Header -->
        <header class="bg-soc-card border border-soc-border rounded-xl p-6 shadow-xl">
            <div class="flex items-center space-x-3 mb-2">
                <span class="px-3 py-1 bg-sky-500/20 text-sky-400 text-xs font-semibold rounded-full border border-sky-500/30">SOC Training</span>
                <span class="text-xs text-slate-400">PCAP Analysis Quiz</span>
            </div>
            <h1 class="text-2xl md:text-3xl font-bold text-slate-100">{title}</h1>
            <p class="text-slate-400 text-sm mt-2">{description}</p>
            <div id="score-banner" class="hidden mt-4 p-4 bg-slate-800/80 rounded-lg border border-slate-700 flex justify-between items-center">
                <div>
                    <span class="text-sm text-slate-400">最終スコア: </span>
                    <span id="score-text" class="text-2xl font-bold text-sky-400">0 / 0</span>
                </div>
                <button onclick="resetQuiz()" class="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium rounded-lg transition">再挑戦</button>
            </div>
        </header>

        <!-- Quiz Container -->
        <div id="quiz-container" class="space-y-6"></div>
    </div>

    <script>
        const quizData = {questions_json};
        const userAnswers = {{}};

        function renderQuestions() {{
            const container = document.getElementById('quiz-container');
            container.innerHTML = '';

            quizData.forEach((q, idx) => {{
                const qNum = idx + 1;
                const card = document.createElement('div');
                card.className = 'bg-soc-card border border-soc-border rounded-xl p-6 shadow-lg space-y-4';
                card.id = `question-${{q.id}}`;

                let optionsHtml = '';
                for (const [key, val] of Object.entries(q.options)) {{
                    optionsHtml += `
                        <button onclick="selectOption(${{q.id}}, '${{key}}')" 
                                id="opt-${{q.id}}-${{key}}"
                                class="option-btn w-full text-left p-4 rounded-lg border border-slate-700 bg-slate-800/50 hover:bg-slate-700/50 hover:border-slate-500 transition flex items-start space-x-3">
                            <span class="font-bold text-sky-400 px-2.5 py-0.5 bg-sky-950/60 rounded border border-sky-800/50">${{key}}</span>
                            <span class="text-slate-200">${{val}}</span>
                        </button>
                    `;
                }}

                card.innerHTML = `
                    <div class="flex justify-between items-start">
                        <h3 class="text-lg font-semibold text-slate-100 flex items-start">
                            <span class="text-sky-400 font-bold mr-2">Q${{qNum}}.</span>
                            <span>${{q.question}}</span>
                        </h3>
                    </div>
                    <div class="space-y-2 mt-4">
                        ${{optionsHtml}}
                    </div>
                    <div id="exp-${{q.id}}" class="hidden mt-4 p-4 rounded-lg bg-slate-900/80 border border-slate-700 text-sm space-y-2">
                        <div id="result-tag-${{q.id}}" class="font-bold"></div>
                        <div class="text-slate-300"><span class="font-semibold text-slate-400">解説: </span>${{q.explanation}}</div>
                    </div>
                `;
                container.appendChild(card);
            }});
        }}

        function selectOption(qId, selectedKey) {{
            const question = quizData.find(q => q.id === qId);
            if (!question) return;

            userAnswers[qId] = selectedKey;

            // ボタンの状態を更新
            ['A', 'B', 'C', 'D'].forEach(key => {{
                const btn = document.getElementById(`opt-${{qId}}-${{key}}`);
                if (!btn) return;
                btn.disabled = true;
                btn.classList.remove('hover:bg-slate-700/50', 'hover:border-slate-500');

                if (key === question.answer) {{
                    btn.classList.add('bg-emerald-950/60', 'border-emerald-500', 'text-emerald-300');
                }} else if (key === selectedKey && selectedKey !== question.answer) {{
                    btn.classList.add('bg-rose-950/60', 'border-rose-500', 'text-rose-300');
                }} else {{
                    btn.classList.add('opacity-50');
                }}
            }});

            // 解説を表示
            const expDiv = document.getElementById(`exp-${{qId}}`);
            const tagDiv = document.getElementById(`result-tag-${{qId}}`);
            expDiv.classList.remove('hidden');

            if (selectedKey === question.answer) {{
                tagDiv.className = 'text-emerald-400 font-bold';
                tagDiv.textContent = '✓ 正解';
            }} else {{
                tagDiv.className = 'text-rose-400 font-bold';
                tagDiv.textContent = `✗ 不正解 (正解: ${{question.answer}})`;
            }}

            checkScore();
        }}

        function checkScore() {{
            if (Object.keys(userAnswers).length === quizData.length) {{
                let correctCount = 0;
                quizData.forEach(q => {{
                    if (userAnswers[q.id] === q.answer) correctCount++;
                }});

                const banner = document.getElementById('score-banner');
                const scoreText = document.getElementById('score-text');
                scoreText.textContent = `${{correctCount}} / ${{quizData.length}}`;
                banner.classList.remove('hidden');
                banner.scrollIntoView({{ behavior: 'smooth' }});
            }}
        }}

        function resetQuiz() {{
            for (let member in userAnswers) delete userAnswers[member];
            document.getElementById('score-banner').classList.add('hidden');
            renderQuestions();
            window.scrollTo({{ top: 0, behavior: 'smooth' }});
        }}

        document.addEventListener('DOMContentLoaded', renderQuestions);
    </script>
</body>
</html>
"""
    return html_template


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

    summary = extract_pcap_summary(args.pcap, max_packets=args.max_packets)
    quiz_data = generate_quiz_with_ollama(summary, num_questions=args.num_questions, model_name=args.model)

    if args.format == "html":
        output_content = render_html(quiz_data)
        ext = "html"
    else:
        output_content = render_aiken(quiz_data)
        ext = "txt"

    output_filename = args.output if args.output else f"soc_quiz.{ext}"

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(output_content)

    print(f"[+] クイズファイルを正常に生成しました: {output_filename}")


if __name__ == "__main__":
    main()
