# 変更履歴 (History)

## [2026-09-12] - v1.0.0
### 変更・改善概要
`pcap2quiz.py` のアーキテクチャおよび機能改修を実施。LLMからの直描HTML出力に伴うパース失敗・崩れ問題を解消し、Structured Output (JSON) 方式および事前テンプレートレンダリング方式へ全面移行。

### 追加・変更点

1. **仕様定義ドキュメントの作成 (`AGENTS.md`)**
   - システムアーキテクチャ、処理フロー、JSON Schema、各コンポーネント仕様、CLIインターフェースを定義。

2. **Ollama 構造化出力 (Structured Output) への対応**
   - JSON Schema 形式を定義し `ollama.chat(format=QUIZ_JSON_SCHEMA)` で呼び出す仕様に変更。
   - LLMからの応答失敗や Markdown コードブロックの混入を防止し、確実にパース可能なJSONデータを取得。

3. **PCAP 解析サマリ抽出の強化 (`extract_pcap_summary`)**
   - 通信フロー統計およびプロトコル別集計処理を実装:
     - Top Talkers (通信量の多い IP アドレスペア)
     - DNS Query リクエスト一覧・集計
     - HTTP Request (Method, Host/URI, User-Agent)
     - TLS/SSL SNI (Server Name Indication)
     - SMB コマンド集計
   - トラフィックの全体像をLLMに提示し、SOC実務に即した質の高い問題作成を実現。

4. **インタラクティブ HTML レンダラーの実装 (`render_html`)**
   - Tailwind CSS を活用した SOC 風ダークモードテンプレートの埋め込み。
   - 選択肢クリック時の動的正誤判定、解説表示、スコア集計、再挑戦ボタンを搭載したスタンドアロン型 HTML を生成。

5. **Moodle 向け Aiken 形式レンダラーの実装 (`render_aiken`)**
   - Aiken フォーマット準拠のテキストエクスポート機能。

6. **CLI オプションの拡充**
   - `-n, --num-questions`: 生成問題数の指定 (デフォルト: 10)
   - `-m, --model`: 使用モデルの指定 (デフォルト: `gemma:4`)
   - `--max-packets`: 解析パケット数の指定 (デフォルト: 500)
   - `-f, --format`: 出力フォーマットの指定 (`html` / `aiken`)
