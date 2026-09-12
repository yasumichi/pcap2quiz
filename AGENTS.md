# AGENTS.md - pcap2quiz 設計・開発仕様書

## 1. 概要
`pcap2quiz` は、PCAPファイルからネットワークトラフィック情報を解析・要約し、LLM（Ollama経由の Gemma 等）を活用してSOC（Security Operations Center）アナリスト向けの選択式クイズ（HTML形式 / Aiken形式）を自動生成するツールです。

## 2. 目的・解決する課題
- **現状の課題:** 
  - LLMへ直接HTML出力させるとMarkdownコードブロックや不要な解説が混入し、直接閲覧・実行可能なHTMLファイルが正常に生成されない。
  - パケット単位のサマリだけでは背景となるインシデントシナリオを模したクイズ生成が難しい。
- **解決アプローチ:**
  - LLMからの応答は **Structured Output (JSON形式)** でクイズ構造体のみを取得する。
  - 取得したJSONデータに基づき、Python側で標準テンプレートを用いて完全な「インタラクティブHTML」または「Moodle向けAiken形式テキスト」を出力する。
  - PCAP解析時にパケット詳細だけでなく「通信フロー統計（IP/DNS/HTTP集計）」を抽出し、質の高い問題を作成する。

## 3. システムアーキテクチャ・処理フロー

1. **PCAP Analysis (PyShark):**
   - PCAPファイルを読み込み、基本統計（IPペア、通信ポート、DNSクエリ一覧、HTTP/TLS/SMBセッション概要）を抽出。
   - トラフィックの「要約プロンプトテキスト」を生成。
2. **Quiz Generation (Ollama API):**
   - `ollama.chat` または `ollama.generate` を使用し、JSON Schema 形式でクイズデータ構造を指定して送信。
   - 出力モデル例: `gemma2`, `gemma:4` 等。
3. **Rendering & Export:**
   - 応答のJSONオブジェクトを検証・パース。
   - **HTML形式:** Tailwind CSS / Vanilla JS を埋め込んだSOC風ダークモードテンプレートにJSONデータを埋め込み、独立した1つのHTMLファイルを出力。
   - **Aiken形式:** Moodle等で直接インポート可能なテキストフォーマットに変換して出力。

## 4. クイズデータ構造 (JSON Schema)

LLMへ要求する出力データフォーマットは以下の構造とします。

```json
{
  "title": "SOC演習クイズ",
  "description": "PCAP解析に基づく実践クイズ",
  "questions": [
    {
      "id": 1,
      "question": "問題文（例: 192.168.1.10から送信された不審なDNSクエリはどれか）",
      "options": {
        "A": "選択肢1",
        "B": "選択肢2",
        "C": "選択肢3",
        "D": "選択肢4"
      },
      "answer": "A",
      "explanation": "詳細な解説（なぜそれが正解か、どのようなログ・プロトコル特性に基づくか）"
    }
  ]
}
```

## 5. 主要コンポーネント仕様

### 5.1. PCAP Analyzer (`extract_pcap_summary`)
- パケット上限数 (`--max-packets`, デフォルト 500)
- 抽出対象情報:
  - Top Talkers (通信量の多いIPアドレスペア)
  - DNS Query 名・レスポンス一覧
  - HTTP リクエスト (Method, URI, User-Agent, Host)
  - TLS SNI (Server Name Indication)
  - 特徴的なTCP/UDP通信

### 5.2. Quiz Engine (`generate_quiz`)
- Ollama API 呼び出し
- システムプロンプト: SOC Tier 1/2 アナリスト向けの問題作成ロールプレイ
- `format="json"` を指定し、パースエラーの防止と構造化出力を担保

### 5.3. Exporter (`render_html`, `render_aiken`)
- **HTML Render:** 
  - インタラクティブ機能（選択肢のクリック判定、スコア集計、解説アコーディオン表示、再挑戦ボタン）。
  - シングルファイル（HTML内にCSS/JSを含む）で動作。
- **Aiken Render:**
  - Aiken標準形式（問題文 -> A)〜D) -> ANSWER: X -> 空行）に準拠。

## 6. コマンドライン引数 (CLI) 仕様

```bash
python pcap2quiz.py <pcap_file> [options]

Options:
  -f, --format {html,aiken}   出力形式 (デフォルト: html)
  -m, --model MODEL           使用するOllamaモデル名 (デフォルト: gemma:4)
  -n, --num-questions INT     生成する問題数 (デフォルト: 10)
  -o, --output PATH           出力ファイルパス
  --max-packets INT           解析する最大パケット数 (デフォルト: 500)
```

## 7. 今後の拡張・改善案
- [ ] クイズ難易度の指定オプション（Tier 1 初級 / Tier 2 中級など）
- [ ] Jinja2 等のテンプレートエンジン導入によるデザインカスタマイズ
- [ ] インシデントストーリー（攻撃シナリオ）を意識した問題構成プロンプトの調整
