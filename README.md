# pcap2quiz

`pcap2quiz` は、PCAPファイルからネットワークトラフィック情報を自動解析・要約し、LLM（Ollama経由の Gemma 等）を活用してSOC（Security Operations Center）アナリスト向けの選択式演習クイズを自動生成するツールです。

出力フォーマットとして、ブラウザで即座に動作する**インタラクティブなHTML**およびMoodle等のLMSでインポート可能な**Aiken形式テキスト**に対応しています。

---

## 主な特徴

- 🔍 **多角的なPCAPトラフィック解析**
  - PyShark を利用し、Top Talkers（IPペア）、DNSクエリ、HTTPリクエスト、TLS SNI、SMBコマンド等のフロー統計を抽出。
- 🤖 **Structured Output (JSON) による高信頼なクイズ生成**
  - Ollama の JSON Schema 構造化出力を活用し、コードブロックの混入やレイアウト崩れのない安定したクイズデータを生成。
- 🛡️ **客観的解析と誤検知（False Positive）対策プロンプト**
  - 攻撃の決めつけを防止し、正常なトラフィックの場合は「正常判定の根拠」や「プロトコル理解」を問う実践的な問題を作成。
- 🎨 **SOC風インタラクティブHTML**
  - Tailwind CSS を埋め込んだダークモードデザイン。
  - 選択肢クリック時の即時正誤判定、解説表示、スコア集計、再挑戦機能を備えたシングルファイルHTMLを出力。
- 📝 **Moodle (Aiken形式) 対応**
  - Moodle などの小テスト機能へ直接インポート可能なテキストフォーマットにも対応。

---

## 動作要件

- Python 3.10 以上
- [Wireshark / tshark](https://www.wireshark.org/) （PyShark のパケット解析に必要）
- [Ollama](https://ollama.com/) （Local LLM サーバー）
  - 使用モデル例: `gemma:4`, `gemma2` など

### 必須 Python パッケージ
- `pyshark`
- `ollama`

---

## インストール

```bash
# リポジトリのクローン（またはダウンロード）
cd pcap2quiz

# 依存パッケージのインストール
pip install pyshark ollama
```

> **注意:** PyShark を動作させるために、システムに `tshark` (Wireshark) がインストールされている必要があります。

---

## 使い方

### 基本的な実行例

```bash
python pcap2quiz.py sample.pcap
```
実行すると、デフォルトで `sample/` ディレクトリ（PCAPファイル名から拡張子を除いた名前）が自動作成され、以下のファイルが出力されます：

- `sample/sample.html` (インタラクティブHTMLクイズ)
- `sample/sample_aiken.txt` (Moodle用Aiken形式テキスト)
- `sample/summary.txt` (パケット解析要約)
- `sample/prompt.txt` (LLM送信プロンプト)
- `sample/response.json` (LLM応答の生JSON)

`sample/sample.html` をブラウザで開くことで、即座にクイズを実行できます。

---

### コマンドライン引数 (オプション)

```bash
python pcap2quiz.py <pcap_file> [options]
```

| オプション | 短縮 | デフォルト | 説明 |
| :--- | :--- | :--- | :--- |
| `--model` | `-m` | `gemma:4` | 使用する Ollama モデル名 |
| `--num-questions` | `-n` | `10` | 生成する問題数 |
| `--output` | `-o` | PCAPベース名 | 出力ディレクトリパス |
| `--html-only` | | `False` | HTML形式のクイズのみ出力 |
| `--aiken-only` | | `False` | Aiken形式のクイズのみ出力 |
| `--max-packets` | | `500` | 解析する最大パケット数 |
| `--prompt-template` | | デフォルト参照 | プロンプトテンプレートファイルパス |

---

### 使用例

#### 1. 使用モデルと問題数、出力ディレクトリを指定して生成
```bash
python pcap2quiz.py capture.pcap -m gemma:4 -n 5 -o my_quiz_dir
```

#### 2. HTML 形式のみ出力
```bash
python pcap2quiz.py capture.pcap --html-only
```

#### 3. Moodle 用の Aiken 形式テキストのみ出力
```bash
python pcap2quiz.py capture.pcap --aiken-only
```

#### 4. 解析パケット上限数を増やして精査
```bash
python pcap2quiz.py capture.pcap --max-packets 1000 -n 15
```

---

## 生成されるクイズの例 (HTML)

- **デザイン:** SOC端末をイメージしたダークモードUI
- **機能:**
  - 選択肢をクリックすると、正解 (`✓ 正解`) / 不正解 (`✗ 不正解`) を即座に判定
  - 詳細な解説文を自動アコーディオン表示
  - 全問解答後に最終スコアを表示し、「再挑戦」ボタンで即座にリセット可能

---

## ドキュメント

- [`AGENTS.md`](AGENTS.md): 設計・開発仕様書およびアーキテクチャ詳細
- [`history.md`](history.md): 変更履歴
