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

## [2026-09-13] - v1.0.1
### 変更・改善概要
正常通信のパケットであっても無理に「攻撃の兆候」と解釈してしまう誤検知（ハルシネーション）を防止するため、Ollama（LLM）への提示プロンプトを大幅に強化。

### 追加・変更点
1. **客観的解析とハルシネーション防止指示の追加 (`pcap2quiz.py`)**
   - サマリに存在する事実（IP, ポート, ドメイン名等）のみに基づく問題生成を徹底（存在しない攻撃ログの決めつけ・創作を禁止）。
2. **正常トラフィックの適切な評価・出題**
   - 明確な攻撃が見られない場合は、無理に攻撃と扱わず「正常通信の特定・理解」「正常判定の根拠」「誤検知（False Positive）防止の視点」を問う問題を作成するよう指示を改修。
3. **ドキュメント更新 (`AGENTS.md`)**
   - プロンプトの設計方針改修に伴い、`AGENTS.md` の Quiz Engine 仕様を更新。

## [2026-09-13] - v1.0.2
### 変更・改善概要
Ollama のバージョンアップや長文応答生成時に発生していた「`Unterminated string` （JSONパースエラー）」を防止するための修正。

### 追加・変更点
1. **Ollama 生成トークン数およびコンテキストサイズの拡張**
   - `ollama.chat` の `options` に `num_predict: 8192` および `num_ctx: 8192` を設定し、出力途切れを回避。
2. **解説文章の長大化防止プロンプトの調整**
   - `explanation` の生成指示に「根拠を添えて簡潔（2〜3文程度）に記載」を追加し、トークン上限超過を抑制。

## [2026-09-13] - v1.0.3
### 変更・改善概要
正常トラフィックの解説において、無理に「攻撃の前兆」「偵察」「攻撃の準備」などと結びつける問題が生成される現象を防ぐため、プロンプトの制約条件を厳格化。

### 追加・変更点
1. **正常通信に対する禁止事項の明記 (`pcap2quiz.py`)**
   - 明確な悪意・異常の根拠がない通信を「攻撃の前兆」「攻撃の準備」「偵察」「不審な通信」と決めつけることを絶対遵守事項として厳禁化。
   - 正常通信については、無理にインシデントと結びつけず「通信相手の特定」「正常なプロトコル挙動理解」「正常判定の分析手順」「過検知・誤検知（False Positive）の防止手法」を問う形式に限定するようプロンプトを強化。
2. **仕様書の同期更新 (`AGENTS.md`)**
   - `AGENTS.md` の Quiz Engine 仕様に本制約条件を反映。

## [2026-09-13] - v1.0.4
### 変更・改善概要
出題内容を「パケットから直接確認できる客観的事実」に特化させ、SOCアナリストとしての一般的行動・手順を問う問題を排除するためのプロンプトおよび仕様の修正。

### 追加・変更点
1. **パケット内容・事実に基づく問題設定の厳格化 (`pcap2quiz.py`)**
   - パケットキャプチャ（IP, ポート, 通信数, DNS名, HTTP/TLS情報等）から直接確認できる事実や、その論理的帰結に関する問題のみを出題するようプロンプトを厳格化。
2. **SOC一般的行動・対応選択に関する出問の禁止**
   - 「エスカレーション手順」「端末隔離の判断」「SOCアナリストとしての次の一手」など、パケット解析そのものではなくSOC運用上の対応手順を問う問題の生成を禁止。
3. **仕様書の更新 (`AGENTS.md`)**
   - 上記の出題範囲および禁止事項を `AGENTS.md` の Quiz Engine 仕様に同期反映。

## [2026-09-13] - v1.1.0
### 変更・改善概要
対応プロトコルの増加に伴うコードの肥大化・複雑化（破綻）を防ぐため、プロトコル解析ロジックを Strategy パターン（プラグイン構造）へリファクタリング。

### 追加・変更点
1. **プロトコル解析モジュール (`parsers/`) の新設**
   - `parsers/base.py`: プロトコル抽出器の抽象基底クラス `BaseExtractor` および統合管理クラス `ProtocolManager` を定義。
   - プロトコル別アナライザーへの切り出し:
     - `parsers/flow.py`: IPペア通信量・パケット概要サンプル (`FlowExtractor`)
     - `parsers/dns.py`: DNSクエリ抽出 (`DNSExtractor`)
     - `parsers/http.py`: HTTPリクエスト抽出 (`HTTPExtractor`)
     - `parsers/tls.py`: TLS SNI抽出 (`TLSExtractor`)
     - `parsers/smb.py`: SMBコマンド抽出 (`SMBExtractor`)
   - `parsers/__init__.py`: デフォルト抽出器を一括登録する `get_default_manager()` を実装。
2. **`pcap2quiz.py` の構造化・保守性向上**
   - `extract_pcap_summary` 内の長大な `if-elif` 条件分岐を全廃し、`ProtocolManager` 経由の処理委譲へリファクタリング。
   - 新しいプロトコルを追加する際、メイン処理を改修せず新クラスを追加・登録するのみで対応可能に（開閉原則の実現）。

## [2026-09-13] - v1.2.0
### 変更・改善概要
新規プロトコル対応として FTP プロトコル解析モジュール (`FTPExtractor`) を追加し、FTP セッション・コマンド・レスポンス等の要約抽出に対応。

### 追加・変更点
1. **FTP プロトコルアナライザーの追加 (`parsers/ftp.py`)**
   - `FTPExtractor` クラスを実装し、FTP コマンド（`USER`, `RETR`, `STOR` 等）、引数、応答コード（`220`, `230`, `530` 等）、およびログイン試行ユーザー名を抽出・集計。
2. **`ProtocolManager` への登録 (`parsers/__init__.py`)**
   - デフォルトマネージャーに `FTPExtractor` をインポート・登録し、PCAP解析時に自動でFTPトラフィック要約を出力・プロンプトに反映できるよう拡張。
3. **仕様書・ドキュメントの同期更新 (`AGENTS.md`)**
   - `AGENTS.md` の標準対応プロトコル一覧に `FTPExtractor` の情報を追加。

## [2026-09-13] - v1.3.0
### 変更・改善概要
新規プロトコル対応として SMTP、POP3、IMAP の電子メール関連プロトコル解析モジュールを追加し、メール送受信トラフィックの集計・要約抽出に対応。

### 追加・変更点
1. **電子メール関連プロトコルアナライザーの追加 (`parsers/`)**
   - `parsers/smtp.py`: `SMTPExtractor` クラスを実装し、SMTP コマンド（`HELO`, `MAIL FROM`, `RCPT TO` 等）、レスポンス、送信元/送信先メールアドレスを抽出・集計。
   - `parsers/pop3.py`: `POP3Extractor` クラスを実装し、POP3 コマンド（`USER`, `PASS`, `RETR` 等）、レスポンス（`+OK`, `-ERR`）、ログイン試行ユーザー名を抽出・集計。
   - `parsers/imap.py`: `IMAPExtractor` クラスを実装し、IMAP コマンド（`LOGIN`, `SELECT`, `FETCH` 等）、レスポンス、ログイン試行ユーザー名を抽出・集計。
2. **`ProtocolManager` への登録 (`parsers/__init__.py`)**
   - デフォルトマネージャーに `SMTPExtractor`, `POP3Extractor`, `IMAPExtractor` をインポート・登録し、PCAP解析時に自動でメール通信要約を出力・プロンプトに反映できるよう拡張。
3. **仕様書・ドキュメントの同期更新 (`AGENTS.md`)**
   - `AGENTS.md` の標準対応プロトコル一覧に `SMTPExtractor`, `POP3Extractor`, `IMAPExtractor` の情報を追加。


## [2026-09-13] - v1.4.0
### 変更・改善概要
生成されるクイズ概要（`description`）のテンプレート文字列「提供されたPCAP」を、ユーザーがコマンドライン引数で指定した入力PCAPファイル名（パスを除いたファイル名）へ動的に変更・反映するよう改善。

### 追加・変更点
1. **入力PCAPファイル名の抽出処理 (`pcap2quiz.py`)**
   - `os.path.basename` を用いて、CLI引数のファイルパスからパスを除外した純粋なファイル名を抽出。
2. **Ollamaプロンプト・生成テンプレートの変更 (`pcap2quiz.py`)**
   - `generate_quiz_with_ollama` に `pcap_filename` 引数を追加し、プロンプト内の出力仕様にファイル名指定を追加。`description` フィールドへ「`<ファイル名>` の解析サマリに含まれる事実のみに基づき...」と出力されるよう制御。

## [2026-09-14] - v1.5.0
### 変更・改善概要
オフライン（インターネット接続不可）環境でのHTML表示崩れを防止するため、Tailwind CSS JSファイルをプロジェクト内に同梱し、HTML生成時に出力先ディレクトリの `assets/` フォルダへ自動コピーする仕組みを導入。

### 追加・変更点
1. **アセットファイルの同梱 (`assets/tailwindcss.js`)**
   - オフライン動作に必要な Tailwind CSS standalone スクリプトを `assets/` ディレクトリ内に配置。
2. **HTML テンプレートのローカル参照化 (`pcap2quiz.py`)**
   - `<script src="https://cdn.tailwindcss.com"></script>` から相対パス `<script src="assets/tailwindcss.js"></script>` へ変更。
3. **アセット自動コピー処理の追加 (`pcap2quiz.py`)**
   - HTML形式での生成時、`pcap2quiz.py` が配置されている `assets/` 内のファイルを、出力指定されたHTMLファイルと同一ディレクトリの `assets/` へ自動的にコピーする処理を追加。

## [2026-09-14] - v1.6.0
### 変更・改善概要
`pcap2quiz.py` 内にヒアドキュメント形式でハードコードされていた HTML テンプレートを外部ファイル (`templates/quiz_template.html`) へ切り出し、テンプレートベースのレンダリング処理へリファクタリング。

### 追加・変更点
1. **HTML テンプレートファイルの独立化 (`templates/quiz_template.html`)**
   - Python コード内から HTML / JavaScript / Tailwind CSS の構造を分離し、独立した `quiz_template.html` ファイルとして新設。
   - エディタの構文ハイライトや補完の恩恵を受けられるようにし、デザインやスクリプトの保守性・可読性を向上。
2. **テンプレート読み込み・埋め込みロジックの改修 (`pcap2quiz.py`)**
   - `render_html` 関数を改修し、`templates/quiz_template.html` をオープンして `{title}`, `{description}`, `{questions_json}` を動的に置換・埋め込んで完全な HTML を生成するよう変更。
3. **仕様書・ドキュメントの同期更新 (`AGENTS.md`, `history.md`)**
   - `AGENTS.md` の HTML Render 仕様に外部テンプレートファイルの参照に関する記述を追加し、`history.md` に本変更履歴を追記。

## [2026-09-15] - v1.7.0
### 変更・改善概要
Ollama問い合わせ用プロンプトテキストを外部テンプレートファイル (`templates/quiz_prompt.txt`) へ切り出し、プロンプトの調整や変更をコード修正なしで行えるようリファクタリング。合わせてCLI引数に `--prompt-template` オプションを追加。

### 追加・変更点
1. **プロンプトテンプレートファイルの作成 (`templates/quiz_prompt.txt`)**
   - Pythonコード内にハードコードされていたプロンプト文字列・客観的事実限定ルール等を分離し、`templates/quiz_prompt.txt` として独立化。
2. **プロンプト読み込み・挿入処理の改修 (`pcap2quiz.py`)**
   - `generate_quiz_with_ollama` 関数にて外部テンプレートファイルを読み込み、`str.format` でパラメータ（`pcap_filename`, `num_questions`, `summary_text`）を挿入する処理へ変更。
3. **CLI引数へのプロンプトテンプレート指定オプション追加 (`pcap2quiz.py`)**
   - `--prompt-template` 引数を追加し、任意のカスタムプロンプトテンプレートファイルを外部から指定可能に設定。
4. **仕様書の同期更新 (`AGENTS.md`)**
   - `AGENTS.md` の Quiz Engine 仕様および CLI オプション説明にプロンプトテンプレートに関する記述を追加。
