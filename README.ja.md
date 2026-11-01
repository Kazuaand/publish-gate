# publish-gate

テキストを公開する前に、秘密情報や個人・組織を特定する情報を検査するツールです。
公開そのものは行いません。コード向けの検出器だけでは、散文や HTML 内の認証情報を
見落とすことがあります。複数の検出器、外部の禁止リスト、独立した2つの判定を組み合わせます。
PASS は検査を通った証拠であり、漏えいが絶対にないという保証ではありません。

## 導入と実行

Python、Homebrew、認証済みの Claude / Codex CLI が必要です。
`sh install.sh` で不足する gitleaks / TruffleHog と、プロジェクト内の `.venv` に
Presidio・spaCy・英語モデルを導入します。続いて `./publish-gate selftest` を実行します。

```sh
./publish-gate check candidate --denylist ../private-rules.txt --out ../evidence/run.json
./publish-gate loop candidate --denylist ../private-rules.txt --fix-cmd 'repair-agent' --max-rounds 3 --out ../evidence/loop.json
```

`denylist.example` を検査対象の外へコピーして編集してください。1行1件の Python 正規表現
（大文字小文字を区別しない）です。任意でカテゴリとタブを前置できます。3列目にはタブで区切った # から始まる注記を置けます。
カテゴリだけのコメント行も使えます。未知のカテゴリは判定者へ `other` として渡します。
値そのものは判定者へ渡しません。空リストや不正な式はエラーです。

## 4段の検査

1. gitleaks、TruffleHog の filesystem モード（検証有効）、Presidio の英語認識器、
   独自パターンを実行します。鍵13種に加え、認証ラベルと値、HTML タグ除去版、
   アクセス権を持つURL、私用IP、ホームパス、メール、電話などを検査します。
   TruffleHog の検証はサービス側のAPIへ接続します。未検証の検出もFAILです。
2. 外部の禁止リストでファイル名・本文・HTML タグ除去版を検査します。
   日本語の氏名・住所や固有の内部語はこのリストに登録します。
3. 新規の判定者2つがファイル名・本文・カテゴリ・番号付きの要審査項目を読みます。既定はツールを無効化した
   Claude Sonnet と、設定を隔離して読み取り専用で起動する Codex です。
   検査対象はそれぞれのサービスへ送られます。認証・利用料金は利用者が管理してください。
4. 即時拒否の検出、要審査項目への両判定者のPASSの欠落、検出器の異常、判定の不備、対象の変化があればFAILです。
   exit 0がPASS、1が検出あり、2が入力・実行エラーです。

`--judge-cmd` を2回指定すると判定コマンドを置き換えられます。シェル展開はしません。
標準入力に依頼全体を受け取り、標準出力にJSONだけを返してください。
`verdict` は `PASS` / `FAIL`、`findings` は `file`・`line`・`reason` を持つ配列です。
PASS時は空配列、FAIL時は1件以上を必要とします。理由は `secret`・`identity`・
`infrastructure`・`capability`・`other` のいずれかとし、実値を引用しません。
カスタムコマンドの読み取り専用化と独立性は利用者が確保してください。
コマンド文字列が違うことだけでは独立した判定とは言えません。

修正コマンドは標準入力から証拠JSONを受け取ります。環境変数 `PUBLISH_GATE_FINDINGS`
は証拠のパス、`PUBLISH_GATE_TREE` は修正対象です。対象内の情報の除去・一般化だけを行い、
関門や禁止リストを弱めてはいけません。修正後に関門ファイルと禁止リストの変更を検査します。
任意のコマンドをOSレベルで隔離する仕組みではないため、信頼できない修正エージェントには
別の制限環境が必要です。上限は検査回数です。3回なら修正は最大2回で、最後の検出結果を残します。

## 証拠と検査範囲

JSONにUTC時刻、対象のSHA-256、各段の結果と件数、検出箇所（相対ファイル名・行・ルールID）、
ツール版、判定ファイルのパスを記録します。即時拒否の実値・生の判定出力は保存しません。
要審査項目は id・file・line・entity・一致した text を証拠に残します。
ファイル名自体が個人情報を含む場合があるため、証拠は非公開で保管してください。

ハッシュはソートした相対パスと内容を長さ付きで連結して計算します。検査用コピーと元の対象を
検査後に再確認します。Git履歴の検査ではありません。対象ルートの `.git`・`.venv`・`__pycache__`
を除外します。公開担当は証拠の `publication_manifest` に記録したファイルだけを書き出し、リンクを拒否してハッシュを再確認してください。元のフォルダを丸ごと公開してはいけません。シンボリックリンク・バイナリ・UTF-8以外
はFAILです。テキスト以外は別途検査してください。検出免除の設定はありません。
検出ルール自身のソースにも誤検知が起こります。最終公開前には同じハッシュか再確認が必要です。

自己テストでは一時ディレクトリに偽の値を組み立て、鍵13種と追加パターン、HTML、
日本語の禁止語、正常なテキスト、ハッシュ変化、判定失敗を検証します。
実際の検出器を必要としますが、判定用エージェントは呼び出しません。

## Presidio の分類と個別判定

URL・DATE_TIME・NRP は対象外です。PERSON・LOCATION・ORGANIZATION・US_DRIVER_LICENSE
は個別審査し、それ以外（未知の種類を含む）は即時FAILです。
判定者は review_items 配列に各 id・verdict・1行の reason を返します。
公開人物・組織・場所または誤検出で、著者の本名・勤務先・取引先・所在地へ辿れない場合だけPASSです。
両者が全項目をPASSにする必要があり、欠落・余分・重複したIDもFAILです。自動承認はありません。

画像はPNG/JPEG/WebP/GIFをシグネチャで識別します。上限は各5 MiB、100フレーム、全フレーム合計2000万画素です。未知バイナリ・未知メタデータ・ICCプロファイルはFAIL。印字可能ASCII文字列にも既存検出器と禁止リストを適用します。両judgeが全フレームを見て画像ごとの判定を返し、欠落・重複・FAILがあれば公開不可です。

`./publish-gate strip input.png output.png` でメタデータなしPNGへ再描画できます。アニメーションは100ms間隔のAPNGになります。色プロファイルを除去するため、置換前に表示とタイミングを確認してください。自動修正はしません。Claudeはprint modeのstream-json画像入力、Codexは--imageで全フレームを受け取ります。

JPEG/WebP/GIF require a byte-exact decode/re-encode match because their decoders do not expose consumed byte counts. Valid images from other encoders may fail with `image-noncanonical-stream-use-strip`; use the strip command to produce PNG. PNG compressed streams must end exactly, without hidden trailing payload.

## バッチと HEAD の検査

`--judge-batch-size 25` で1回の審査項目数、`--judge-timeout 600` で1回の秒数上限を指定します。ファイル全文をバッチに渡し、同じファイルの項目が多い場合は全文を再送します。画像は1回につき最大1枚で全フレームを渡します。項目・画像の欠落や1バッチのエラーでも段4は FAIL。judge JSON にマスク済みの失敗分類・終了コード・経過秒・stderr末尾を残します。利用上限時は枠のある環境から運用者が再実行してください。

`--git-tracked` は HEAD の blob を一時領域へ書き出します。作業中の変更や未追跡ファイルを含めず、node_modules/dist/.git/.venv/__pycache__ は全階層で除外。manifest と hash はこの書き出しに対応します。symlink と submodule は拒否します。修正を反映するにはコミットが必要です。

画像の文字検査はメタデータ・付随領域・未消費バイトを対象とし、圧縮画素領域は除外します。画素は両 judge の全フレーム視覚審査、メタデータは既存の拒否検査で扱います。
