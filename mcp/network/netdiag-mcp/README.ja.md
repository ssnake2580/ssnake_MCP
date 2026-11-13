# netdiag-mcp

[English](README.md) | 日本語

オンデマンドのネットワーク診断MCPサーバーです。DNS参照（DNSSEC ADビット確認込み）・ping・`mtr`ベースの経路レポート・TCPポート疎通確認・HTTPステータス/リダイレクト確認・TLS証明書確認・WHOISを1本にまとめています。

「〇〇に繋がらない」「DNS反映されたか」といった問い合わせの下調べを、踏み台サーバーへ都度SSHして`dig`/`ping`/`curl`を打つ代わりに済ませることを狙っています。

## ツール一覧

| ツール | 用途 |
|---|---|
| `dns_lookup` | `dig`によるDNSレコード参照（A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA）。特定リゾルバ指定・平文DNS/DoT/DoHの切り替えも可 |
| `dnssec_check` | 検証済みリゾルバへ問い合わせてADビットの有無を確認する（平文/DoT/DoH）。素の`dig`でRRSIGが見えてもそれだけではDNSSEC検証済みとは言えないため、これが唯一の確実な確認方法 |
| `ping_host` | ICMP ping（countは1〜10にクランプ） |
| `traceroute_path` | `mtr --report`によるホップ単位の経路/ロスレポート（固定サイクル数、連続実行ではない） |
| `tcp_port_check` | TCPポートの開閉確認（単純なsocket connect、ポートスキャンではない） |
| `http_check` | URLへHEAD/GETしステータス・リダイレクトチェーン・レイテンシを報告 |
| `http_get` | URLへGETし本文を返す。テキスト系のみ（`text/*`・JSON・XML・JavaScript・YAML・`+json`/`+xml`）、上限1 MiB。ループバック・リンクローカル・クラウドのメタデータ宛先はリダイレクト経由も含めて拒否 |
| `tls_cert_check` | 提示されたTLS証明書のsubject/issuer/有効期限/SANを報告 |
| `whois_lookup` | ドメインのWHOIS参照 |
| `asn_lookup` | Team CymruのwhoisサービスによるIPのASN・国コード参照、またはAS番号の組織情報参照。APIキーやGeoIP DB不要 |
| `current_time` | 指定したIANAタイムゾーンでの現在日時と曜日。曜日を日付から導くのは暦の計算で、間違えても気づけないためデータとして返す。UTC・epochも返すのでサーバー時刻の点検にも使える |
| `health_check` | バージョンと、ラップしている各バイナリ（`dig`/`ping`/`mtr`/`whois`）がPATH上にあるかどうか |

すべて読み取り専用・単一ターゲットのみ（バッチ/一括スイープ機能なし）です。運用者が手で打つ疎通確認コマンドの薄いラッパーという位置づけで、`nmap`的な多ホスト/多ポートへの探索は意図的にスコープ外にしています。複数対象への能動的なプローブは影響範囲が異なる別の判断・承認フローが必要な行為だからです。

`tcp_port_check`・`http_check`・`http_get`・`tls_cert_check`はPython自身のsocket/ssl/httpxスタックを使い、`nc`/`curl`/`openssl`へシェルアウトしません。そのため`dig`/`ping`/`mtr`/`whois`のいずれかが入っていない（あるいは全く入っていない）ホストでもこの4つは動作します（`health_check`はどのバイナリが無いかを報告しますが、サーバー全体は落としません）。

`dns_lookup`/`dnssec_check`は`transport="dot"`/`"doh"`でDNS over TLS・DNS over HTTPSにも対応します（digの`+tls`/`+https`）。BIND 9.18以降の`dig`が必要で、古い`dig`はこのフラグを黙って平文DNSにフォールバックせず明示的に拒否（エラー終了）します——「暗号化で確認したつもり」が実は平文だった、という誤検知を防ぐためです。

`tls_cert_check`/`http_check`をIPアドレス直指定で実行すると、SNIホスティング/CDN配下（Cloudflare等）のオリジンでは「handshake failure」等のTLSハンドシェイクエラーになることがあります。TLSのSNI拡張はホスト名しか運べないため、共用エッジ上でIPリテラルからは正しい証明書へルーティングできないのが原因です。これはツールの不具合ではなくTLSの正常な仕様なので、CDN配下の対象はホスト名で確認してください。

## セットアップ

### 1. システム依存パッケージ

`dns_lookup`・`dnssec_check`・`ping_host`・`traceroute_path`・`whois_lookup`はそれぞれ`dig`・`ping`・`mtr`・`whois`にシェルアウトします。使いたいものだけ入れてください。

```bash
# Debian/Ubuntu
sudo apt install dnsutils iputils-ping mtr-tiny whois
```

`mtr`はraw socket権限が必要です。Debian/Ubuntuの`mtr-tiny`パッケージはインストール時に`mtr-packet`ヘルパーへ`cap_net_raw`を付与するため、通常は非特権のサービスユーザーでも追加設定なしに動作します——`traceroute_path`がsocket権限エラーを返す場合は`getcap "$(command -v mtr-packet)"`で確認してください。この権限が無い場合、`traceroute_path`はサーバーを落とさず`ToolError`としてクリーンに失敗します。

### 2. インストール

```bash
pip install netdiag-mcp
# または
uv tool install netdiag-mcp
```

### 3. Claude Code（プラグイン）

このリポジトリはプラグイン 1 個のマーケットプレイスも兼ねているので、Claude Code から
そのまま導入できます。

```
/plugin marketplace add shigechika/netdiag-mcp
/plugin install netdiag-mcp@netdiag-mcp
```

プラグインは `uvx netdiag-mcp` を起動します。必須の環境変数はありません。前提は上記の
システム依存パッケージだけで、TCP・HTTP・TLS のチェックはそれらが無くても動きます。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要があります。ログインシェルなら通常問題ありませんが、
GUI から起動した場合は通っていないことがあります。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールしてください。

### 4. Claude Code（手動登録）

```bash
claude mcp add netdiag -- netdiag-mcp
```

必須の環境変数はありません。

### 5. Codex

```bash
codex mcp add netdiag -- netdiag-mcp
```

stdio サーバーを起動できる MCP クライアントなら、どれでも同じ形で使えます。コマンドに `netdiag-mcp` を指定してください。

## 任意: `http_get` の認証情報

`http_get` は、設定した https の URL 前方一致の下にある URL へ `Authorization`
ヘッダを付けて送れます。認証付きの JSON エンドポイントを、認証情報をモデルに渡さずに
読むためのものです。`NETDIAG_HTTP_AUTH` に、前方一致とヘッダ値の組を JSON で書きます。

```bash
NETDIAG_HTTP_AUTH='{"https://reports.example.ac.jp/daily/": "Bearer <token>"}'
```

- ヘッダは、リクエストごと・リダイレクトの 1 ホップごとに、URL を部品に分けて比べて決めます（https のみ、ホストとポートは完全一致、パスは `/` 区切りの前方一致）。別の宛先へのリダイレクトでは付けず、付けている間に受け取った Cookie も持ち越しません。`user@host` 形式の URL と、英数字・`.`・`_`・`~`・`-`・`/` 以外を含むパス（`%`・`;`・`.`/`..` のセグメント）には一致しません。サーバ側の正規化でプレフィックスの外へ出されるのを防ぐためです。複数一致したら最長の前方一致を使い、大文字小文字・`:443`・末尾のドットだけが違う前方一致は重複として拒否します。値は表示可能な ASCII に限ります
- netdiag-mcp 自身は、値をツールの出力・エラー・`health_check` のどこにも出しません。最後のホップに付けたときは結果のステータス行に `auth=applied` と出ます。`health_check` は設定した前方一致を正規化した形で一覧します（値は出さない）。不正な前方一致はエラーで位置（何番目か）だけを示し、文字列は出しません。前方一致の下の応答本文に値（とトークン部分）が含まれていれば `[redacted]` に伏せますが、base64 などに変換して返すエンドポイントでは見えてしまうので、前方一致は自分で管理するエンドポイントにだけ向けてください
- 値が不正なら黙って無視せず、`http_get` はエラーを返し、`health_check` は `degraded` になります
- 読むのは環境変数だけです。同じユーザーで複数のインスタンスを動かす場合（多くの人に開いたものと、限られた人向けのものなど）は、送るべきインスタンスの環境にだけ設定してください。ファイルにすると全インスタンスで共有されます

## CLI

```bash
netdiag-mcp --version   # バージョン表示
netdiag-mcp --check     # バイナリの欠けと NETDIAG_HTTP_AUTH の不正を報告（全バイナリがあり、設定していれば正しく読めるときexit 0）
```

## セキュリティ上の注意

- 外部バイナリの呼び出しは常にargvリスト渡し（シェル文字列を組み立てない）なので、引数がシェル構文として解釈される余地がありません
- ホスト名/IP・ポート番号はサイズ/範囲を検証してからしか使いません。ツール入力はLLM駆動＝敵対的とみなす、という他のツール呼び出し面と同じ扱いです
- `tcp_port_check`は1回の呼び出しにつき1つのhost:portのみ接続します。ループや範囲指定の引数は意図的に存在しません
- 任意の `http_get` の認証情報は、設定した https の前方一致の外へ出ず、netdiag-mcp 自身が表示することもありません。応答の本文が返してしまう場合はサーバ側の問題です（上記）

## 開発

### 実地スモークテスト

ユニットテストはフィクスチャに対するロジックの検証はできても、ツールが実データを返さなくなったこと
（`dig`/`ping`/`mtr`/`whois`バイナリが死んでいる、TLS証明書ストアが壊れている、送信ICMPがブロックされている等）
は検知できません。`scripts/smoke_test.py`は**登録されている全ツール**を実際の公開エンドポイントへ実行し、
空・不正形式・エラー応答を検知します。

```bash
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only ping --traceback
```

- **インベントリを持たないため、対象は全て固定の公開エンドポイント**——CloudflareのIP`1.1.1.1`とIANAの
  `example.com`（ドキュメント・テスト用途としてRFC 2606で予約済み）を使います。このサーバーは設定を持たず
  対象を発見する仕組みが無い点が、このファミリーの機器フリート系MCPサーバーとの違いです
- `tests/test_smoke_probes.py`はオフライン側の半分です。登録されている全ツールにプローブ仕様があるか
  （逆に、登録されていないツールへのプローブが残っていないか）だけを確認するため、ネットワークアクセス
  無しでCIが「ツールを追加したが動作確認方法を決めていない」という漏れを検知します

## License

MIT
