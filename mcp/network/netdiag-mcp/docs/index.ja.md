# netdiag-mcp

オンデマンドのネットワーク診断MCPサーバーです。DNS参照（DNSSEC ADビット確認込み）・
ping・`mtr`ベースの経路レポート・TCPポート疎通確認・HTTPステータス/リダイレクト確認・
TLS証明書確認・WHOIS・ASN/GeoIP逆引きを1本にまとめています。

「〇〇に繋がらない」「DNS反映されたか」といった問い合わせの下調べを、踏み台サーバーへ
都度SSHして`dig`/`ping`/`curl`を打つ代わりに済ませることを狙っています。

## ツール一覧

| ツール | 用途 |
|---|---|
| `dns_lookup` | `dig`によるDNSレコード解決（A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA）。特定リゾルバ指定・平文DNS/DoT/DoH対応 |
| `dnssec_check` | 検証済みリゾルバへ問い合わせADビットの有無を確認（平文/DoT/DoH） |
| `ping_host` | ICMP ping（countは1〜10にクランプ） |
| `traceroute_path` | `mtr --report`によるホップ単位の経路/損失レポート（固定サイクル、常時実行ではない） |
| `tcp_port_check` | TCPポートの開放確認（単純なsocket接続、ポートスキャンではない） |
| `http_check` | URLへHEAD/GETしステータス・リダイレクトチェーン・レイテンシを報告 |
| `http_get` | URLへGETし本文を返す。テキスト系のみ（`text/*`・JSON・XML・JavaScript・YAML・`+json`/`+xml`）、上限1 MiB。ループバック・リンクローカル・クラウドのメタデータ宛先はリダイレクト経由も含めて拒否 |
| `tls_cert_check` | ホストが提示する証明書を取得しsubject/issuer/有効期限/SANを報告 |
| `whois_lookup` | ドメインのWHOIS参照 |
| `asn_lookup` | Team CymruのwhoisサービスによるIPのAS番号・国コード逆引き、またはAS番号の組織情報（APIキー・GeoIP DB不要） |
| `current_time` | 指定したIANAタイムゾーンでの現在日時と曜日。曜日を日付から導くのは暦の計算で、間違えても気づけないためデータとして返す。UTC・epochも返すのでサーバー時刻の点検にも使える |
| `health_check` | バージョンとラップしているバイナリ（`dig`/`ping`/`mtr`/`whois`）のPATH上の有無 |

全ツールは読み取り専用・単一ターゲットのみ（バッチ/スイープ機能なし）です。運用者が手動で
行う確認のラッパーであり、スキャンツールではありません。`nmap`的な複数ホスト/ポートの
スキャンは意図的にスコープ外です。

## 設計上の注意点

**4ツールは外部バイナリを一切呼びません。** `tcp_port_check`・`http_check`・`http_get`・
`tls_cert_check`はPython標準のsocket/ssl/httpxスタックを使い、`nc`/`curl`/`openssl`に
依存しません。そのため`dig`/`ping`/`mtr`/`whois`しか入っていない（あるいは何も入っていない）
環境でもこの4つは動作します（`health_check`が欠けているバイナリを報告するだけで、
サーバー全体は落ちません）。

**DNS over TLS/HTTPSには新しい`dig`が必要です。** `dns_lookup`/`dnssec_check`の
`transport="dot"`/`"doh"`（digの`+tls`/`+https`）はBIND 9.18以降が必要です。古い`dig`は
このフラグを拒否して即座にエラーになります（平文DNSへ黙ってフォールバックしない）。

**IPアドレス指定でのTLS確認は正常な相手でも失敗しうります。** `tls_cert_check`/
`http_check`をSNIホスティング/CDN配下（Cloudflare等）のオリジンへIPアドレス指定で
実行すると、TLSハンドシェイクが失敗することがあります。SNIはホスト名しか運べないため、
IPリテラルでは共有エッジ上の正しい証明書へルーティングできません。これはツールの不具合
ではなく正常なTLSの挙動です。CDN配下の対象はホスト名で確認してください。

## 次のステップ

- [リファレンス](reference.ja.md) — 各ツールのパラメータ・CLI・終了コード
