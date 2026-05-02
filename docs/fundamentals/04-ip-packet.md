# 04. IPパケットの構造（ヘッダーとペイロード）

> このドキュメントが答える問い：「VPC Flow Logs に並ぶ数字は何を意味する？ `srcaddr / dstaddr` だけ見れば足りるのか？」

## パケット = 封筒の例え

ネットワーク上を流れる「メッセージの最小単位」が **パケット (packet)** です。郵便の封筒で例えると分かりやすい：

```
┌────────────────────────────────────────────┐
│ FROM: 100.64.10.1   (送信元IP)             │ ← ヘッダー
│ TO  : 205.111.37.86 (宛先IP)               │
│ ─────────────────────────────────────────  │
│                                            │
│   "GET /financial-news HTTP/1.1 ..."       │ ← ペイロード（中身）
│                                            │
└────────────────────────────────────────────┘
```

- **ヘッダー (header)**：配送に必要な情報（送信元・宛先・プロトコル種別など）
- **ペイロード (payload)**：実際に運びたいデータ（HTTPリクエスト、SQLクエリ、メールなど）

ルーターやスイッチは中身（ペイロード）には基本触らず、**ヘッダーを見て転送先を決める**だけです。封筒の住所だけ読んで仕分けるのと同じ。

## IPヘッダーに最低限入っているもの

| フィールド | 役割 |
|---|---|
| **Source IP**          | 誰から（送信元アドレス） |
| **Destination IP**     | 誰へ（宛先アドレス） |
| Protocol               | 中身は TCP / UDP / ICMP のどれか |
| TTL (Time To Live)     | あと何ホップで破棄するか（無限ループ防止） |
| Header Checksum        | ヘッダー破損検出 |
| Total Length           | パケット全体の長さ |

実際にはもっと多くのフィールドがありますが、ラボや Flow Logs の読解には **送信元IP・宛先IP・Protocol・(後述の)Port** さえ把握できれば十分です。

## なぜ送信元IPと宛先IPの両方が必要か

郵便の封筒に「差出人」が書いていなければ、相手は返事を出せません。ネットワークも同じ：

1. クライアント `100.64.10.1` → サーバー `205.111.37.86` に「リクエスト」を送る
   - SRC: `100.64.10.1`、DST: `205.111.37.86`
2. サーバーは封筒の差出人欄を読んで、**SRC と DST を入れ替えて応答**を返す
   - SRC: `205.111.37.86`、DST: `100.64.10.1`

NAT が「送信元IPを書き換える」のは、まさにこの差出人欄を別の住所に偽装する作業です（[02. NAT](./02-public-private-nat.md) 参照）。

## ヘッダーは IP だけではない（プロトコルスタック）

実際のパケットは、複数層のヘッダーが入れ子になっています。

```
[Ethernetヘッダー][ IPヘッダー [ TCPヘッダー [ HTTPデータ ] ] ]
   L2            L3            L4              L7
   MACアドレス   IPアドレス    ポート番号       アプリ層データ
```

- **L3 (IP)**：どのホストへ → `srcaddr` / `dstaddr`
- **L4 (TCP/UDP)**：そのホストの**どのアプリケーション**へ → `srcport` / `dstport`
- **L7**：HTTP, SSH, PostgreSQL などの中身

## このリポジトリでの実践：VPC Flow Logs

[architecture.md](../../architecture.md) の Monitoring セクションにあるとおり、本ラボでは VPC Flow Logs を有効化しています。Flow Logs の 1 行は次のような形式：

```
2 123456789012 eni-abc123 10.0.10.5 169.254.169.254 12345 80 6 5 314 1714000000 1714000060 ACCEPT OK
                          └─srcaddr─┘ └──dstaddr───┘ srcport dstport protocol
```

| 列 | 意味 | 攻撃解析での読み方 |
|---|---|---|
| `srcaddr` | 送信元IP | 誰が動いたか（攻撃者IP？ EC2自身？） |
| `dstaddr` | 宛先IP | 何を狙ったか（IMDSの`169.254.169.254`？ RDS？） |
| `srcport` / `dstport` | ポート番号 | サービス推定（22=SSH, 80=HTTP, 5432=PostgreSQL） |
| `protocol` | 6=TCP, 17=UDP, 1=ICMP | ping か、TCP接続か |
| `action` | ACCEPT / REJECT | Security Group / NACL の判定結果 |

`scripts/flow_logs_analyzer.sh` はこのヘッダー情報だけで攻撃の足跡を再構成しています。**ペイロードは Flow Logs には含まれない**——だから「何を盗まれたか」までは Flow Logs では分かりません（→ ALB アクセスログや GuardDuty が補完）。

## SSRF と IMDS：パケットの宛先を変えれば情報が取れる

`scripts/04_ssrf_metadata.sh` で実行している攻撃は、ヘッダーの世界の話です：

```
攻撃者 → ALB / EC2 (Webアプリ)
        ペイロード: "url=http://169.254.169.254/latest/meta-data/"
                                  ↑
                      ここで EC2 から内部IPへ新たなパケットが発射される
                      SRC: EC2のIP / DST: 169.254.169.254
```

EC2 はそのリクエストを「自分が出した正規通信」として処理し、IMDS（リンクローカルアドレス `169.254.169.254`）から IAM 認証情報を返してしまう。**Flow Logs にも `dstaddr=169.254.169.254` が残らない**（リンクローカルは Flow Logs 対象外）のが厄介な点です。

→ 詳しくは `docs/packet-flow-trace.md` がパケット単位で追跡しています。

## ハマりどころ

- **「ヘッダー」と聞くと HTTP ヘッダー（`User-Agent` など）を連想しがちですが、ネットワーク層では IP/TCP のヘッダーを指す**。文脈で使い分ける
- **Flow Logs はヘッダーのみ・ペイロードなし**。深い解析には別の仕組み（パケットキャプチャ、ALB ログ、アプリケーションログ）が必要
- **NAT Gateway 配下のパケットは送信元IPがNATのIPに書き換わる**ため、Flow Logs だけでは「真の発信源」を追えない（[02-public-private-nat.md](./02-public-private-nat.md) 参照）

## 次に読む

- [05. AWS VPC・リージョン・AZ（仮想データセンター） →](./05-vpc-regions-az.md)
- 関連実装：`terraform/monitoring.tf`, `scripts/flow_logs_analyzer.sh`
- 詳細トレース：[../packet-flow-trace.md](../packet-flow-trace.md)
