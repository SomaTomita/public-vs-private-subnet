# 07. パブリックサブネット vs プライベートサブネット & NAT 設定

> このドキュメントが答える問い：「結局、本リポジトリの `config_mode=public` と `private` は何がどう違うのか？ なぜ攻撃結果が変わるのか？」

## サブネットを「パブリック」にする 2 つの条件

AWS において **「パブリックサブネット」「プライベートサブネット」という属性は存在しません**。サブネット作成時に選ぶドロップダウンもなし。
**パブリックかどうかは「設定の組み合わせ」で決まります**。

> ### 公式の判定基準
>
> 1. その VPC に **Internet Gateway がアタッチされている**
> 2. そのサブネットに関連付けられたルートテーブルに **`0.0.0.0/0 → IGW` のエントリがある**

両方満たして初めて「パブリックサブネット」。片方でも欠けたら「プライベートサブネット」です。

## パブリックサブネット

```
[インターネット]
      ↓ ↑
   [IGW]
      ↓ ↑
[Public Subnet]   ←── ルートテーブル: 0.0.0.0/0 → IGW
   │
   └── [EC2 (パブリックIP付き)]
```

- **双方向通信可能**：インターネットから EC2 に直接 SSH できるし、EC2 から `apt update` もできる
- **EC2 にパブリック IP（または EIP）が必要**：プライベートIPだけでは届かない
- 用途：ALB、NAT Gateway、踏み台サーバー、公開Webサーバー（小規模）

## プライベートサブネット

```
       (インターネットから直接到達不可)
[Public Subnet]
   │
   └── [NAT Gateway]
          ↓ (outboundのみ)
[Private Subnet]   ←── ルートテーブル: 0.0.0.0/0 → NAT GW
   │
   └── [EC2 (パブリックIPなし)]
```

- **インターネットから直接アクセスできない**
- NAT Gateway 経由で **outbound（外向き）通信のみ可能**
- inbound（内向き）はインターネットから一切届かない（IGW にルートがないため）
- 用途：アプリケーションサーバー、データベース、ワーカー

### さらに厳しい「完全プライベート」サブネット

ルートテーブルに **デフォルトルートそのものを書かない** とどうなるか？

```
[DB Private Subnet]   ←── ルートテーブル: 10.0.0.0/16 → local のみ
```

- インターネットへの outbound すら不可能
- VPC 内通信のみに閉じる
- 用途：RDS（本リポジトリの DB Private サブネットがこれ）

## このリポジトリでの実装：Config A vs Config B

### Config A: Public Direct（教育用の悪い例）

```
[Internet] → [IGW] → [Public Subnet (10.0.1.0/24)] → [EC2 (Public IP)]
                                                      ↓
                                           [DB Private Subnet] → [RDS]
```

- **EC2 がインターネットに直接さらされる**
- HTTP (80) は `0.0.0.0/0` から、SSH (22) は `my_ip` のみ許可
- 攻撃面：最大

### Config B: Private + ALB（プロダクション級）

```
[Internet] → [IGW] → [Public Subnet] → [ALB]
                                          ↓ (HTTP only, 内部通信)
                            [App Private Subnet] → [EC2 (No Public IP)]
                                                      ↓ outbound
                                                   [NAT GW]
                                          [DB Private Subnet] → [RDS]
```

- **EC2 にパブリック IP がない**。インターネットから直接届かない
- 入口は ALB のみ。ALB が HTTP を Private サブネットへ proxy
- EC2 → インターネットは NAT GW 経由（パッケージ更新やIMDS応答など）
- SSH は SSM Session Manager 経由（ポート22は閉じる）
- 攻撃面：最小化

## ルートテーブルの差分（一目で分かる）

| サブネット | Config A の Route Table | Config B の Route Table |
|---|---|---|
| Public  | `0.0.0.0/0 → IGW` | `0.0.0.0/0 → IGW` |
| App Private  | （EC2が居ない） | `0.0.0.0/0 → NAT GW` |
| DB Private | （default routeなし） | （default routeなし） |

**たった 1 行のルート差分が、攻撃面を劇的に変える**——これが本ラボの主題です。

## 攻撃面マトリクス（架構ドキュメントの抜粋）

| 攻撃レイヤ | Config A | Config B | 補足 |
|---|---|---|---|
| Network Boundary（直接ポートスキャン・SSH ブルートフォース） | **VULNERABLE** | **BLOCKED** | プライベートサブネットの効果が最も顕著 |
| Application 層（SSRF、SQLi など） | VULNERABLE | VULNERABLE | ALB を通れば届く。WAF 等の追加対策が必要 |
| AWS API 層（IMDS 経由のクレデンシャル窃取） | VULNERABLE | VULNERABLE | IMDSv2 と最小権限 IAM が必要 |
| VPC 内部の横展開 | VULNERABLE | VULNERABLE | Security Group の細分化、Network Firewall |
| Outbound（C2 通信、データ持ち出し） | VULNERABLE | VULNERABLE | NAT GW は egress フィルタしない |

→ **「プライベートサブネットは必要だが十分ではない」** ([architecture.md "Conclusion"](../../architecture.md))。ネットワーク境界を閉じても、アプリ層・IAM 層の脆弱性は残ります。

## 動作確認シナリオ

`scripts/run_all_attacks.sh` を Config A と Config B の両方で実行して比較します。

```bash
# Config A で攻撃
terraform apply -var="config_mode=public"
cd ../scripts && ./run_all_attacks.sh

# Config B に切り替えて同じ攻撃
cd ../terraform && terraform apply -var="config_mode=private"
cd ../scripts && ./run_all_attacks.sh

# 差分レポート生成
./compare_results.sh
```

期待される結果（一部）：

| スクリプト | Config A | Config B |
|---|---|---|
| `01_portscan.sh` | 22, 80, 5432 などが見える | フィルタリングされて見えない |
| `02_ssh_probe.sh` | SSH バナー取得可能 | 接続タイムアウト |
| `04_ssrf_metadata.sh` | **成功**（ALB 経由でも届く） | **成功**（プライベートでもアプリ脆弱性は残る） |
| `06_outbound_check.sh` | 通る | 通る（NAT GW があるため） |

「BLOCKED」と「VULNERABLE」が並ぶ表が、`compare_results.sh` の出力です。

## NAT Gateway の挙動を再確認

NAT Gateway は **「内→外は通す、外→内は通さない」** という非対称な装置です。

| 通信方向 | 動作 |
|---|---|
| EC2 (Private) → インターネット | パブリックIPに NAT して通す |
| インターネット → EC2 (Private) | **届かない**（戻りパケット以外は破棄） |

これは「Stateful NAT」と呼ばれ、家庭用ルーターと同じ仕組みです。攻撃者が能動的に Private サブネットに侵入するのは難しい一方、**EC2 自身が悪意あるサーバーに通信を始めれば NAT GW は喜んで通す**——これが C2 通信や exfiltration が成立する理由です（`scripts/13_outbound_c2.sh`, `scripts/16_data_exfiltration.sh` 参照）。

## ハマりどころ

- **「IGW がアタッチされているのにインターネットに出られない」** → ルートテーブルに `0.0.0.0/0 → igw` を書き忘れている、またはサブネットが**間違ったルートテーブル**に関連付けられている
- **「パブリックサブネットなのに EC2 から ping できない」** → EC2 にパブリックIP/EIPが付いていない、または Security Group / NACL で塞がれている
- **「Private サブネットの EC2 から `yum update` できない」** → NAT Gateway が無いか、ルートテーブルのデフォルトルートが NAT を向いていない
- **NAT GW と NAT Instance の混同**：NAT GW はマネージドサービス（AWS が運用）、NAT Instance は EC2 を NAT として使う古い手法。本ラボは NAT Gateway

## 補完すべき本番向けコントロール

`architecture.md` の **"Required complementary controls for production"** に詳しいですが、要点だけ：

1. **IMDSv2 強制** (`http_tokens = "required"`) → SSRF からのクレデンシャル窃取を大幅軽減
2. **AWS WAF を ALB に** → アプリ層の攻撃をブロック
3. **最小権限 IAM + SCP** → 仮にクレデンシャルが漏れても被害を限定
4. **Egress フィルタ**（Security Group の outbound 制限、AWS Network Firewall、Route 53 Resolver DNS Firewall）→ NAT GW のフィルタなし問題を補う
5. **GuardDuty + CloudTrail** → 侵入後の検知

「Private サブネット = 安全」と思考停止しないこと。**Private サブネットは必要だが十分ではない**——これが本ラボから持ち帰るべき結論です。

## このシリーズの終わりに

ここまで読み終えれば：

- `architecture.md` の CIDR 表 → 各サブネットの役割が読める
- `terraform/main.tf` `routing.tf` `nat.tf` → 何を作って何を作らないか分かる
- `scripts/04_ssrf_metadata.sh` の流れ → どのレイヤを突いているか説明できる

実際に `terraform apply` → `run_all_attacks.sh` → `compare_results.sh` を回しながら、各ドキュメントに何度も戻ってください。**手を動かして初めて知識は定着します**。

## 関連リンク

- [00. インデックスに戻る](./README.md)
- [architecture.md（プロジェクト全体像）](../../architecture.md)
- [README.md（使い方）](../../README.md)
- [docs/packet-flow-trace.md（攻撃のパケット単位トレース）](../packet-flow-trace.md)
- [docs/design-decisions.md（設計判断の記録）](../design-decisions.md)
