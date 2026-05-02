# 06. ハンズオン：カスタムVPCとIGWを自分で作る

> このドキュメントが答える問い：「`terraform apply` の裏で、AWS のどのリソースがどの順番で作られている？ コンソールで手作業するなら何をすればいい？」

## ゴール

「VPC → サブネット → ルートテーブル → IGW」を**コンソールで手作業 → Terraform で自動化**の順に追体験し、本リポジトリの `terraform/main.tf` の意味を完全に理解する。

## 5 ステップで作るカスタム VPC

### Step 1. VPC を作る

| 項目 | 値 |
|---|---|
| 名前 | `custom-vpc` |
| CIDR | `10.0.0.0/16` |
| リージョン | `ap-northeast-1`（東京） |

このだけで「VPC」は完成。**自動で main route table と NACL が 1 つずつ作られます**。

### Step 2. サブネットを作る

| 名前 | AZ | CIDR | 役割 |
|---|---|---|---|
| `public-a`     | ap-northeast-1a | `10.0.1.0/24`  | ALB / NAT GW / Config A の EC2 |
| `public-c`     | ap-northeast-1c | `10.0.3.0/24`  | ALB（HA） |
| `app-private-a`| ap-northeast-1a | `10.0.10.0/24` | Config B の EC2 |
| `app-private-c`| ap-northeast-1c | `10.0.11.0/24` | （拡張用） |
| `db-private-a` | ap-northeast-1a | `10.0.20.0/24` | RDS |
| `db-private-c` | ap-northeast-1c | `10.0.21.0/24` | RDS（Multi-AZ要件） |

ポイント：

- **サブネットは必ず VPC の CIDR に収まる範囲で切る**。`10.0.0.0/16` から外れる CIDR を指定すると AWS にエラーで弾かれる
- **AWS は各サブネットの最初の 4 IP と最後の 1 IP（合計 5 個）を予約**する。`/24` で実際に使えるのは 251 IP

### Step 3. Internet Gateway を作って VPC にアタッチ

```
[Internet Gateway: custom-vpc-igw]
            │
       [Attach to VPC]
            ↓
        [custom-vpc]
```

IGW は **「VPC に対して 1 つだけ」**アタッチできる。アタッチしただけではまだ通信は流れません（次ステップ必須）。

### Step 4. ルートテーブルを作って関連付ける

3 種類のルートテーブルを作成：

#### Public Route Table

| Destination | Target |
|---|---|
| `10.0.0.0/16` | `local`（自動） |
| `0.0.0.0/0`   | `igw-xxxx`     |

→ `public-a`, `public-c` に関連付ける。**ここで初めてサブネットがパブリックになる**。

#### App Private Route Table

`config_mode = "private"` なら：

| Destination | Target |
|---|---|
| `10.0.0.0/16` | `local` |
| `0.0.0.0/0`   | `nat-xxxx`（NAT GW） |

→ `app-private-a`, `app-private-c` に関連付け

#### DB Route Table

| Destination | Target |
|---|---|
| `10.0.0.0/16` | `local` |

→ デフォルトルートなし。`db-private-a`, `db-private-c` に関連付け。完全に閉じる。

### Step 5. （Private モードのみ）NAT Gateway を立てる

| 項目 | 値 |
|---|---|
| 配置サブネット | `public-a`（必ず Public 側） |
| Elastic IP | 1 つ確保してアタッチ |

→ App Private Route Table のデフォルトルートを NAT GW に向ける。

## このリポジトリでの実装：`terraform/main.tf` を読む

ここまでをコードで宣言したのが `terraform/main.tf` と `terraform/locals.tf` です。

### `main.tf` の中で何が起きているか（疑似コード）

```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"          # ← Step 1
}

resource "aws_subnet" "public" {
  for_each   = local.public_subnets   # ← Step 2 (AZ-a, AZ-c の2つ作る)
  cidr_block = each.value.cidr
  availability_zone = each.value.az
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id            # ← Step 3
}

# routing.tf
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id   # ← Step 4
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public
  subnet_id = each.value.id
  route_table_id = aws_route_table.public.id
}

# nat.tf  (config_mode == "private" のときだけ作成される)
resource "aws_nat_gateway" "main" {
  count         = local.is_private ? 1 : 0     # ← Step 5
  subnet_id     = aws_subnet.public["a"].id
  allocation_id = aws_eip.nat[0].id
}
```

`for_each` と `count` を使い分けて、**「Config A では作らない／Config B では作る」リソース**を制御しているのがポイントです。詳細は [architecture.md の "Resource Switching by config_mode"](../../architecture.md) を参照。

## 動作確認

```bash
cd terraform
terraform apply -var="config_mode=public"

# VPC情報を確認
terraform output vpc_id
terraform output public_subnet_ids

# AWSコンソールでも見える
aws ec2 describe-vpcs --filters "Name=cidr,Values=10.0.0.0/16"
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)"
```

VPC ダッシュボード → Resource Map で**ビジュアルに確認**するのがおすすめです。

## 課金されるもの・されないもの

| リソース | 料金 | コメント |
|---|---|---|
| VPC | **無料** | いくつ作っても無料 |
| サブネット | **無料** | |
| ルートテーブル | **無料** | |
| Internet Gateway | **無料** | アタッチも無料 |
| **NAT Gateway** | **時間課金 + データ転送課金** | ap-northeast-1 で約 $0.062/h |
| **Elastic IP** | アタッチ中は無料、未使用時のみ課金 | NAT GW にアタッチしているなら無料 |
| **EC2 / RDS / ALB** | 各々課金 | 詳しくは README の Cost Estimate |

→ ラボ終了後は **必ず `terraform destroy`**。NAT GW と RDS と ALB が積み上がります。

## ハマりどころ

- **IGW を VPC にアタッチしただけでは何も通信できない**。ルートテーブルに `0.0.0.0/0 → igw` を書いて初めて意味を持つ
- **サブネット作成時に「自動でパブリックIPを割り当てる」フラグ**を ON にしないと、その後 EC2 を立てても自動でパブリックIPが付かない（`terraform/main.tf` の `map_public_ip_on_launch` を確認）
- **NAT Gateway は Public サブネットに置く**こと。Private に置くと自分が外に出られないので意味がない（パブリックIP/EIPが必要）
- **ルートテーブルを変更してもサブネット自体は再作成されない**が、**サブネットの CIDR を変えるとサブネット再作成**＝そこに乗っている EC2 も作り直しになる

## 次に読む

- [07. パブリックサブネット vs プライベートサブネット & NAT →](./07-public-private-subnet.md)
- 関連実装：`terraform/main.tf`, `terraform/locals.tf`, `terraform/routing.tf`, `terraform/nat.tf`
