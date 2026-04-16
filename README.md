# Autocerts

一个运行在阿里云函数计算上的无状态证书服务，用于签发、托管和自动续期 HTTPS 证书。
无需数据库，服务器，几乎不需要费用。

支持能力：

- 使用 Let's Encrypt 通过 `DNS-01` 签发证书
- 签发时显式指定 `dns_provider=cloudflare|aliyun`
- 将证书上传到阿里云 SSL 证书管理 V2.0
- 扫描并续期 ALB、CDN、OSS Bucket CNAME、函数计算自定义域名正在使用的证书

## 部署

部署云函数和云函数的artifact bucket。

### 云函数环境变量

| 变量 | 说明 |
| --- | --- |
| `ACME_EMAIL` | Let's Encrypt ACME 邮箱，填一个能收到邮件的就行，不需要注册 |
| `CRON_INTERVAL` | `reconcile` 模式阈值，例如 `24h` |
| `ACME_ACCOUNT_PRIVATE_KEY_PEM` | 建议配置，避免每次冷启动生成新 ACME 账号；支持多行 PEM，也支持单行 `\\n` 转义 PEM |

生成 `ACME_ACCOUNT_PRIVATE_KEY_PEM` 的一个简单方式：

```bash
ssh-keygen -t ecdsa -b 256 -m PEM -f acme_account.key -N ""
cat acme_account.key
```


### 函数计算授权最小 RAM 权限
配置给函数计算FC的授权策略请见[role.yaml](./role.yaml).


## 操作

### 签发证书

方式一: 向云函数提交一个事件触发
```json
{
  "mode": "issue",
  "domains": "example.com,*.example.com",
  "dns_provider": "aliyun"
}
```

方式二: 使用autocerts CLI

安装autocerts

```shell
go install ./cmd/autocerts
```

运行指令

```shell
autocerts issue -domains example.com,*.example.com -dns-provider aliyun
```

dns_provider可选 `aliyun` 和 `cloudflare`. 如果是cloudflare，确保云函数环境变量有以下配置：

| 变量 | 说明 |
| --- | --- |
| `CLOUDFLARE_API_KEY` | 必填 |
| `CLOUDFLARE_EMAIL` | 可选；配置后使用 `email + global api key` |

### 自动更新证书

方式一: 向云函数提交一个事件触发

```json
{ "mode": "reconcile" }
```

在云函数配置定时任务时，让触发器写入的事件就写这个。

方式二：autocerts手动触发

```shell
autocerts reconcile
```

如果 `REGIONS` 里某个地域没有函数计算 endpoint，`reconcile` 会把该地域的 FC 扫描记为 warning 并跳过；同一地域里的 `ALB` 和全局 `OSS` 扫描不受影响。
