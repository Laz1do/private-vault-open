# 私密密码库 · 自建同步服务器

Node.js 22 或更新版本，运行时无 npm 依赖。服务只保存当前加密快照，以及单调递增的同步版本号；不解密密码，不接收 AES 密钥，不输出请求正文或 token。服务器只需要同步 token 的 SHA-256 摘要。客户端安装包和客户端配置不得放在同步服务器上。

## Docker 部署

先在软件中导出 `.pvault` 文件，在本机源码根目录执行：

```sh
node tools/server-config.mjs --file /path/to/passwords.pvault --out server/server.env
```

只把生成的 `server.env` 和服务器程序复制到服务器。该文件只含 vault ID、token 摘要和运行参数，不含 AES 密钥、原始 token 或密码记录。密码文件留在本机，不能复制到服务器。工具拒绝覆盖现有配置；已有库部署应沿用原库 ID 和 token 摘要。`.env.example` 只是变量说明，不是可用凭据。

在本目录运行：

```sh
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8787/health
```

容器以非 root 用户运行。命名卷 `vault-data` 保存密文；重建容器不会清空卷。不要运行 `docker compose down -v`，它会删除密码库。只运行一个服务实例，不要让多个进程共享同一数据目录。

Docker 镜像构建上下文只包含服务器代码与 Dockerfile，配置文件不会复制进镜像。服务环境变量仍需受到服务器账户权限保护。

## HTTPS 与反向代理

有公共域名且本机 80/443 端口可用时，可直接使用本目录的 Caddy Compose 配置。在 `server/.env` 中写 `VAULT_DOMAIN=vault.example.com`（改成你自己的 DNS 名称，A/AAAA 指向服务器），放好 `server.env` 后执行：

```sh
docker compose -f compose.https.yaml up -d --build
docker compose -f compose.https.yaml ps
```

此配置不暴露 Node 8787 端口，Caddy 将 HTTPS 请求转发到内部服务并申请、续期证书。证书与密码密文分别保存在持久卷中。域名和开放端口要求见 [Caddy 自动 HTTPS 文档](https://caddyserver.com/docs/automatic-https)。该快速配置用于公共 DNS 名称；使用公网 IP 时，需要自行配置可信的 IP 证书和反向代理，不能以自签名证书或关闭证书验证替代。

服务器已有站点占用 80/443 时，使用下面的回环服务配置接入原有 HTTPS 代理。手机和 Windows 客户端使用 `https://vault.example.com` 根地址；软件只接受 HTTPS 公网地址和开发用回环 HTTP。

默认只映射宿主回环地址 `127.0.0.1:8787`。手机与其他电脑应访问服务器的 HTTPS 地址，由现有反向代理或隧道提供公网连接和 TLS。Node 服务本身只提供 HTTP；不要将明文 HTTP 端口直接暴露公网。反向代理与容器分开部署时，根据网络关系调整 upstream，不要把手机 endpoint 配成 `localhost`。

现有 Nginx HTTPS 站点可使用以下 location，证书和 `server_name` 由部署环境配置：

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Host $host;
    proxy_read_timeout 20s;
    client_max_body_size 8m;
}
```

反向代理不要记录 Authorization 或请求正文，也不要缓存 `/v1/vault`。常规只记录路径和响应状态的访问日志可以保留。HTTPS 地址和客户端中配置的 endpoint 必须一致。

## 直接运行

先通过部署环境设置下列环境变量，再运行：

```sh
node server.mjs
```

| 变量 | 含义 |
| --- | --- |
| `VAULT_DATA_DIR` | 必填；当前密文快照的可写目录 |
| `VAULT_TOKEN_HASH` | 必填；同步 token 的 64 位十六进制 SHA-256 摘要 |
| `VAULT_ID` | 必填；必须与客户端密码库 ID 相同 |
| `HOST` | 默认 `127.0.0.1`；容器内使用 `0.0.0.0` |
| `PORT` | 默认 `8787` |

限制数据目录权限为服务器运行账户可读写。运行中只有 `vault-state.json` 和写入过程中的临时文件；临时文件不是历史备份。启动会删除未完成写入的临时文件，并读取已提交的当前状态。损坏状态或错误 vault ID 会使启动失败，不会静默创建空库。

## 接口与限制

- `GET /health`：无需凭据，仅返回 `{"ok":true}`。
- `GET /v1/vault`：Bearer 鉴权，返回 `{revision,envelope}`；空库为 revision 0、envelope null。
- `PUT /v1/vault`：Bearer 鉴权，JSON 正文 `{expectedRevision,envelope}`。版本相同才原子替换并返回新的 `{revision}`；不相同返回 409 `revision_conflict`。在同一进程内串行比较和提交。
- 不提供网页、安装包下载或其他接口；路径必须精确匹配，不接受查询参数。token 摘要通过固定长度恒定时间比较验证。
- Envelope 精确包含 `v:1`、相同 `vaultId`、`alg:"A256GCM"`、规范 Base64 的 12 字节 nonce，以及包含 GCM tag 的 Base64 密文。服务器只能检查格式，无法判断密文能否被客户端成功解密。
- 密文上限 4 MiB，含 16 字节 GCM tag；整个 HTTP JSON 正文上限 8 MiB。错误 JSON/字段返回 400，超大正文返回 413，非 JSON 正文返回 415。未授权返回 401，其他路径返回 404。

文件内容先写入同目录的独占临时文件并 fsync，再原子重命名。Unix 同时 fsync 数据目录。Windows 使用原子重命名，但 Node 不提供相同方式的目录 fsync。已有密文不会因为保存失败而被截断。

## 验证

```sh
node --test tests/server.test.mjs
```

测试使用临时目录和模拟密文，涵盖鉴权、并发 CAS、重启恢复、磁盘中无测试明文，以及格式和体积限制。
