# 协作接口 v0.2.0

## 密码库与密文

`Vault = {schema:1,vaultId,records:{[recordId]:Version[]}}`。`Version = {id,ancestors,kind:'put'|'delete',entry,deviceId,updatedAt}`；`Entry = {title,username,password,url,notes}`。随机版本 ID 与因果前驱决定合并顺序，时间只用于展示。删除保留标记，旧文件和离线客户端不会恢复已经删除的记录。并发头需用户选择，resolve 包含全部已见头的前驱。

`Envelope = {v:1,vaultId,alg:'A256GCM',nonce:base64,data:base64}`。32 字节随机库密钥，12 字节随机 nonce，16 字节 GCM tag，AAD 为 `private-vault/v1/` + vaultId。密文上限 4 MiB，HTTP JSON 和便携文件上限 8 MiB。

## 便携文件

严格 JSON：`{format:'private-vault-file',version:1,profile:{vaultId,keyB64,token,endpoint},vault:Vault}`。这是**无密码、可直接读取**的文件，包括库密钥和连接权限。没有 deviceId 或 mode；导入保留目标设备身份和模式。新空库可接纳其他库，已有记录/墓碑或恢复态只接受同库，库 ID 相同但不同密钥也拒绝。同库合并保留因果关系；文件不是可回滚的历史备份。

## Host

Promise API：`getConfig()` -> profile 加 `mode:'file'|'server'` 和可选 deviceLabel；旧库缺少密钥时返回 null。

- `readLocal()` -> null 或 `{deviceId,envelope}`；`writeLocal(local)` 保留已有 profile。
- `writeState(config,local)` 原子提交配置与密文。Windows DPAPI / AndroidKeyStore 包裹 profile，无明文降级。
- `chooseImportFile()` -> UTF-8 文本或取消时 null；`saveExportFile(text)` -> 保存成功 bool。
- `request(method,'/v1/vault',body?)` 只在 server 模式允许 GET/PUT，凭据由 native 添加，只发送密文。公网必须 HTTPS 根地址，允许开发用回环 HTTP；不跟随重定向。
- `copyText(text)` 与 `openExternal(url)`。

内部 state 损坏时停止读写，不静默重建。旧 vault.json 不能因缺密钥覆盖；恢复导入先验证原密文，再原子建立新 state，旧文件保留。

## Client

`await createVaultClient(host)` 提供 `snapshot/subscribe/save/remove/resolve/sync/exportFile/importFile/setMode/configureServer`。快照含 records/status/message/lastSync/configured/pending/mode/serverEndpoint/vaultId/needsImport，不含密钥或原始访问凭据。所有编辑、导入和配置修改串行；模式切换等待在途同步完成，file 模式核心和 native 双重禁网。导出等待已排队编辑。坏文件验证失败不更改配置或数据。

旧库缺少原 profile 时 needsImport 为 true，暂停编辑、导出及同步；导入同库文件后验证旧密文、合并并保留原设备身份。getConfig 无 mode 的旧协议按 server 处理，公开新 profile 默认 file。

## 同步服务

一个实例仅保存一个库的密文当前状态。配置只有 VAULT_ID、VAULT_TOKEN_HASH 与运行参数，不接收客户端密钥。

- `GET /health` 返回 `{ok:true}`。
- Bearer 鉴权 `GET /v1/vault` -> `{revision,envelope}`，空库 `{revision:0,envelope:null}`。
- `PUT /v1/vault` 接收 `{expectedRevision,envelope}`，CAS 匹配后原子提交并 revision+1，否则 409。客户端重新读取、因果合并和重试，期间发生的本机编辑必须保留。

服务器对结构、ID 和体积进行检查，无法验证或解密内容；不记录请求正文或凭据。
