# PIN/UV 密钥协商与 hmac-secret 的信任边界评估

仓库：libfido2（分支 task/317，基线提交 308b5e7）
范围：`src/ecdh.c`、`src/pin.c`、`src/aes256.c`、`src/authkey.c`、`src/cbor.c`、`src/cred.c`、`src/assert.c`、`src/dev.c`
日期：2026-11-23

## 1. 信任边界总览

PIN/UV 与 hmac-secret 共用同一条信任链：

```
authenticatorGetInfo（未签名）
        │  决定 pinProtocol / pinUvAuthToken / uv 等能力标志
        ▼
clientPIN getKeyAgreement（authkey，未认证）
        │  匿名 ECDH → sharedSecret
        ▼
kdf()（协议 1: SHA-256；协议 2: HKDF×2）
        │  派生 HMAC key / AES key
        ▼
AES-256-CBC 加密 PIN/盐值  ←→  AES-256-CBC 解密 token / hmac-secret
```

链上有两个独立的信任假设，必须分开讨论：

- **链路可信**：主机与认证器之间的传输（USB HID / NFC / BLE）没有被中间人篡改或窃听。CTAP 的 ECDH 是**匿名**的（`fido_do_ecdh()` 对 `fido_dev_authkey()` 返回的公钥不做任何认证，`src/ecdh.c:166`、`src/authkey.c:104`），因此链路可信**无法由协议自身建立**，只能由物理/系统层保证（独占打开 hidraw 设备、NFC 近距离、操作系统中介如 Windows Hello）。
- **设备可信**：对端确实是用户以为的那枚认证器，且其固件未被篡改。设备的一切自我声明（getInfo 中的 `pinProtocols`、`options`、重试计数）都只是声明，不是证明；报告后文所有结论均不把这些声明当作独立证据。

两个假设相互独立：链路可信不代表设备可信（设备可能被换壳/固件篡改），设备可信也不代表链路可信（NFC 中继、恶意 USB 集线器可在真实设备前做 MitM）。

## 2. 协议协商：设备声明即唯一输入

### 2.1 现状

- `fido_dev_set_protocol_flags()`（`src/dev.c:67`）把 getInfo 的 `pinProtocols` 数组直接翻译成 `FIDO_DEV_PIN_PROTOCOL1/2` 标志；未知值仅记录日志后忽略。
- `fido_dev_get_pin_protocol()`（`src/dev.c:581`）**静态偏好协议 2**：只要标志位含 2 就用 2，否则用 1，都没有则返回 0（后续 `cbor_encode_pin_opt()` 失败，`src/cbor.c:829`）。
- 没有公开 API 允许调用方设定最低可接受协议，也没有"上次见过协议 2、这次不见了"的粘性检查。`fido_dev_force_u2f()`（`src/dev.c:568`）还会把标志清零。
- `pinUvAuthToken` 选项位（`src/dev.c:58`）决定走 CTAP2.1 的 `getPinUvAuthTokenUsingPinWithPermissions`（带子命令 9、权限位、rpId 绑定）还是回退 CTAP2.0 的 `getPinToken`（子命令 5，无权限、无 rpId 绑定，`src/pin.c:300-317`）。

### 2.2 不可信传输对端（链路攻击者）能造成的降级

链路攻击者能篡改 getInfo 响应（该响应不签名），因此可以：

1. **协议降级 2→1**：从 `pinProtocols` 中删掉 2。后果：
   - KDF 从 HKDF-SHA256（双输出、info 分离）退化为单次 SHA-256（`src/ecdh.c:84-108`）；
   - PIN/盐值加密从随机 IV 的 CBC（`aes256_cbc_fips`，`src/aes256.c:105`）退化为**全零 IV** 的 CBC（`aes256_cbc_proto1`，`src/aes256.c:94`）。同一 ECDH 会话内，PIN 哈希密文与 hmac 盐值密文使用同一密钥同一 IV，首块相等性泄露；SHA-256(PIN) 的密文是确定性的，跨会话重放/等价性观察成为可能（每次会话密钥虽新，但低熵 PIN 的密文在同一密钥下可比对）；
   - pinAuth 从完整 32 字节 HMAC 截断为 16 字节（`src/cbor.c:823`）。
   这些都在 CTAP 规范允许范围内，属于"合法但更弱"，库不会报警。
2. **令牌作用域降级**：删掉 `pinUvAuthToken` 选项位，迫使 `uv_token_wait()` 走 CTAP2.0 路径，拿到无权限、无 rpId 绑定的 token——攻击者若截获该 token 密文并能在链路上重放，可跨命令、跨 RP 使用。
3. **伪造重试计数**：`parse_retry_count()`（`src/pin.c:565`）原样采信设备上报的剩余次数，可诱导用户反复输入 PIN 或放弃操作（可用性/钓鱼面，非密钥面）。

链路攻击者**不能**做的：在仅被动窃听时恢复 PIN 或共享密钥（ECDH 本身抗被动监听）；在设备可信且使用协议 2 时解密历史会话（前向安全性受 ephemeral 主机密钥保护，`fido_do_ecdh()` 每次新建密钥对）。

### 2.3 被篡改认证器能造成的错误密钥使用

设备端攻击者不需要降级——它本身就是 ECDH 的对端，**天然知道 sharedSecret**，因此：

- 直接解出 `SHA256(PIN)[:16]`（`pin_sha256_enc`，`src/pin.c:28`），对低熵 PIN 可离线爆破。这是 CTAP 的固有属性：PIN 加密只防链路，不防对端。
- 在 `uv_token_rx`（`src/pin.c:255`）中返回任意长度（16 的倍数即可）的"token"密文；库解密后**不校验长度**（规范要求 16 或 32 字节），该 token 随后直接作为 HMAC 密钥使用（`cbor_add_uv_params` → `cbor_encode_pin_auth`，`src/pin.c:739`、`src/cbor.c:796`）。
- 在 hmac-secret 输出中返回任意长度的密文（见第 4 节）。
- 谎报能力位，诱使库走它偏好的路径（同 2.2，但无需篡改链路）。

结论：**设备声明只能用于"能力发现"，不能用于"安全决策"**。当前代码把声明同时用于两者（协议选择直接影响 KDF 与加密强度），这是最主要的信任边界模糊点。

## 3. 令牌解密：无完整性、无长度校验

`uv_token_rx()` 的解密路径：

1. `cbor_parse_reply` 只检查状态字节与 CBOR 结构（`src/cbor.c:121`）；
2. `aes256_cbc_dec()` 按 `fido_dev_get_pin_protocol()` 选择协议 1（零 IV）或协议 2（密文首 16 字节为 IV，`src/aes256.c:240`）；
3. CBC 解密**没有任何完整性保护**（无 HMAC、无填充校验，`aes_cbc()` 只要求输入长度为 16 的非零倍数，`src/aes256.c:33`）；
4. 解密结果直接存入 `token`，不校验长度是否为规范的 16/32 字节。

影响评估：

- **链路攻击者**对 token 密文做比特翻转 → 解密出错误 token → 后续 pinAuth 校验失败（认证器侧拒绝）。仅可用性影响，但错误被归因为 `FIDO_ERR_RX`/`FIDO_ERR_INTERNAL`，与"设备故障"不可区分，排障困难。
- **被篡改认证器**可给出 48、64 字节等超长 token；HMAC 接受任意长度密钥，库不会拒绝——密钥材料的长度语义完全由对端决定，属于"错误密钥使用"的温床（例如协议 2 下给出 16 字节 token，使 HMAC 密钥熵低于预期）。

## 4. hmac-secret 输出：解密先于验证，长度不校验

### 4.1 现状

- 盐值**输入**有校验：`cbor_encode_hmac_secret_param()` 要求 32 或 64 字节（`src/cbor.c:623`）。
- 秘密**输出**无校验：`decrypt_hmac_secret()`（`src/cred.c:192`）与 `decrypt_hmac_secrets()`（`src/assert.c:289`）解密后不检查 `hmac_secret.len`。规范要求输出为 32（单盐）或 64（双盐）字节；当前实现接受任意 16 的倍数，并通过 `fido_cred_hmac_secret_ptr()` / `fido_assert_hmac_secret_ptr()` 原样交给调用方——调用方若假定 32 字节，即发生长度混淆的错误密钥使用。
- **解密发生在签名验证之前**：`fido_dev_get_assert()` 在返回前就完成解密（`src/assert.c:357-363`），而扩展掩码一致性检查（`check_extensions`，`src/assert.c:395`、`src/cred.c:267`）只在调用方主动调用 `fido_assert_verify()` / `fido_cred_verify()` 时才执行。应用在验证签名前就可能已经消费了 `hmac_secret`。
- 多条断言时，`decrypt_hmac_secrets()` 对缺少扩展的语句**静默跳过**（`src/assert.c:295`），不报错；攻击者（链路或设备）可选择性地只让部分语句携带 hmac-secret 输出。
- makeCredential 的 `hmac-secret-mc` 输出位于 authdata 扩展中、受证明签名覆盖，但 `attestation=none` 或自证明时该签名不构成对调用方的证明；且同样是在 `fido_cred_verify()` 之前就已解密。

### 4.2 威胁归属

- **链路攻击者**：可篡改扩展密文造成解密出垃圾秘密（无完整性），或从 authdata 中剥离扩展（若调用方不调用 verify 则静默成功）。两类攻击都在"调用方先 verify 再使用秘密"的前提下被阻断——但这个前提目前**只由调用方纪律保证，库不强制**。
- **被篡改认证器**：可返回长度异常的秘密、对多语句选择性输出、在 `attestation=none` 下任意伪造。此时签名验证也不构成防御（签名密钥就在攻击者手里），唯一的边界是"调用方是否信任该设备的证明链"。

## 5. 秘密派生：KDF 输入全部来自对端声明

- `kdf()`（`src/ecdh.c:78`）的协议分支完全由 `fido_dev_get_pin_protocol()` 决定，而该值来自未认证的 getInfo。协议 1 的 SHA-256(secret) 与协议 2 的 HKDF(secret, salt=0, info="CTAP2 HMAC/AES key") 输出长度不同（32 vs 64 字节），`aes256_cbc_enc/dec` 与 `cbor_encode_pin_auth` 都按同一标志位解释密钥布局（`src/aes256.c:236`、`src/cbor.c:815`）。标志位一旦被降级，整条派生链同步降级，无任何交叉校验。
- 正面事实：主机侧 ECDH 私钥每次会话 ephemeral（`fido_do_ecdh()`），OpenSSL 的 `EVP_PKEY_derive` 会校验对端公钥点是否在曲线上，无效曲线攻击面有限；`es256_pk_from_EC_KEY()` 也做 `EC_POINT_is_on_curve` 检查（`src/es256.c:361`）。注意 `es256_pk_to_EVP_PKEY()`（`src/es256.c:269`）本身不做曲线上检查，依赖 OpenSSL 在 derive 时兜底。
- HKDF 的 salt 固定为 32 字节零（`src/ecdh.c:45`），符合 CTAP 规范，不构成问题，但意味着协议 2 的全部额外强度来自 info 分离与双输出，而非 salt。

## 6. 兼容方案建议

原则：不改变对规范兼容设备的线上行为，只增加"声明与结果"的交叉校验，并把安全决策从设备声明中剥离。

### 6.1 协议选择

1. **增加最低协议下限（可选 API，默认保持现状）**：如 `fido_dev_set_min_pin_protocol(dev, 2)`。设定后，`fido_dev_get_pin_protocol()` 在设备未声明协议 2 时返回 0 而非静默降到 1，使 `cbor_encode_pin_opt()` 失败、操作中止。默认不设限，完全向后兼容。
2. **粘性协商（sticky negotiation）**：在同一 `fido_dev_t` 生命周期内，若 getInfo 曾声明协议 2，后续 re-open/re-info 中协议 2 消失时记日志或失败，抵抗"先探测后降级"。
3. **权限位降级的显式化**：`pinUvAuthToken` 缺失导致回退 CTAP2.0 `getPinToken` 时，通过 `fido_log_debug` 之外的可观察途径（新返回码或查询 API）告知调用方"token 无权限/rpId 绑定"，由调用方决定是否接受。
4. **不把重试计数用于安全决策**：文档化 `fido_dev_get_retry_count()` 仅为 UI 提示。

### 6.2 解密结果校验

1. **token 长度白名单**：`uv_token_rx()` 解密后要求 `token->len ∈ {16, 32}`（协议 2 建议只接受 32），不符即 `FIDO_ERR_RX` 并清零缓冲区。
2. **hmac-secret 长度白名单**：`decrypt_hmac_secret(s)` 解密后要求 `len ∈ {32, 64}`，且与请求的盐值长度一致（单盐 32、双盐 64）；不符即失败并 `fido_blob_reset()`。
3. **多语句完整性**：`decrypt_hmac_secrets()` 在请求了 `FIDO_EXT_HMAC_SECRET` 时，若任一语句缺少扩展则整体失败，而非静默跳过（与 `check_extensions` 的严格语义对齐）。
4. **解密与验证的顺序**：在 `fido_dev_get_assert()` / `fido_dev_make_cred()` 文档与 man 页中明确"返回的 hmac_secret 在 `fido_*_verify()` 成功前不可信"；更进一步的兼容做法是在解密前先做扩展掩码的本地比对（请求掩码 vs 返回掩码），掩码不符直接拒绝解密——这不依赖签名验证，纯本地即可执行，且对合规设备无行为变化。
5. **错误归因**：CBC 解密失败、长度校验失败、pinAuth 被拒分别映射到不同返回码/日志，避免把主动攻击与设备故障混为一谈。
6. **密钥清零**：`fido_dev_get_uv_token_wait` 的临时 `ecdh`/`token` 已走 `fido_blob_free`（内部清零），保持；建议对 `dev->puat` 在 `fido_dev_close` 时显式 `fido_blob_reset`（`fido_dev_get_puat` 已做重置，关闭路径值得复核）。

### 6.3 何时可以认为"设备可信"与"链路可信"

- **链路可信**的条件（满足其一）：物理独占的 USB 连接且主机 USB 栈可信；操作系统中介的受信通道（Windows Hello 的 `USE_WINHELLO` 路径）；NFC/BLE 在受控物理环境且接受中继残余风险。CTAP 协议本身**永远不提供**链路认证——匿名 ECDH 只保证被动窃听安全。
- **设备可信**的条件（需同时满足）：设备证明（attestation）链到可信根且调用方验证了 `fido_cred_verify()`；设备固件/硬件来源可信（供应链）；getInfo 声明仅作能力发现、不作安全决策（即落实 6.1）。在 `attestation=none` 时，设备可信**无法建立**，此时 hmac-secret 输出只能视为"与某枚自称的设备共享的秘密"，不能视为"与用户的设备共享的秘密"。

## 7. 结论

- 最严重的问题不是密码学缺陷，而是**信任来源混淆**：协议强度、token 长度、秘密长度三个安全关键参数全部单方面取自未认证的设备声明或设备提供的密文，库内无交叉校验。
- 链路攻击者的现实收益主要是**降级**（协议 2→1、权限 token→裸 token）与**可用性破坏**；被篡改认证器的收益是**错误密钥使用**（任意长度 token/秘密、PIN 哈希离线爆破）。两者应分开防御：前者靠粘性协商与最低协议下限，后者靠解密结果白名单校验与"先验证后使用"的调用纪律。
- 第 6 节的全部建议均可在不破坏规范互操作的前提下实现：对合规设备行为不变，对异常声明/异常密文从"静默接受"变为"显式失败"。
