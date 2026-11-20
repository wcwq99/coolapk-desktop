# 酷安 Android 客户端请求算法静态分析

> 目标 APK：`coolapk-16.7.3.apk`（`versionName=16.7.3` / `versionCode=2611121`，minSdk 24 / targetSdk 34）
> 对齐工程：`coolapk-desktop`（Tauri/Rust，`src-tauri/src/coolapk/`）
> 文档目的：**APK 每次更新后，用它判定参考工程的请求实现是否失效，并给出可执行的复检与重取步骤。**
> 最后验证：2026-11-19，在线回归 **24/24 通过**（`verify_report.txt`）。

证据标记：

| 标记 | 含义 |
| --- | --- |
| `[静态]` | 直接从 APK 文件里读到的字节/符号 |
| `[在线]` | 用构造请求打真实网关得到的对照结论（A/B 反证，已固化为 `verify_live.py` 用例） |
| `[对齐]` | 与参考工程实现一致，作为交叉验证 |
| `[推断]` | 合理推断，未取得直接证据 |

---

## 0. 一句话结论

酷安客户端的请求可信度由 **四层** 组成，全部无需登录：

1. **Token V3**（`X-App-Token`）：`md5` + `bcrypt(cost=4)` 链，密码表以 **XOR 0x5A** 固化在 `libauth.so` —— 唯一的"秘密"；
2. **设备码**（`X-App-Device`）：9 字段 `; ` 拼接 → base64 → 字符逆序 → 去 `=`；
3. **UA 模板**：`Dalvik/... (#Build; ...) +CoolMarket/<版本>-<构建号>-universal`，网关强校验；
4. **写接口风控**（仅少数路径）：易盾 `_v2_post_token` 表单字段 + `ddid` Cookie，业务 ID 与路径清单由 `/v6/main/init` 服务端下发。

除第 4 层依赖网易易盾 native SDK 运行时而无法离线生成外，其余三层均可纯静态离线复刻；
其中 Token V3 已能在**不联网**的情况下，把一条真实官方客户端抓包的 token **逐字符复现**（见 §3.5）。

---

## 1. 静态分析前提：这个 APK 是被加固的

| 事实 | 证据 |
| --- | --- |
| `classes.dex` 只有 **30 个类 / 956 个字符串**，全部是 `com.netease.nis.wrapper.*`（网易易盾壳）+ `a/auu/a` | `apk_res/classes.dex` 头表解析 |
| 该 dex 声明 `file_size=98518552`，但有效表只覆盖前 ~64KB，其余是加密载荷 | dex 头 `map_off=62988` |
| 全 APK 只有 **1 个** dex 魔数（偏移 0），真实业务 dex 不在明文里 | 全文件 `dex\n035` 搜索 |
| `jadx` 全量反编译只产出 31 个文件（`jadx_out/`、`jadx_full/`） | 业务代码是运行期解密的 |
| 业务代码包名被混淆为 `com/byaztp`，字符串被易盾加密（`X-App-Token`、`coolapk` 等明文串在 dex 中查不到） | `dex_out/dex_746fa7a000.dex`：完整未截断的 8.16MB dex，8522 个 `com/byaztp` 类型描述符 |

**结论：不要指望在 Java 层读签名逻辑。**
- 上一轮从内存 dump 出的 12 个业务 dex 在 `dex_out/`，但多数在 8MB 处被截断（`header_file_size` > 实际大小）；完整的只有 `dex_7421c05000`、`dex_7468e51000`、`dex_746fa7a000`、`dex_748d2e2000`、`dex_77672a7de0`；
- 且字符串被加密：结构可看、常量不可看；
- 因此本项目的突破口是 **native 库 `libauth.so`** + **服务端 A/B 反证**。

---

## 2. 请求头契约（完整清单）

`X-Requested-With: XMLHttpRequest` 是**硬性要求**：缺失时网关返回 `HTTP 404 + {"status":1000,"message":"请求方式错误"}`，极易被误判成"签名错误"。

| Header | 取值 | 是否被校验 | 证据 |
| --- | --- | --- | --- |
| `User-Agent` | 见 §5 | **强校验**，缺 `+CoolMarket/...` 后缀或只改版本号 → `403` | `[在线]` 2 例 |
| `X-App-Id` | `com.coolapk.market` | **请求头层面校验包名**：改成别的包名 → `1002 应用未授权`；同时该值参与签名 | `[在线]` |
| `X-App-Version` | `16.7.3` | **强校验**，旧值 → `403` | `[在线]` |
| `X-App-Code` | `2611121` | **强校验**，旧值 → `403` | `[在线]` |
| `X-Api-Version` | `16` | **强校验**，`15`/`99` → `403` | `[在线]` |
| `X-App-Device` | 见 §4 | **必带且参与签名**，缺失/与 token 不配对 → `1004` | `[在线]` 2 例 |
| `X-App-Token` | 见 §3 | **必带**，缺失/伪造 → `1004` | `[在线]` 2 例 |
| `X-Requested-With` | `XMLHttpRequest` | **必带**，缺失 → `404 + status 1000` | `[在线]` |
| `X-App-Supported` | `2611121` | 不校验（乱填 `999` 仍 `200`） | `[在线]` |
| `X-Dark-Mode` | `0` | 不校验 | `[在线]` |
| `X-Sdk-Int` | `36` | 不校验（`99` 仍 `200`） | `[在线]` |
| `X-App-Mode` | `universal` | 不校验（置空仍 `200`） | `[在线]` |
| `X-App-Channel` | `coolapk` | 未单独做反证 | `[对齐]` |
| `X-Sdk-Locale` | `zh-CN` | 未单独做反证 | `[对齐]` |
| `Cookie` | 登录态凭据（`SESSID`/`uid`/`username`/`token`） | 登录态接口必需 | `[对齐]` |

`api2.coolapk.com` 与 `api.coolapk.com` 使用同一套头与签名规则 —— `[对齐]`（未单独反证）。

> ⚠️ 区分两种"app_id 改动"，返回码不同，别混：
> - 改 **`X-App-Id` 请求头** → `1002 应用未授权`（网关的包名授权检查）；
> - 只改 **签名输入里的 app_id**（头仍是 `com.coolapk.market`）→ `1004 请求验证错误`（bcrypt 对不上）。

---

## 3. 算法 A：`X-App-Token`（Token V3）★核心

### 3.1 载体与符号 `[静态]`

`lib/arm64-v8a/libauth.so`（914,928 字节；本 APK 只打包了 arm64-v8a）：

| 符号/字符串 | 说明 |
| --- | --- |
| `JNI_OnLoad` + 字符串 `getToken` + `com/coolapk/market/util/AuthUtils` | 通过 `RegisterNatives` 注册（无 `Java_*` 导出符号）；Java 侧类为 `com.coolapk.market.util.AuthUtils` |
| `_Z3md5NSt6__ndk112basic_string...` / `_ZN3MD5*` | 自带 MD5 |
| `_Z13base64_decode...` / `_Z13base64_encode...` / `_Z10trimBase64...` | 自带 base64（含一处 `trimBase64`） |
| `bcrypt_hashpw` / `bcrypt_gensalt` / `bcrypt_checkpw` / `_crypt_gensalt_blowfish_rn` | 自带 OpenBSD bcrypt |
| `./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789` | **bcrypt 的 base64 变体字母表**（起始 `.` `/`） |
| `getPackageName` / `getVersionCode` / `getAppSignature` / `verifyAppSignature` | 运行时取 `X-App-Id`、`X-App-Code`，并做签名自校验（反篡改） |

**推论**：`X-App-Id` 与 `X-App-Code` 不是写死常量，而是运行时 `getPackageName()` / `getVersionCode()` 的返回值 —— 与 `[在线]` 结论（改它们会导致验签失败）一致。

### 3.2 密码表：唯一的"秘密"及其定位 `[静态]`

| 项 | 值 |
| --- | --- |
| 载体 | `lib/arm64-v8a/libauth.so` |
| 偏移 | **264422**（十进制；不要依赖它） |
| 形态 | 1240 字符 base64 串（可打印 ASCII） |
| 解码 | base64 → **930 字节** |
| 还原 | 逐字节 **XOR `0x5A`** → 930 字符 base64 文本（"密码表"） |
| 算法实际读取区间 | **仅 `[128, 652)`**：时间槽 `slot*4 + 128`，`slot ∈ [0,100)`，窗口长 128 |
| 校验特征 | 该区间内 100 个窗口解码后都是 96 字节可打印 ASCII |

> 表的其余字节（`[0,128)` 与 `[652,930)`）不参与签名计算，但仍随版本变化 —— 比对版本差异时**整表**都要比。

参考工程 `coolapk-desktop/src-tauri/src/coolapk/auth_blob.b64` 的内容就是这 930 字符表的二次 base64 —— 已验证与 APK 提取结果**逐字节相等**。

**不要用偏移定位，用结构搜索**：

```bash
python apk_extract.py coolapk-<版本>.apk
# 输出示例：
#   entry=lib/arm64-v8a/libauth.so offset=264422 xor=0x5A b64_len=1240
#   [result] 已写出: coolapk-<版本>_token_table.txt
# 退出码：0=找到  2=未找到（先排除"表换了后缀/换了长度"，再怀疑算法变更）  1=异常
```

`apk_extract.py` 的识别条件（不依赖偏移）：

1. 扫描 `.so` / `.dex` / `.dat` / `.bin` 里长度 ≥ 200 的 `[A-Za-z0-9+/]` 连续段；
2. 以 4 字符对齐滑窗，取 1240 字符 → base64 解码，长度必须恰为 930 字节（应对与相邻 base64 粘连）；
3. 先试 XOR `0x5A` 快路径，若无命中再全量 256 key 扫描；
4. 结果必须通过 §3.2 的"100 窗口可打印"校验。

### 3.3 签名算法（8 步）

设 `ts` = Unix 秒；`verCode` = APK `versionCode`；`device` = `X-App-Device` 头原值（完整字符串）。

```
① idx      = ((ts + verCode) % 100) * 4 + 0x80
② segment  = base64_decode( table[idx : idx+128] )        # 96 字节 ASCII
③ plain    = "com.coolapk.market" & segment & md5_hex(device) & ts & verCode
             （& 为字面分隔符，共 5 段）
④ password = md5_hex( base64_std(plain) )
⑤ saltSrc  = base64_std( "%x/%s" % (ts, md5_hex(plain)) ).rstrip("=")
⑥ salt22   = saltSrc[0:21] + "."                          # 第 22 位固定为 '.'
⑦ hashStr  = bcrypt( password, "$2y$04$" + salt22, cost=4 )
⑧ token    = "v3" + base64_std( hashStr ).rstrip("=")
```

要点：

- **时间槽**：`(ts + verCode) % 100` 共 100 个槽，槽间距 4 字符 → 相邻窗口高度重叠，窗口固定 128 字符；
- `0x80` 偏移不可省（少 `0x80` → `1004`，已证）；
- `cost` 由 token 自身携带，服务端按 token 里的 cost 重算（`cost=10` 仍 `200`，已证）；官方客户端用 **4**；
- `salt22` 第 22 位是 `'.'`，不在标准 base64 字母表内，但 bcrypt 只取该字符高 2 位，实机 token 逐字节一致；
- bcrypt 结果统一用 `$2y$` 前缀再做 base64（`$2b$` 与 `$2y$` 的 hash 体相同，仅前缀不同）；
- 第 ④ 步的 `base64` 与第 ⑤ 步都是**标准 base64（含 `+` `/`）**，不是 bcrypt 字母表。

### 3.4 服务端校验语义 `[在线]`（对应 `verify_live.py` 的 24 条用例）

| 破坏项 | 期望 | 实际返回 |
| --- | --- | --- |
| 基线（正确 token） | 通过 | `200 {"data":...}` |
| 缺 `X-App-Token` | 拒绝 | `1004 请求未验证` |
| 缺 `X-App-Device` | 拒绝 | `1004 请求验证错误` |
| 缺 `X-Requested-With` | 拒绝 | `404 + 1000 请求方式错误` |
| 时间槽少 `0x80`（签名输入） | 拒绝 | `1004` |
| 签名输入 `app_id` 被改 | 拒绝 | `1004` |
| 签名输入 `verCode` 被改 | 拒绝 | `1004` |
| `X-App-Id` 请求头被改 | 拒绝 | `1002 应用未授权` |
| `X-App-Device` 与 token 不配对 | 拒绝 | `1004` |
| 凭空伪造 `v3...` | 拒绝 | `1004` |
| `bcrypt cost=10` | 通过 | `200`（cost 由 token 自述） |
| 时间戳回退 23h | 通过 | `200` |
| 时间戳回退 25h | 拒绝 | `1005 请求已过期` |
| 时间戳前推 10min | 通过 | `200` |
| 时间戳前推 30min | 拒绝 | `1005 请求失败：你当前的请求时间为…` |
| `X-Api-Version=15` | 拒绝 | `403`（空体） |
| `X-App-Version=16.2.0` | 拒绝 | `403` |
| `X-App-Code=2604201` | 拒绝 | `403` |
| UA 去掉 `+CoolMarket` 后缀 | 拒绝 | `403` |
| UA 只把版本号改成 `16.2.0-2604201` | 拒绝 | `403` |
| `X-App-Supported=999` | 通过 | `200`（不校验） |
| `X-Sdk-Int=99` | 通过 | `200`（不校验） |
| `X-App-Mode` 置空 | 通过 | `200`（不校验） |
| `X-Dark-Mode=1` | 通过 | `200`（不校验） |

**推断的服务端实现**（`[推断]`，与上表全部吻合）：解析 token → base64 → 取 `$2y$<cost>$<salt22><hash>` → 从 `salt22` 前 12 字符解出 `ts` → 用自身密码表对应窗口 + 请求头的 `X-App-Device`/`X-App-Id`/`verCode` 重建 `password` → 用 token 自带的 `salt`/`cost` 重算 bcrypt 与 `hash` 比对 → 校验 `ts` 落在约 `[now-24h, now+15min]`。

> 时间窗边界实测：`-23h` 通过、`-25h` 拒绝；`+10min` 通过、`+30min` 拒绝。边界值本身未逐秒收敛，不要把它当精确 SLA。

### 3.5 离线验证向量（不需要任何网络）

```
device = gNykjY3ITZjRzNlRTY0gzNgsTMwAjLyETOwQjMuE0MRFEI7MkMxITM4AjMyAyOp1GZlJFI7kWbvFWaYByOgsDI7AyOmdWQFZFOLRFZKVjSIBnU1AXQXJjN5YzTlBlSt0CM1gUd3UFR
```

**最强证据：完整复现真实官方客户端的 bcrypt 串。**
参考工程 `auth.rs` 的 `REAL_SALT` 注释保留了一条真实抓包样本：

```
$2y$04$NmFmZWYwMTMvZGVmZTQwZ.Q/letpnjTvhRLkevU06/rbD/hFq4UEi
```

用 APK 提取的密码表 + 本文 §3.3 公式，在 `ts=1795092499` 上把 token 解码回来，得到**完全相同**的 60 字符串：

```bash
python check_real_capture.py     # 输出 "结果 : 完全一致"，退出码 0
```

三条基准向量（`token_vectors.json`，随表指纹一起锁定）：

| ts | token |
| --- | --- |
| 1700000000 | `v3JDJ5JDA0JE5qVTFNMll4TURBdk5EWmlOV1EwWS5pRS5xa2s5Ty8uOVBoWWlnUkpoTmNTeWFqR2Z6bTBL` |
| 1800000000 | `v3JDJ5JDA0JE5tSTBPV1F5TURBdlpESm1ORFkyTi53blh0MkdISHRyT3A5THBHWXhmWVRFN1FYUVY5cDBp` |
| 1795092499 | `v3JDJ5JDA0JE5tRm1aV1l3TVRNdlpHVm1aVFF3Wi5RL2xldHBualR2aFJMa2V2VTA2L3JiRC9oRnE0VUVp` |

```bash
python coolapk_token_v3.py          # 逐条比对 + 真实抓包 salt 校验 + 输出当前时间 token
python coolapk_token_v3.py --regen  # 换表后重建基准（务必先确认在线回归全通过）
```

> 基准向量与**密码表指纹**绑定：表一变，`coolapk_token_v3.py` 会明确报"表已更换，需 --regen"，而不是给出真假难辨的 FAIL/PASS。

### 3.6 踩坑备忘

1. `X-Requested-With` 缺失是 `1000 请求方式错误`，不是签名错；
2. `v3` 前缀与 `.rstrip('=')` 缺一不可（参考工程用 `trim_end_matches('=')`）；
3. `salt22` 不能直接喂标准 base64 解码器 —— 它是 **bcrypt 字母表**的 22 字符 + `'.'`；
4. `bcrypt` 库必须允许自定义 salt（Python：`bcrypt.hashpw(password, b"$2b$04$"+salt22)`，输出前缀再换成 `$2y$`）；
5. `md5_hex(device)` 的输入是 **`X-App-Device` 头的完整原值**（逆序 base64 那串），不是解码后的 Android ID；
6. `ts` 必须是整数：传 `float` / `str` 会直接抛异常（脚本已做 `int()` 归一）。

---

## 4. 算法 B：`X-App-Device` 设备码

### 4.1 格式 `[对齐]` + 反解验证

```
plain   = "<device_id>; ; ; ; <manufacturer>; <brand>; <model>; <build>; <oaid>"
code    = reverse_chars( base64_std(plain) ) 去掉 '='、'\r'、'\n'
```

9 个字段（`;` 分隔后 trim）：`0 device_id | 1 '' | 2 '' | 3 '' | 4 厂商 | 5 品牌 | 6 机型 | 7 Build | 8 oaid`。

实测反解 `coolapk_cfg.DEVICE`：

```
DU7uH50--JPeO6962WAp5RpHJ5JdTK8VEAgf; ; ; ; Xiaomi; Redmi; 22081212C; AQ3A.240912.001; 784a4e74ce27b926
```

参考工程在无真实机型时用：

```
<android_id>; ; ; ; Xiaomi; Xiaomi; 23113RKC6C; UKQ1.230804.001;
```

> **设备码与 UA 不要求描述同一台机器。** 本文档用的设备码是 `22081212C`，UA 里是 `23113RKC6C`，
> 两者互不影响（服务端只用设备码头原值算 md5）。换设备码时按需同步 UA 即可，不会因为"不一致"被拒。

### 4.2 与 Token 的绑定关系 `[在线]`

token 内参与签名的是 `md5_hex(X-App-Device 原值)`。因此：

- 换设备码 ⇒ 必须重新签名（参考工程 `sync_device_code()` 后 `auth.set_device_code()`）；
- 只改 `X-App-Device` 不改 token ⇒ `1004`（已证；`verify_live.py` 用 `DEVICE2 = DEVICE[:-8]+'XwUd3UFQ'` 制造该场景，`DEVICE2` 是**人为变体**，不是第二台真机）；
- 改造设备码时可保留字段 0/8（设备标识、OAID），只替换 4~7（厂商/品牌/机型/Build）—— 参考工程 `device_code_with_profile()`。

反解/校验：

```python
import base64
def decode_device(code: str) -> str:
    s = code[::-1]
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s).decode()
```

---

## 5. 算法 C：`User-Agent` 模板

```
Dalvik/2.1.0 (Linux; U; Android <系统版本>; <机型> Build/<Build>) (#Build; <品牌>; <机型>; <Build>; <系统版本>) +CoolMarket/<版本名>-<构建号>-universal
```

当前 APK 实例：

```
Dalvik/2.1.0 (Linux; U; Android 16; 23113RKC6C Build/AQ3A.250226.002) (#Build; Redmi; 23113RKC6C; AQ3A.250226.002; 16) +CoolMarket/16.7.3-2611121-universal
```

- 后缀 `+CoolMarket/<versionName>-<versionCode>-universal` **必须与 `X-App-Version` + `X-App-Code` 同步**；
- 整段删除后缀 → `403`；只把后缀里的版本号改成 `16.2.0-2604201` → 同样 `403`（两条均为在线用例）—— 说明网关对"UA 后缀 / X-App-Version / X-App-Code / X-Api-Version"做一致性白名单。

---

## 6. 算法 D：写接口风控（易盾）

只影响少数写接口，且清单由服务端下发，**不应硬编码**。

### 6.1 `_v2_post_token`（网易易盾）

- 载体：`libnesec.so` / `libnesec-x86.so`（易盾 SDK；`assets/nedata.db`、`nedig.properties`、`assets/adi-registration.properties` 亦为其配套 `[推断]`）
- 位置：**表单字段** `_v2_post_token`（不是 header）`[对齐]`
- 生成方：易盾 SDK 运行时产生（含设备指纹采集 + 服务端挑战），**无法静态离线复刻**
- 业务 ID 与路径由 `/v6/main/init` 下发（2026-11-19 实测）：

```json
"PostToken.businessId": "aca7df55758868ea76460c100ef168e9",
"PostToken.List": ["/v6/feed/createFeed", "/v6/feed/reply"]
```

### 6.2 `ddid` Cookie 注入

`/v6/main/init` 同时下发（2026-11-19 实测）：

```json
"MainInit.useDDI": "1",
"MainInit.useDDISessionId": "1",
"MainInit.useDDIEvent": "0",
"MainInit.useDDIEventList": ["/v6/feed/createFeed","/v6/feed/reply","/v6/feed/like","/v6/feed/likeReply","/v6/message/send"]
```

规则（`[对齐]` 参考工程 `cookie_for_request()`）：

1. 普通请求：剔除 Cookie 里的 `ddid`；
2. 命中 `useDDIEventList` 的路径：把 `ddid` **percent-encode 后**追加进 Cookie；
3. `ddid` 的值即数盟设备 ID（ShuzlmID / 设备标识）；
4. 挂件等内置网页另注入 `DID`（与写操作的 `ddid` 是两个不同字段）。

编码规则（`encode_login_cookie_value`，即 `application/x-www-form-urlencoded` 语义）：

```
[A-Za-z0-9-_.~] → 原样
' '            → '+'
其它           → %XX（大写十六进制）
```

> ⚠️ 清单会变。参考工程硬编码的 `DDI_EVENT_PATHS` **缺 `/v6/message/send`**（实测 init 已包含），应改为运行期读 `MainInit.useDDIEventList`。

---

## 7. API 版本闸门（为什么"APK 一更新就全 403"）

网关对以下四项做白名单一致性校验，任一不匹配 → `HTTP 403`（空响应体，无 JSON）：

```
X-App-Version   == <当前 versionName>
X-App-Code      == <当前 versionCode>
X-Api-Version   == <当前 API 版本；16.7.3 → 16>
User-Agent 后缀 == "+CoolMarket/<versionName>-<versionCode>-universal"
```

`versionCode` 同时是 Token V3 的两处输入（`plain` 第 5 段、时间槽 `%100`），所以**升级 APK 时版本号一改，签名与网关闸门会同时变化**。这是"APK 更新后参考工程失效"最常见的原因。

> `X-Api-Version` 的取值目前只有实测结论（`16.7.3` → `16`），没有从 APK 静态推导的规则；升级后若 403 而其余三项已同步，优先怀疑它。

---

## 8. APK 更新后的复检流程（照抄执行）

**前置条件**：Windows/Linux + Python 3.10+，已装 `bcrypt`（`python -m pip install bcrypt`）；需要联网（只读公共接口，不需要登录）。
**全部命令都在工作区根目录（脚本所在目录）执行** —— 报告与表文件都写到当前目录。

设新 APK 为 `coolapk-<ver>.apk`。

```bash
# ① 取版本三元组（必须与网关一致）
apktool d -f -s coolapk-<ver>.apk -o apk_res_<ver>
# 读 apk_res_<ver>/apktool.yml 的 versionName / versionCode

# ② 改唯一配置源（升级后只改这一个文件）
#    coolapk_cfg.py:  VERSION / APP_CODE / API_VERSION / UA_TEMPLATE / DEVICE
#    其余脚本（token/verify/init）都从它取值，不要再散改

# ③ 重取密码表（结构识别，不依赖偏移）
python apk_extract.py coolapk-<ver>.apk
#    退出码 0 = 找到；2 = 没找到 —— 先排除"表换了后缀/长度变了"，再怀疑算法变更
#    产出：coolapk-<ver>_token_table.txt（文件名由 coolapk_cfg.VERSION 决定）
#    把旧的 coolapk-<旧版>_token_table.txt 移出目录，避免误读旧表

# ④ 判断表是否变化
#    - 表变了：先跑 ⑥ 的在线回归，全通过后再 `python coolapk_token_v3.py --regen` 重建基准向量
#      （基准向量与表指纹绑定，换表后旧向量一定 FAIL，这是设计行为，不是 bug）
#    - 表没变：直接 ⑤

# ⑤ 离线自检
python coolapk_token_v3.py
#    期望：三条向量 OK + "真实抓包 salt22 OK"

# ⑥ 在线回归（关键门禁）
python verify_live.py --full
#    期望 24/24，报告写入 verify_report.txt

# ⑦ 写接口风控清单是否变化
python init_check.py
#    产出 init_config.json / init_config.txt；退出码 0 = 六项关注键全部取到

# ⑧ 失败定位
#    403 群   → §7 版本闸门（Version/Code/Api-Version/UA 后缀）
#    1004 群  → 密码表 / XOR key / 时间槽偏移 0x80 / bcrypt 参数 / 设备码不配对
#    1002     → X-App-Id 被改成别的包名
#    1000     → 缺 X-Requested-With
#    1005     → 本机时钟偏差超窗
```

同步到参考工程只需三处：

| 改动点 | 位置 |
| --- | --- |
| `auth_blob.b64` | `src-tauri/src/coolapk/auth_blob.b64` ← 新表（930 字符再 base64） |
| `APP_CODE` | `src-tauri/src/coolapk/auth.rs` 的 `const APP_CODE` |
| 版本号 / UA | `src-tauri/src/coolapk/native_device.rs` 的 `APP_SUFFIX`、`client.rs` 的 `X-App-Version`/`X-App-Code`/`X-Api-Version` |

---

## 9. 症状 → 原因 → 处置

| 症状 | 最可能原因 | 处置 |
| --- | --- | --- |
| `404 {"status":1000,"请求方式错误"}` | 缺 `X-Requested-With: XMLHttpRequest` | 补头（不是签名问题） |
| `200 {"status":1002,"应用未授权"}` | `X-App-Id` 不是 `com.coolapk.market` | 改回头值 |
| `200 {"status":1004,"请求验证错误"}` | token 算法错：表 / 窗口偏移 / 签名输入 app_id / verCode / 设备码不配对 | 按 §3.3 打印中间值逐项比对 |
| `200 {"status":1004,"请求未验证"}` | 完全没带 token | 补 `X-App-Token` |
| `200 {"status":1005,"请求已过期"}` | 本机时钟偏差超窗（过去 >24h 或未来 >~15min） | 校时 |
| `403` 空响应体 | 版本闸门（§7） | 同步四项到当前版本 |
| 只读正常、发帖/评论失败 | 缺 `_v2_post_token` 或路径未注入 `ddid` | 按 init 下发清单处理（§6） |
| 登录相关接口失败 | 登录走 `account.coolapk.com` Web 授权，不走 Token V3 | 见 §11 未覆盖项 |

---

## 10. 与 `coolapk-desktop` 的对齐情况与已知偏差

| 项 | 参考工程 | 本次实测 | 建议 |
| --- | --- | --- | --- |
| Token V3 公式 | `auth.rs::generate_token_at` | 逐项一致；在线 24/24 通过 | — |
| 密码表 | `auth_blob.b64` | 与 `libauth.so@264422` XOR 0x5A 后完全相同 | 文档化来源，便于升级替换 |
| `auth.rs::probe_salt_for_known_real_timestamp` | 把 `REAL_SALT` 与 `ts=1795096595` 配对 | 该 salt/hash 实际对应 **ts=1795092499**（`0x6AFEF013`），与测试入参不符；本实现的 `ts=1795092499` 结果与其**整串一致** | 这是调试用 probe（只有 `println!` 无断言）；正确基准见 §3.5 |
| `cost=10 会导致登录校验失败` 注释 | 结论限于登录链路 | 普通只读接口 `cost=10` 仍 `200` | 注释加限定范围 |
| `DDI_EVENT_PATHS` | 硬编码 4 条 | init 已下发 5 条（多 `/v6/message/send`） | 改为读 `MainInit.useDDIEventList` |
| `POST_TOKEN_PATHS` | 硬编码 2 条 | 与 init 的 `PostToken.List` 一致 | 可改为读下发 |
| 版本串位置 | 分散在 Rust 多处 | 本项目已收敛到 `coolapk_cfg.py` | 升级时优先改配置源 |

---

## 11. 当前未覆盖 / 待确认

| 项 | 状态 |
| --- | --- |
| 登录授权链路（`account.coolapk.com` Web 登录 → `SESSID`/`uid`/`username`/`token` Cookie） | **未分析**；本轮只覆盖客户端请求签名。Cookie 由服务端 `Set-Cookie` 下发，客户端不做加密计算 `[推断]` |
| `_v2_post_token` 的具体生成 | 在易盾 native SDK（`libnesec.so`）内，需设备运行时；本轮确认了字段名、位置（表单）、businessId 与路径清单 |
| 易盾 `verifyAppSignature` 的实际约束 | 仅确认符号存在（`[静态]`）；若 APK 被重签，官方客户端会拒绝出 token，但服务端校验不依赖它 `[推断]` |
| `libEncryptorP.so` / `libdu.so` | 字符串被加密 / 仅 socket 相关，未见与请求签名相关；`libCPS.so` 是 OpenSSL AES 封装的通用加密库（服务广告/数盟 SDK） |
| 其他写接口的额外风控 | 只确认了 `useDDIEventList` / `PostToken.List`，其余路径未穷举 |
| `X-App-Channel` / `X-Sdk-Locale` | 未单独 A/B 反证 |

---

## 12. 证据清单（可复核）

| 证据 | 获取方式 |
| --- | --- |
| APK 加固事实 | `apk_res/classes.dex` 头表：`string_ids_size=956`、`class_defs_size=30`、`file_size=98518552` |
| 壳类清单 | 同上 dex 的 30 个 class_def，全为 `com/netease/nis/wrapper/*` |
| `libauth.so` 能力面 | `strings libauth.so`：`getToken`、`bcrypt_hashpw`、`_ZN3MD5*`、`base64_decode`、`com/coolapk/market/util/AuthUtils` |
| 密码表位置 | `lib/arm64-v8a/libauth.so` 偏移 `264422`，1240 字符 base64，解码 930 字节，XOR `0x5A` |
| 表与参考工程等价 | `python apk_extract.py` 产出的表 == `base64_decode(auth_blob.b64)` |
| 算法正确性（离线） | `python coolapk_token_v3.py`：3 条基准向量 + 真实抓包 bcrypt 串整串一致 |
| 算法正确性（在线） | `python verify_live.py --full` → 24/24，报告 `verify_report.txt`（**这才是请求头校验矩阵的证据**） |
| 写接口清单 | `python init_check.py` → `init_config.txt`（businessId、两条路径清单） |

配套文件：

| 文件 | 作用 |
| --- | --- |
| `酷安APK请求算法.md` | 本文档 |
| `coolapk_cfg.py` | **唯一配置源**：版本三元组、UA 模板、样本设备码、表/向量文件路径 |
| `coolapk_token_v3.py` | Token V3 离线签名；优先读缓存表文件，缺失时从 `apk_res/lib` 现取；`--regen` 重建基准 |
| `apk_extract.py` | 从任意版本 APK 结构识别并导出密码表（带退出码） |
| `verify_live.py` | 在线回归（默认 8 例，`--full` 24 例） |
| `init_check.py` | 拉取 `/v6/main/init` 并打印写接口风控清单（带退出码） |
| `check_real_capture.py` | 离线证据：复现真实抓包的 bcrypt 串 |
| `coolapk-16.7.3_token_table.txt` | 本版密码表（930 字符），由 `apk_extract.py` 产出 |
| `token_vectors.json` | 基准向量 + 表指纹，由 `coolapk_token_v3.py --regen` 产出 |
| `verify_report.txt` / `init_config.txt` | 最近一次回归与 init 采集结果 |

---

*本文档基于 `coolapk-16.7.3`（versionCode 2611121）实测。APK 更新后按 §8 复检；
若 §8 ③ 找不到表，或 §3.3 的步骤③⑤ 结构变化，则说明签名方案已被改动，需要重做 native 静态分析。*
