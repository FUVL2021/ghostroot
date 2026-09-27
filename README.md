# GhostRoot

> Android 图形化提权工具 —— 面向 **小米 8550（SM8550）平台**（实测机型：小米 13 / fuxi），Android 16 / kernel 5.15.178
> **未解锁 Bootloader** 前提下的研究性 PoC。
>
> 内核提权 payload `libfuxi8550` 由 **御坂114514** 发布，声明支持**所有搭载小米 8550（SM8550）处理器的设备**。

⚠️ **仅供安全研究与自有设备测试使用。请勿用于未经授权的设备。**
使用前请阅读 [DISCLAIMER.md](DISCLAIMER.md)。

**本仓库作者：酷安 FUVL2210**

---

## 这是什么

GhostRoot 是一个 **APK 形态**的提权工具。它把两条「获取 `shell` 域（uid=2000）」
的路径**图形化、一键化**，再借助内核漏洞完成最终提权。

核心思路：`App 域 (uid=10xxx)` 的自提权极难，但设备上存在一个**天然的高权域**
—— `adb shell` 的 `shell` 域（uid=2000，SELinux `u:r:shell:s0`）。
先「借」到 shell 域，再从 shell 域出发打内核漏洞，路径短得多。

```
┌──────────────────────────────────────────────────────────┐
│  你的 App (uid=10xxx / untrusted_app)                    │
│      │                                                    │
│      ├── 通道① 0073  ── CVE-2026-0073 无线调试认证绕过    │
│      │                  (需开无线调试，走漏洞，主路)       │
│      │                                                    │
│      └── 通道② Shizuku ── 借 Shizuku(ADB模式) 的 shell 域 │
│                          (无需无线调试，走"正路"，兜底)    │
│                    ↓                                      │
│           shell 域 (uid=2000 / u:r:shell:s0)             │
│                    ↓                                      │
│        CVE-2026-43499 提权 → root 域                      │
└──────────────────────────────────────────────────────────┘
```

---

## 设备前提

| 项 | 值 |
|---|---|
| 机型 | 小米 XIAOMI |
| SoC | Snapdragon 8 Gen 2 (SM8550 / kalama) |
| 系统 | HyperOS OS3.0.307.0.WMCCNXM |
| Android | 16 (SDK 36) |
| 内核 | 5.15.178 |
| SELinux | Enforcing |
| Bootloader | **未解锁** |

> 未解锁 BL 是本项目的硬前提 —— 所有方案都不依赖刷机、改 boot、写分区。

---

## 双通道设计

### 通道 ①：CVE-2026-0073（主路）

无线调试（ADB over Wi-Fi）的 TLS 认证绕过高危漏洞。设备开启无线调试后，
`adbd` 会在本地监听一个随机高位端口；此漏洞可绕过其 TLS 客户端认证，
直接以 `shell` 域建立 ADB 会话。

- 实现：`app/src/com/fuxi/ghostroot/Adb0073.java`（纯 Java，自实现 ADB 协议）
- 参考实现：`native/adb0073.c`（C 版本，含完整 ADB 握手：CNXN / STLS / AUTH / OPEN / WRTE）
- 依赖：无线调试已开启

### 通道 ②：Shizuku（兜底）

Shizuku 以 **ADB 模式** 运行时，其服务端进程就是 `shell` 域（uid=2000）。
App 通过 Shizuku 的 binder 借它的权限执行命令 —— 拿到的是**同一个** shell 域，
与通道 ① 完全等价，但**不需要开无线调试**。

- 实现：`app/src/com/fuxi/ghostroot/ShizukuShell.java` + `ShizukuAdapter.java`
- 依赖：Shizuku 已安装 + ADB 模式已启动 + 已授权本 App

两条通道通过统一的 `Shell` 接口抽象（`Shell.java`），拿到域之后的所有操作
（推送 payload / 执行提权）**与通道无关**，可无缝切换。

---

## Payload（`app/lib/arm64-v8a/`）

仓库**包含**提权内核 payload，以便直接复现完整链路：

| 文件 | 大小 | 来源 | 说明 |
|---|---|---|---|
| `libfuxi8550.so` | 1,889,584 B | **御坂114514 发布** | SM8550 内核提权 payload（静态 ELF，`.so` 仅为命名习惯，实际是可执行镜像）。 |
| `libghostroot.so` | 6,297,784 B | 本项目 | 0073 利用器（ADB 认证绕过 → 取得 `uid=2000` shell 域）。 |

MD5：
```
142355ab39b9205f2cb673afd430fa3c  libfuxi8550.so
da07fd63ba7dbd0f058f311cc2d9f41e  libghostroot.so
```

### `libfuxi8550.so` 来源与设备支持

> **来源**：由 **御坂114514** 发布。
> **设备支持**：**所有搭载小米 8550（SM8550）处理器的设备**。

即：小米 13 (fuxi)、小米 13 Pro、小米 13 Ultra、Redmi K60 Pro、
小米平板 6 / 6 Pro、MIX Fold 3 等 SM8550 机型均在声明支持范围内
（具体可用性仍取决于各自 ROM / kernel 版本，见下方偏移警告）。

> ⚠️ **内核偏移警告**：该 payload 内含硬编码内核符号偏移，
> 只对**相同 ROM / 相同 kernel 版本**有效。
> 本项目实测环境见「设备前提」。

### 8550 输出的关键标志（供排查）

提权成功时 `libfuxi8550.so` 会打印：

```
[+] SUCCESS: /sys/fs/selinux/enforce=0 sched_setattr=... errno=...
[+] adb root broker installed for adbd pid=...
[+] su daemon written to ... (N bytes)
[+] SU DAEMON READY: ... ...
[+] ROOT SUCCESS: UID/GID 0 with full capabilities; pid=...
```

失败时的两条特征串（本工具会自动识别并提示重启）：

```
[-] root chain stopped with one-shot PI state alive; reboot before retrying
[-] atomic credential transaction verification failed
```

---

## 目录结构

```
.
├── README.md                  ← 本文
├── DISCLAIMER.md              ← 免责声明
├── build/
│   └── build_apk.py           ← 一键打包脚本
├── app/
│   ├── AndroidManifest.xml    ← 含 Shizuku provider 声明
│   ├── libs/                  ← Shizuku API/AIDL/Provider jar
│   ├── lib/arm64-v8a/         ← 内核 payload（见上节）
│   ├── res/                   ← 原始资源（文本，供 aapt 编译）
│   └── src/com/fuxi/ghostroot/
│       ├── MainActivity.java            ← 主界面（一键提权流水线 + 成功收尾）
│       ├── ShellTerminalActivity.java   ← 独立 Shell 终端（双通道）
│       ├── Shell.java                   ← 通道抽象接口
│       ├── Adb0073Shell.java            ← 通道①实现
│       ├── ShizukuShell.java            ← 通道②实现
│       ├── ShizukuAdapter.java          ← Shizuku 接入
│       ├── Adb0073.java                 ← CVE-2026-0073 纯 Java 实现
│       ├── SelfSignedCert.java          ← 自签证书（ADB TLS 用）
│       ├── SyncPush.java / RawPush.java ← 大文件推送方案
│       └── ...
├── native/
│   ├── adb0073.c / adb0073.h   ← C 版 ADB 协议实现
│   └── jni_wrap.c
└── docs/
    └── INSTALL.md              ← 安装与使用
```

---

## 安装

```bash
# 因 SELinux 限制，system_server 读不了 /sdcard，需先拷到 /data/local/tmp
adb push GhostRoot.apk /data/local/tmp/
adb shell pm install -r /data/local/tmp/GhostRoot.apk
```

或直接在手机文件管理器里点击安装（不受上述限制）。

---

## UI 说明

因为目标环境没有 aapt2（不能用 `@layout/xxx` 引用新布局），
**新增界面全部用纯 Java 代码构建**，不碰 XML 资源。

### 主界面
「一键提权」流水线。顶部有「独立 Shell 终端」入口，
可不跑完整流程、单独测试 shell 通道。

### 独立 Shell 终端（双通道）
```
┌──────────────────────────────┐
│ ① Shizuku   ② 0073           │  ← 单选切换
├──────────────────────────────┤
│ 0073 端口: [留空=自动扫描]     │
│ 状态: ❌/✅ ...               │  ← 探测结果
├──────────────────────────────┤
│ 命令输入 [id          ]       │
│ [探测通道] [执行 (Run)]       │
│ ── 输出滚动区 ──             │
└──────────────────────────────┘
```

先点【探测通道】确认通道可用，再执行命令。预期输出 `uid=2000` / `u:r:shell:s0`。

---

## 提权流程（4 个阶段）

```
阶段 A  获取 shell 域
        ├─ 前置检查 /data/misc/adb/adb_keys（#0）
        ├─ 主路：0073 端口扫描（ADB 握手判定，非"能连上"）
        └─ 兜底：Shizuku 通道
阶段 B  推送 payload
        ├─ 8550 → /data/local/tmp/fuxi8550（校验大小）
        └─ ksud → /data/local/tmp/ksud
阶段 C  执行提权 + 结果判定
        ├─ 成功：ROOT SUCCESS
        └─ 失败特征：one-shot PI alive / cred verify failed → 提示重启
阶段 D  成功收尾（#10）  ← 仅在确认成功后才做
        ├─ D1：清理 /data/local/tmp（只删明确路径，不通配）
        └─ D2：固化 RSA 公钥到 /data/misc/adb/adb_keys（去重追加）
```

> **重要提示（务必遵守）**
> 1. 请不要中途退出软件，否则可能失败。
> 2. 如果 **30 秒内没有提权完成**，基本上是失败，可能是判断逻辑没写好。
> 3. 最坏情况是**内核卡死**（不会损坏系统/数据，因为只提权、未动分区），
>    长按电源重启即可。

---

## 项目状态

| 模块 | 状态 |
|---|---|
| CVE-2026-0073 通道（Java / C 实现） | ✅ 真机跑通，可取得 shell 域 |
| SM8550 kernel 提权 payload | ✅ 真机跑通 |
| Shizuku 通道 | ✅ 真机跑通（`uid=2000` shell 域） |
| 0073 端口扫描（ADB 握手判定） | ✅ 真机跑通 |
| UI 重构（单标题栏） | ✅ 完成 |
| 免责声明页 | ✅ 完成 |
| 成功收尾（清 tmp + 固化 adb_keys） | ✅ 代码完成，待真机复验 |
| 代码拆分 / 清理中间产物 | ⏳ 待做 |

---

## 已知问题 / 待办

- [ ] **成功收尾（#10）待真机复验**：D2 依赖设备上已有 RSA 公钥，
      若找不到来源会跳过并提示。需实跑一次确认行为。
- [ ] **无线调试开启后自动关闭**，窗口期很短。
- [ ] 内核漏洞阶段可能触发 **RCU stall → 整机锁死**，需长按电源强制重启。
      建议：屏幕常亮、单轮单次、人工盯着跑，不要后台长跑。
- [ ] **代码拆分**：`Adb0073.java` 较长，待拆分。
- [ ] **清理中间产物**：仓库/工作区里的旧版本 APK 待归档到 `backup/`。
- [ ] 提权后 **SELinux 网络缓存可能被污染** → enforcing 下断网 / App 闪退。
      这是 exploit 的副作用（连带破坏 `sel_netif` 等缓存），
      需要用「重载 SELinux 策略 + 重建 lo」的方式修复。

---

## 来源与致谢

| 组件 | 来源 | 说明 |
|---|---|---|
| **`libfuxi8550.so`**（内核提权 payload） | **御坂114514 发布** | 声明支持 **所有搭载小米 8550（SM8550）处理器的设备**。 |
| Shizuku API / AIDL / Provider jar | [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku) | 用于「通道②」的 shell 域接入。 |
| 其余源码（Android 端、0073 通道、构建脚本、文档） | 本项目（酷安 FUVL2210） | — |

`libfuxi8550.so` 由 **御坂114514** 发布，本项目仅将其**原样收录**用于研究与复现，
版权与解释权归原作者所有。若原作者希望移除，请提 Issue，会立即处理。

---

## 免责声明

本项目为**安全研究**用途，旨在研究和披露特定设备/系统版本上的漏洞。
详见 [DISCLAIMER.md](DISCLAIMER.md)。

**禁止**用于任何未经授权的设备或非法目的。