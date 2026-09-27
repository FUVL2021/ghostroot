# GhostRoot
> Android 图形化提权工具 —— 面向 **小米 8550（SM8550）平台**（实测机型：小米 13 / fuxi），Android 16 / kernel 5.15.178
> **未解锁 Bootloader** 前提下的研究性 PoC。
>
> 内核提权 payload `libfuxi8550` 由 **御坂114514** 发布，声明支持**所有搭载小米 8550（SM8550）处理器的设备**。

⚠️ **仅供安全研究与自有设备测试使用。请勿用于未经授权的设备。**
使用前请阅读 [DISCLAIMER.md](DISCLAIMER.md)。

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
│        CVE-2026-43499提权 → root 域                             │
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

这些 `.so` 在 APK 构建时被原样打进 `lib/arm64-v8a/`；
`.gitignore` 中**刻意没有** `*.so` 通配规则（见文件内 NOTE）。

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
│       ├── MainActivity.java            ← 主界面（一键提权流水线）
│       ├── ShellTerminalActivity.java   ← 独立 Shell 终端（双通道，纯 Java UI）
│       ├── Shell.java                   ← 通道抽象接口
│       ├── Adb0073Shell.java            ← 通道①实现
│       ├── ShizukuShell.java            ← 通道②实现
│       ├── ShizukuAdapter.java          ← Shizuku 接入（含上述踩坑修正）
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

## UI 说明

因为目标环境没有 aapt2（不能用 `@layout/xxx` 引用新布局），
**新增界面全部用纯 Java 代码构建**，不碰 XML 资源。

### 主界面

「一键提权」流水线。顶部有「独立 Shell 终端（Shizuku）」入口，
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

## 项目状态（务必先读）

| 模块 | 状态 |
|---|---|
| CVE-2026-0073 通道（Java / C 实现） | ✅ 真机跑通，可取得 shell 域 |
| SM8550 kernel 提权 payload | ✅ 真机跑通 |
| Shizuku 通道（provider 推 binder 修正） | ⚠️ **代码已修正为官方机制，尚待真机复验** |
| 0073 端口自动扫描 | ⚠️ **不完善**，见「已知问题」 |
| UI / 打包链 | ✅ 可构建出可安装 APK |

> **本仓库是研究用原型，不是"开箱即用"的成品软件。**
> Shizuku 通道与端口扫描两块仍在修，请以源码 + 踩坑记录为主要参考价值。

---
## 已知问题 / 待办
- [ ] **Shizuku 通道待真机复验**：已按反编译结论修正为「App 声明 provider，等
      Shizuku 服务端 `call(..., "sendBinder", ...)` 推 binder」，但尚未回传
      `✅ Shizuku 通道可用 (uid=2000)` 的实测日志。安装后若 Shizuku 授权列表里
      没有本 App，需**卸载重装**（provider 在安装时注册）。
- [ ] **0073 端口扫描太弱**：目前只试 11 个固定端口（5555 + 37000~45000 段）。
      Android 16 上 `/proc/net/tcp` 对普通 App 不可读（`Permission denied`），
      需另找枚举方式（如通过 Shizuku 拿 shell 域后读，或扩大扫描范围 + 并发）。
- [ ] 无线调试开启后**自动关闭**，窗口期很短。
- [ ] 内核漏洞阶段可能触发 **RCU stall → 整机锁死**，需长按电源强制重启。
      建议：屏幕常亮、单轮单次、人工盯着跑，不要后台长跑。
- [ ] 未做「仅 0073 模式 / 仅 Shizuku 模式」的模式拆分。
- [ ] UI 重构、免责声明页、固化 RSA 密钥等待办。

---
## 来源与致谢

| 组件 | 来源 | 说明 |
|---|---|---|
| **`libfuxi8550.so`**（内核提权 payload） | **御坂114514 发布** | 声明支持 **所有搭载小米 8550（SM8550）处理器的设备**。 |
| Shizuku API / AIDL / Provider jar | [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku) | 用于「通道②」的 shell 域接入。 |
| 其余源码（App 壳、0073 通道、构建脚本、文档） | 本项目 | — |

`libfuxi8550.so` 由 **御坂114514** 发布，本项目仅将其**原样收录**用于研究与复现，
版权与解释权归原作者所有。若原作者希望移除，请提 Issue，会立即处理。

---
## 免责声明

本项目为**安全研究**用途，旨在研究和披露特定设备/系统版本上的漏洞。
详见 [DISCLAIMER.md](DISCLAIMER.md)。
**禁止**用于任何未经授权的设备或非法目的。
