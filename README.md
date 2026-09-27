# GhostRoot

> Android 图形化提权工具 —— 面向 **小米 13 (fuxi / SM8550)**，Android 16 / kernel 5.15.178
> **未解锁 Bootloader** 前提下的研究性 PoC。

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
│        内核漏洞提权 → root 域                             │
└──────────────────────────────────────────────────────────┘
```

---

## 设备前提

| 项 | 值 |
|---|---|
| 机型 | 小米 13 (fuxi, 型号 2211133C) |
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

## Shizuku 接入的正确姿势（踩坑记录）

这一节是**最有价值的部分之一**，因为网上绝大多数资料是错的。

### ❌ 错误做法

```java
// App 主动去 call Shizuku 的 provider
cr.call(Uri.parse("content://moe.shizuku.privileged.api.shizuku"), "getBinder", ...);
```

会得到：

```
java.lang.SecurityException: Permission Denial: opening provider
moe.shizuku.manager.ShizukuManagerProvider from ProcessRecord{...}
requires android.permission.INTERACT_ACROSS_USERS_FULL
```

因为 `moe.shizuku.manager.ShizukuManagerProvider` 是 Shizuku **管理界面自用**的
provider，不是给第三方 App 的接口。

### ✅ 正确机制（反编译官方字节码得出）

**方向是反的** —— 不是 App 去「拉」，而是 Shizuku 服务端主动「推」：

```
Shizuku 服务端 (shell 域)
   └─ call(content://<你的包名>.shizuku, "sendBinder", bundle)
          │   bundle 里带 EXTRA_BINDER = BinderContainer(binder)
          ↓
   你的 App 自己声明的 provider
   rikka.shizuku.ShizukuProvider.handleSendBinder()
          └─ BinderContainer.binder → Shizuku.onBinderReceived(binder, pkgName)
          ↓
   之后 Shizuku.pingBinder() == true，exec 可用
```

**关键点**（全部从字节码实证）：

1. **authority 必须是 `<你的包名>.shizuku`**
   —— 官方代码是 `"content://" + context.getPackageName() + ".shizuku"` 硬拼的。
   本项目：`com.fuxi.ghostroot.shizuku`

2. **必须由你的 App 自己声明这个 provider**（写进 Manifest）：

```xml
<provider
    android:name="rikka.shizuku.ShizukuProvider"
    android:authorities="com.fuxi.ghostroot.shizuku"
    android:exported="true"        <!-- 必须 true -->
    android:multiprocess="false"   <!-- 必须 false -->
    android:enabled="true" />
```

   ⚠️ `exported=false` 或 `multiprocess=true` 会在 `attachInfo()` 里
   直接抛 `IllegalStateException`。

3. **Manifest 还要有权限 + meta-data**：

```xml
<uses-permission android:name="moe.shizuku.manager.permission.API_V23" />

<application ...>
    <meta-data
        android:name="moe.shizuku.client.V3_SUPPORT"
        android:value="true" />
```

   这两项是 Shizuku 服务端**校验调用方**用的，运行时改不了，只能写进 Manifest。

4. **binder 在 Bundle 里的 key**：
   `moe.shizuku.privileged.api.intent.extra.BINDER`
   值是 **`moe.shizuku.api.BinderContainer`**（Parcelable），
   **不是** `IBinder` —— 要取它的 public 字段 `.binder`。
   （`BinderContainer` 在 `shizuku-provider.jar` 里，编译和 d8 都要带上。）

5. **进程不是 provider 进程时**，用官方 API：
   `ShizukuProvider.requestBinderForNonProviderProcess(ctx)`
   —— 它内部会注册 `BINDER_RECEIVED` 广播 + call 自己的 provider。

> 常量速查表：
>
> | 常量 | 值 |
> |---|---|
> | `PERMISSION` | `moe.shizuku.manager.permission.API_V23` |
> | `MANAGER_APPLICATION_ID` | `moe.shizuku.privileged.api` |
> | `METHOD_SEND_BINDER` | `sendBinder` |
> | `METHOD_GET_BINDER` | `getBinder` |
> | `ACTION_BINDER_RECEIVED` | `moe.shizuku.api.action.BINDER_RECEIVED` |
> | `EXTRA_BINDER` | `moe.shizuku.privileged.api.intent.extra.BINDER` |

---

## 无 Gradle / 无 aapt2 的构建方式（踩坑记录）

本项目**刻意不使用 Gradle**。原因：目标环境（Android + proot）里 aapt2 会 SIGILL，
且需要最大限度控制产物。整套构建链是手工串起来的。

### 工具链

| 工具 | 说明 |
|---|---|
| `aapt` | **必须用 `qemu-x86_64-static` 包一层**，否则 SIGILL（见下） |
| `javac` | 编译 Java，`-bootclasspath android34.jar`，**不能用 lambda**（jar 里没 `LambdaMetafactory`） |
| `d8.jar` | dex 转换 |
| `zipalign` | 4 字节对齐（同样要 qemu 包一层） |
| `apksigner.jar` | 签名（v1+v2+v3） |

### 🔑 关键突破：x86_64 Android 工具用 qemu 包一层就能跑

```bash
# ❌ 直接执行 → SIGILL (rc=132)
/tmp/btx/android-14/aapt v

# ✅ qemu 包一层 → 正常
qemu-x86_64-static /tmp/btx/android-14/aapt v
# Android Asset Packaging Tool, v0.2-10229193
```

这一条解决了「无法用官方工具验证产物」的死结，`aapt dump badging / xmltree / resources`
全部可用。同样适用于 `zipalign`。

### 📦 打包铁律（血泪教训）

**1. 绝对不要手写 Python 拼二进制 AXML。**

我们试过手改二进制 AXML 注入 `<activity>`，字节能对上、apktool 能解，
但 **`PackageManager` 拒绝**（报「解析软件包时出现问题。(33)」+ `packageInfo is null`）。

原因：`aapt` 能解 ≠ `PackageParser` 能解，两者校验标准不同。手拼的 AXML
与官方编译产物**结构不等价**（官方 3040 字节 vs 手拼 3048 字节）。

**✅ 正确做法：用文本 Manifest + aapt 编译，拿官方产物。**

```bash
qemu-x86_64-static aapt package -f \
    -M app/AndroidManifest.xml \
    -S app/res \
    -I android34.jar \
    -F skeleton.apk
```

产出 `AndroidManifest.xml` + `resources.arsc` + `res/layout/main.xml` 官方三件套，
`PackageParser` 必然接受。

**2. `resources.arsc` 必须用 STORED（不压缩）。**

Android 10+ 要求 `resources.arsc` 未压缩且 4 字节对齐，否则 `PackageParser` 拒绝。

```python
w.writestr(zipfile.ZipInfo('resources.arsc'), arsc_data, zipfile.ZIP_STORED)
```

**3. `R.java` 的常量必须与 `arsc` 里的实际 ID 一致。**

这是最阴的坑：换用 aapt 重编后**资源 ID 会重新分配**，
如果 `R.java` 还是旧值，`findViewById()` 会返回 `null` → `NullPointerException` 闪退。

```bash
# 拿权威 ID
qemu-x86_64-static aapt dump resources GhostRoot.apk | grep 'id/'
```

本项目的实例：aapt 重编后

| 资源 | 旧 `R.java` | 实际 `arsc` |
|---|---|---|
| `id/run` | `0x7f010002` | `0x7f050000` |
| `id/scroll` | `0x7f010004` | `0x7f050001` |
| `id/output` | `0x7f010001` | `0x7f050002` |
| `id/copy` | `0x7f010000` | `0x7f050003` |
| `id/save` | `0x7f010003` | `0x7f050004` |
| `layout/main` | `0x7f020000` | `0x7f020000` ✅（唯一幸存） |

> `layout/main` 恰好没变，所以界面能出来，但 5 个 id 全错位 → 一点按钮就闪退。

**4. `-source 8` 下不能用 lambda**，全部改匿名内部类。

```
error: cannot access LambdaMetafactory
```

因为 `android34.jar` 里没有这个符号。本项目所有回调都是 `new View.OnClickListener(){...}`。

### 构建脚本

见 [`build/build_apk.py`](build/build_apk.py)：

```bash
python3 build/build_apk.py <classes.dex> <lib目录> <输出.apk>
```

流程：`aapt package` 编骨架 → 拼装（arsc STORED）→ `zipalign` → `apksigner`。

---
## Payload（`app/lib/arm64-v8a/`）

仓库**包含**提权内核 payload，以便直接复现完整链路：

| 文件 | 大小 | 说明 |
|---|---|---|
| `libfuxi8550.so` | 1,889,584 B | 面向 **SM8550 / kernel 5.15.178** 的内核提权 payload（静态 ELF，`.so` 仅为命名习惯，实际是可执行镜像）。 |
| `libghostroot.so` | 6,297,784 B | 0073 利用器（ADB 认证绕过 → 取得 `uid=2000` shell 域）。 |

MD5：
```
142355ab39b9205f2cb673afd430fa3c  libfuxi8550.so
da07fd63ba7dbd0f058f311cc2d9f41e  libghostroot.so
```

> ⚠️ **`libfuxi8550.so` 的硬编码内核偏移只对「同一 ROM / 同一 kernel 版本」有效。**
> 换机、换系统版本后必须按目标机的真实 `kallsyms` 重新生成，
> 否则轻则无效，重则触发内核崩溃（RCU stall → 整机锁死，需长按电源重启）。
> 本项目对应的实测环境见「设备前提」。

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

## 免责声明

本项目为**安全研究**用途，旨在研究和披露特定设备/系统版本上的漏洞。
详见 [DISCLAIMER.md](DISCLAIMER.md)。

**禁止**用于任何未经授权的设备或非法目的。
