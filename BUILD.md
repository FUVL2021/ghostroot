# 构建说明（GhostRoot / Vin的提权工具）

> 目标机型：小米 13（fuxi / SM8550 / kalama），Android 16，内核 5.15.178，未解锁 BL。
> 本工程仅供安全研究与自有设备验证使用。

## 工程结构

```
app/
├── AndroidManifest.xml          # versionCode=20 / versionName=2.0
├── lib/arm64-v8a/               # 预编译 native（打包进 APK）
│   ├── libghostroot.so          # 0073 利用器（CVE-2026-0073）
│   └── libfuxi8550.so           # 8550 提权器（vermeer-ghostroot profile 178）
├── libs/                        # 编译期依赖（不打包）
│   ├── shizuku-api-13.1.5.jar
│   ├── shizuku-aidl-13.1.5.jar
│   └── shizuku-provider-13.1.5.jar
├── res/
└── src/com/fuxi/ghostroot/      # Java 源码（见下）
```

## 双 dex 架构（关键）

本工程使用「壳层 dex + 加密业务层 dex」两层结构：

| 层 | 内容 | 说明 |
|---|---|---|
| **壳层** `classes.dex`（明文） | `StubApp` / `ShizukuAdapter` / `R` + 三个 shizuku jar | 在 `Application.onCreate` 之前就要可用（`ContentProvider` 会先实例化） |
| **业务层** `app.dex.enc`（AES 加密） | `Adb0073` / `Adb0073Shell` / `MainActivity` / `Shell` / `ShellTerminalActivity` / `ShizukuBridge` / `ShizukuShell` / `SelfSignedCert` / `DisclaimerActivity` / `R` | 运行时由 `StubApp` 解密后 `DexClassLoader` 加载 |

### ⚠️ 必须遵守的两条铁律

1. **`ShizukuAdapter` 必须留在壳层**，且壳层 dex **必须**包含三个 shizuku jar。
   `ShizukuAdapter` 通过 `Shizuku.onBinderReceived()` 写入 `rikka.shizuku.Shizuku` 的静态字段（`binder` / `service`），
   这些字段是**类级别**的。

2. **业务层 d8 绝对不能把 shizuku jar 打进去**。
   否则会产生**两个 `rikka.shizuku.Shizuku` 类**（壳层一份、业务层一份）、**两套互不同步的静态字段**，
   症状是：
   ```
   java.lang.IllegalStateException: binder haven't been received
       at rikka.shizuku.Shizuku.requireService(Shizuku.java:430)
       at rikka.shizuku.Shizuku.getVersion(Shizuku.java:526)
       at rikka.shizuku.ShizukuBinderWrapper.transact(ShizukuBinderWrapper.java:31)
   ```
   —— 壳层那份 `service` 已就绪，但 `ShizukuBinderWrapper` 调的是业务层那份（`service == null`）。

   **修法**：业务层 `d8` 只传自己编译出的 `.class`，不传 jar（编译期 `javac -cp` 仍需 jar 做符号解析）。

## 构建步骤

### 1. 编译

```bash
APP=/path/to/fuxi-ghostroot/app
LIBS="$APP/libs"
SRC="$APP/src/com/fuxi/ghostroot"
CP=/path/to/android.jar          # 需 API 34 及以上

# 壳层
mkdir -p dexA
javac -encoding UTF-8 -source 8 -target 8 -bootclasspath $CP -cp "$LIBS/*" -d dexA \
    $SRC/StubApp.java $SRC/ShizukuAdapter.java $SRC/R.java

# 业务层
mkdir -p dexB
javac -encoding UTF-8 -source 8 -target 8 -bootclasspath $CP -cp "$LIBS/*" -d dexB \
    $SRC/Adb0073.java $SRC/Adb0073Shell.java $SRC/DisclaimerActivity.java \
    $SRC/MainActivity.java $SRC/SelfSignedCert.java $SRC/Shell.java \
    $SRC/ShellTerminalActivity.java $SRC/ShizukuBridge.java $SRC/ShizukuShell.java $SRC/R.java
```

### 2. dex 化

```bash
D8=/path/to/d8

# 壳层：带三个 shizuku jar
$D8 --min-api 29 --output dexA $LIBS/shizuku-api-13.1.5.jar \
    $LIBS/shizuku-aidl-13.1.5.jar $LIBS/shizuku-provider-13.1.5.jar \
    $(find dexA -name '*.class')

# 业务层：不带 jar！（见上文铁律 2）
$D8 --min-api 29 --output dexB $(find dexB -name '*.class')
```

### 3. 加密业务层 dex

```bash
# key = "VinGhostRoot2026" (ASCII, 16 字节) → hex 56696e47686f7374526f6f7432303236
openssl enc -aes-128-ecb -K 56696e47686f7374526f6f7432303236 \
    -in dexB/classes.dex -out app.dex.enc
```

### 4. 打包 + 签名

把 `dexA/classes.dex` 作为 APK 的 `classes.dex`，
`app.dex.enc` 作为 `assets/app.dex.enc`，
再把 `app/lib/arm64-v8a` 下的 so 放进 APK 的 `lib/arm64-v8a/`。

> ⚠️ 注意区分 `app/lib/`（native so 目录）和 `app/libs/`（jar 目录），传错会产出残缺 APK。

## 提权流程

```
一键提权
   ├── 主路：0073 (CVE-2026-0073, TLS + 无线调试) → shell 域(uid=2000)
   └── 兜底：Shizuku (需用户已装 Shizuku 且 ADB 模式运行) → shell 域(uid=2000)
         └── 8550 (CVE-2026-43499, futex PI 竞态 → KWRITE) → ROOT
```

## 已知约束

- 未解锁 BL：不可写分区、不能用 mtdoops 取证。
- 内核 `CONFIG_USER_NS is not set`：所有依赖 userns 的提权在本机不可用。
- 8550 exploit 竞态失败可能导致 RCU stall 锁死整机，需长按电源强制重启。
- Shizuku 客户端 jar 版本（13.1.5）与服务端（13.6.0）AIDL 兼容：
  `SERVER_VERSION = 13`、`newProcess = 7`、`attachApplication = 18` 均未变。
  但 13.6 服务端 `newProcess` 会校验调用方是否已 `attachApplication`，
  因此必须走 `Shizuku.onBinderReceived()` 完整链路。
