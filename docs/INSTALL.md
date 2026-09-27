# 安装与使用

## 依赖软件

| 软件 | 说明 |
|---|---|
| **Shizuku** | 通道②必需。从 [Shizuku 官方](https://shizuku.rikka.app/) 安装，启动 **ADB 模式** |
| **无线调试** | 通道①必需。设置 → 开发者选项 → 无线调试 |

### Shizuku ADB 模式怎么启动

Shizuku 的 ADB 模式需要「用 adb 启动一次服务」。常见方式：

1. **有电脑时**：手机开 USB 调试，连电脑，执行
   ```bash
   adb shell sh /storage/emulated/0/Android/data/moe.shizuku.privileged.api/start.sh
   ```
2. **无电脑时**：用「无线调试」+ 手机上的终端 App（如 Termux）自行配对启动，
   或用 Shizuku 支持的 root 方式。

启动后，Shizuku 主界面会显示「服务正在运行」，且能看到「通过 ADB 运行」。

---

## 安装 GhostRoot

从 Release 下载 `GhostRoot.apk`，或自行构建（见下文）。

⚠️ **首次安装建议先卸载旧版本** —— 本 App 声明了 `ContentProvider`
（Shizuku 接入点），provider 是安装时注册的，覆盖安装有时不刷新。

```bash
adb install -r GhostRoot.apk
```

或在手机上直接点 APK 安装（需允许「安装未知来源应用」）。

---

## 使用

### 第一步：授权 Shizuku

打开 GhostRoot 后：

1. 如果 Shizuku 已启动，App 会通过它自己声明的 provider 收到 binder
2. 首次需要**在 Shizuku App 里授权 GhostRoot**：
   打开 Shizuku → 「已授权应用」→ 找到 GhostRoot → 允许

> 如果授权列表里没有 GhostRoot，说明 provider 没注册成功，
> **卸载重装**再试。

### 第二步：测试 Shell 通道

进「**独立 Shell 终端**」：

1. 选 **① Shizuku**，点 **【探测通道】**
2. 状态栏应显示 `✅ Shizuku 通道可用 (uid=2000)`
3. 输入 `id`，点 **【执行】**，输出应为：
   ```
   uid=2000(shell) gid=2000(shell) context=u:r:shell:s0
   ```

**拿到 `uid=2000` 就说明 shell 域借到了**，这是后续提权的前提。

### 第三步：一键提权

回到主界面，点【一键提权】。App 会自动：

1. 选择可用通道拿 shell 域
2. 推送 payload 到 `/data/local/tmp/`
3. 执行提权

> ⚠️ **风险提示**：提权阶段可能触发内核 **RCU stall**，
> 表现为**整机卡死、无响应**，只能长按电源键强制重启。
> 建议：屏幕保持常亮、单次运行、人工盯着，不要后台长跑。

---

## 从源码构建

### 环境

本项目不使用 Gradle。你需要：

- JDK（能跑 `javac` / `java`）
- `d8.jar`（Android SDK build-tools 里）
- `apksigner.jar`（同上）
- `aapt` + `zipalign`（同上，**x86_64 版本需 qemu 包一层**）
- `android.jar`（API 34，作为 bootclasspath）

### 步骤

**1. 编译 Java**

```bash
javac -source 8 -target 8 -nowarn -encoding UTF-8 \
    -bootclasspath android34.jar \
    -cp "app/libs/shizuku-api-13.1.5.jar:app/libs/shizuku-aidl-13.1.5.jar:app/libs/shizuku-provider-13.1.5.jar" \
    -d classes \
    app/src/com/fuxi/ghostroot/*.java
```

> ⚠️ 注意：
> - `-source 8` 下**不能用 lambda**（`android34.jar` 里没有 `LambdaMetafactory`），
>   全部用匿名内部类
> - classpath **必须包含 `shizuku-provider.jar`**（里面是 `BinderContainer`）

**2. 生成 R.java**

由于不使用 aapt2，`R.java` 需要手工维护。**必须与 `resources.arsc` 里的实际 ID 一致**：

```bash
aapt dump resources <某个已编译的.apk> | grep 'id/'
```

**3. 转 dex**

```bash
java -cp d8.jar com.android.tools.r8.D8 \
    --min-api 23 --lib android34.jar \
    --output dexout \
    classes/com/fuxi/ghostroot/*.class \
    app/libs/shizuku-api-13.1.5.jar \
    app/libs/shizuku-aidl-13.1.5.jar \
    app/libs/shizuku-provider-13.1.5.jar
```

**4. 打包 + 签名**

```bash
python3 build/build_apk.py dexout/classes.dex lib/arm64-v8a out.apk
```

这个脚本会：`aapt package` 编骨架 → 拼装（arsc 用 STORED）→ `zipalign` → `apksigner`。

**5. 验证**

```bash
aapt dump badging out.apk
aapt dump xmltree out.apk AndroidManifest.xml
apksigner verify --print-certs out.apk
zipalign -c 4 out.apk
```

---

## 常见问题

### Q: 安装报「解析软件包时出现问题。(33)」

`PackageParser` 拒绝了产物。常见原因：

1. `resources.arsc` 被压缩了（必须是 STORED）
2. Manifest 手拼过（必须用 aapt 从文本编译）
3. `R.id` 与 arsc 不一致

### Q: 装好后一打开就闪退

`findViewById()` 返回 null。几乎总是 **`R.java` 常量与 `arsc` 不一致**。
用 `aapt dump resources` 核对。

### Q: Shizuku 里看不到 GhostRoot

provider 没注册。确认 Manifest 里有：

```xml
<provider android:name="rikka.shizuku.ShizukuProvider"
          android:authorities="com.fuxi.ghostroot.shizuku"
          android:exported="true" android:multiprocess="false" />
```

然后**卸载重装**。

### Q: 报 `SecurityException: ... INTERACT_ACROSS_USERS_FULL`

你在 call Shizuku 的 `ShizukuManagerProvider` —— 方向错了。
应该反过来：让 Shizuku 推 binder 给你的 provider。详见 README 的
「Shizuku 接入的正确姿势」。

### Q: 0073 探测不到端口

目前端口扫描很弱（只试 11 个固定端口）。Android 16 上
`/proc/net/tcp` 对普通 App 不可读。建议：
- 在终端里**手动填入**你从无线调试界面看到的端口
- 或先用通道② Shizuku