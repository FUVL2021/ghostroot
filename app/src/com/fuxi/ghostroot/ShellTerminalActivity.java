package com.fuxi.ghostroot;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 独立 Shell 终端（双通道版）。
 *
 * 目的：绕开 8550 提权流水线，直接测两条「拿 shell 域」的通道：
 *
 *   ① Shizuku 通道 —— 借 Shizuku(ADB 模式) 的 uid=2000 shell 域（兜底 / 正路）
 *   ② 0073 通道   —— CVE-2026-0073 无线调试 TLS 认证绕过（主路，走漏洞）
 *
 * 两条路拿到的都是 uid=2000 / u:r:shell:s0，后续 8550 流程完全相同。
 * 本页只做「通道可达性 + 命令执行」验证，方便分别排查。
 *
 * 全部 UI 用纯 Java 构建（本工程无 aapt2/Gradle，资源表不能重编）。
 */
public class ShellTerminalActivity extends Activity {

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final StringBuilder fullLog = new StringBuilder();

    private TextView output;
    private TextView status;
    private EditText input;
    private EditText portIn;
    private Button runBtn, probeBtn;
    private RadioGroup channelGroup;

    /** 已探测可用的 0073 端口（-1 = 未探测到）。 */
    private int adbPort = -1;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(12, 12, 12, 12);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        TextView hint = new TextView(this);
        hint.setText("Shell 终端（双通道）\n"
                + "① Shizuku：借 Shizuku(ADB模式) 的 shell 域\n"
                + "② 0073：CVE-2026-0073 无线调试绕过（主路）\n"
                + "两条路 uid 都应为 2000 / u:r:shell:s0");
        hint.setTextColor(0xFF8B949E);
        hint.setTextSize(12);
        root.addView(hint);

        // ---- 通道选择 ----
        channelGroup = new RadioGroup(this);
        channelGroup.setOrientation(RadioGroup.HORIZONTAL);
        RadioButton rbShizuku = new RadioButton(this);
        rbShizuku.setText("① Shizuku");
        rbShizuku.setId(1001);
        rbShizuku.setChecked(true);
        RadioButton rb0073 = new RadioButton(this);
        rb0073.setText("② 0073");
        rb0073.setId(1002);
        channelGroup.addView(rbShizuku);
        channelGroup.addView(rb0073);
        root.addView(channelGroup);

        // ---- 0073 端口输入（仅选 ② 时需要）----
        LinearLayout portRow = new LinearLayout(this);
        portRow.setOrientation(LinearLayout.HORIZONTAL);
        TextView portLbl = new TextView(this);
        portLbl.setText("0073 端口: ");
        portLbl.setTextColor(0xFF8B949E);
        portLbl.setTextSize(12);
        portIn = new EditText(this);
        portIn.setHint("留空=自动扫描(候选+全段)");
        portIn.setInputType(InputType.TYPE_CLASS_NUMBER);
        portIn.setTextSize(12);
        portIn.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        portRow.addView(portLbl);
        portRow.addView(portIn);
        root.addView(portRow);

        // ---- 状态行 ----
        status = new TextView(this);
        status.setTextColor(0xFFFFC107);
        status.setTextSize(12);
        status.setText("状态: 未探测");
        root.addView(status);

        // ---- 命令输入 ----
        input = new EditText(this);
        input.setHint("id");
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        input.setLines(3);
        input.setBackgroundColor(0xFF0A0D10);
        input.setTextColor(0xFFC9D1D9);
        root.addView(input);

        // ---- 探测 + 执行 ----
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        probeBtn = new Button(this);
        probeBtn.setText("探测通道");
        runBtn = new Button(this);
        runBtn.setText("执行 (Run)");
        btnRow.addView(probeBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        btnRow.addView(runBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(btnRow);

        // ---- 输出 ----
        ScrollView scroll = new ScrollView(this);
        scroll.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        scroll.setFillViewport(true);
        output = new TextView(this);
        output.setTextColor(0xFFC9D1D9);
        output.setTextSize(11);
        output.setMovementMethod(ScrollingMovementMethod.getInstance());
        scroll.addView(output, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll);

        // ---- 操作按钮行 ----
        // 注：v29 起删除「复制日志 / 保存到 sdcard」按钮 ——
        //     日志区 output 已设 textIsSelectable，长按即可选中复制。
        setContentView(root);

        probeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { probe(); }
        });
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { exec(); }
        });

        log("Shell 终端就绪（双通道）。");
        log("建议先点【探测通道】，再看状态行。");
    }

    private boolean useShizuku() { return channelGroup.getCheckedRadioButtonId() == 1001; }

    // ============================================================
    // 探测
    // ============================================================
    private void probe() {
        log("[*] 探测通道……");
        probeBtn.setEnabled(false);
        new Thread(new Runnable() {
            @Override public void run() {
                if (useShizuku()) {
                    final boolean ok = ShizukuAdapter.bootstrap(ShellTerminalActivity.this);
                    String desc = ShizukuAdapter.describe();
                    String err = ShizukuAdapter.lastError();
                    log("[Shizuku] bootstrap=" + ok + (err.isEmpty() ? "" : " err=" + err));
                    log("[Shizuku] " + desc);
                    if (ok) {
                        String id = ShizukuAdapter.exec("id");
                        log("[Shizuku] id => " + (id == null ? "(null)" : id.trim()));
                        if (id != null && (id.contains("uid=2000") || id.contains("uid=0"))) {
                            setStatus("✅ Shizuku 通道可用 (uid=2000)", 0xFF4CAF50);
                        } else if (id == null) {
                            setStatus("⚠️ Shizuku 已连接但 exec 无返回（授权？）", 0xFFFF9800);
                        } else {
                            setStatus("⚠️ Shizuku 返回非 shell: " + id.trim(), 0xFFFF9800);
                        }
                    } else {
                        setStatus("❌ Shizuku 不可用: " + err, 0xFFF44336);
                    }
                } else {
                    int port = probe0073();
                    if (port > 0) {
                        adbPort = port;
                        String id = new Adb0073().run("127.0.0.1", port, "id");
                        log("[0073] port=" + port + " id => " + (id == null ? "(null)" : id.trim()));
                        if (id != null && (id.contains("uid=2000") || id.contains("uid=0"))) {
                            setStatus("✅ 0073 通道可用 (port=" + port + ")", 0xFF4CAF50);
                        } else {
                            setStatus("⚠️ 0073 端口连通但 id 异常", 0xFFFF9800);
                        }
                    } else {
                        setStatus("❌ 未找到 0073 端口（无线调试没开？）", 0xFFF44336);
                    }
                }
                ui.post(new Runnable() { @Override public void run() { probeBtn.setEnabled(true); } });
            }
        }, "probe").start();
    }

    /**
     * 扫描无线调试（adbd）端口。
     *
     * 背景（实测）：
     *   - 本地回环上「端口未监听」时 connect() 会**立刻**返回 ECONNREFUSED（实测 <1ms），
     *     所以扫全网段并不慢，真正的瓶颈只是 connect() 系统调用本身。
     *   - 小米 / HyperOS 的无线调试端口**不在固定值上**，实测某台 fuxi 上是 32145，
     *     既不是 5555 也不在 37000~45000 常见段 —— 旧版只试 11 个固定端口，
     *     所以「点完立刻弹失败」。
     *   - Android 10+ 上 /proc/net/tcp 对普通 App 不可读（Permission denied），
     *     无法直接枚举 LISTEN 端口，只能主动 connect 探测。
     *
     * 策略：
     *   1) 用户手填优先；
     *   2) 先试一批「高概率候选」（5555 / 32145 / 37000+ 常见段等），命中即返回；
     *   3) 未命中则做 5000~65535 全段**并发**扫描，命中即停。
     */
    private int probe0073() {
        // 1) 用户手填优先
        String manual = portIn.getText() == null ? "" : portIn.getText().toString().trim();
        if (!manual.isEmpty()) {
            try {
                int p = Integer.parseInt(manual);
                log("[0073] 使用手填端口 " + p);
                return p;
            } catch (Throwable ignored) {}
        }

        // 2) 高概率候选（实测小米无线调试端口可能落在非常规位置，这里覆盖常见值）
        int[] candidates = {
                5555,                                   // 标准 adb tcp
                32145,                                  // 实测 fuxi/HyperOS 无线调试端口
                37000, 37001, 38000, 39000, 40000,      // 旧版覆盖区间
                41000, 42000, 43000, 44000, 45000,
                5037,                                   // adb server 默认
                5556, 5557, 5558, 5559                  // 多设备 adb tcp
        };
        for (int p : candidates) {
            String hs = new Adb0073().probe("127.0.0.1", p);
            if (hs != null) {
                log("[0073] 候选端口 " + p + " ADB 握手成功 (" + hs + ")");
                return p;
            }
        }

        // 3) 全段并发扫描（判据同样是「会说 ADB 协议」，而非仅 TCP 可连）
        log("[0073] 候选未命中，开始并发扫描 5000-65535 …（按 ADB 握手判定，命中即停）");
        final int found = scanRangeConcurrent(5000, 65535, 96);
        if (found > 0) {
            log("[0073] 扫描命中端口 " + found);
            setStatus("✅ 找到 ADB 端口 " + found, 0xFF4CAF50);
        } else {
            log("[0073] 扫描结束，未发现会响应 ADB 握手的端口（无线调试没开？）");
        }
        return found;
    }

    /**
     * 多线程并发扫描 [from, to] 闭区间，返回第一个可连接端口（否则 -1）。
     * 采用「分块 + 提前退出」：每块内串行、块间并发，命中后置位退出。
     */
    private int scanRangeConcurrent(final int from, final int to, final int threads) {
        final java.util.concurrent.atomic.AtomicInteger hit =
                new java.util.concurrent.atomic.AtomicInteger(-1);
        final java.util.concurrent.atomic.AtomicInteger cursor =
                new java.util.concurrent.atomic.AtomicInteger(from);
        final int total = to - from + 1;
        final java.util.concurrent.atomic.AtomicInteger done =
                new java.util.concurrent.atomic.AtomicInteger(0);
        final int chunk = 64; // 每个线程每次领 64 个端口

        Thread[] pool = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            pool[i] = new Thread(new Runnable() {
                @Override public void run() {
                    while (hit.get() < 0) {
                        int start = cursor.getAndAdd(chunk);
                        if (start > to) return;
                        int end = Math.min(start + chunk - 1, to);
                        for (int p = start; p <= end; p++) {
                            if (hit.get() >= 0) return;
                            // ① 先做极快的 TCP 连通性筛选（未监听端口瞬时 ECONNREFUSED）
                            if (!tcpAlive(p, 120)) continue;
                            // ② 只有连得上的端口才做 ADB 握手，避免 6 万次 700ms 超时
                            if (new Adb0073().probe("127.0.0.1", p) != null) {
                                hit.compareAndSet(-1, p);
                                return;
                            }
                        }
                        int d = done.addAndGet(end - start + 1);
                        if (d % 4000 == 0) {
                            setStatus("扫描中… " + d + "/" + total, 0xFFFFC107);
                        }
                    }
                }
            }, "scan-" + i);
            pool[i].start();
        }
        for (Thread t : pool) {
            try { t.join(); } catch (Throwable ignored) {}
        }
        return hit.get();
    }

    private boolean tcpAlive(int port, int timeoutMs) {
        java.net.Socket s = null;
        try {
            s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), timeoutMs);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (s != null) s.close(); } catch (Throwable ignored) {}
        }
    }

    private void setStatus(final String s, final int color) {
        ui.post(new Runnable() {
            @Override public void run() {
                status.setText("状态: " + s);
                status.setTextColor(color);
            }
        });
    }

    // ============================================================
    // 执行
    // ============================================================
    private void exec() {
        final String cmd = input.getText() == null ? "" : input.getText().toString().trim();
        if (cmd.isEmpty()) return;
        fullLog.setLength(0);
        output.setText("");
        log("$ " + cmd);
        doExec(cmd);
    }

    private void doExec(final String cmd) {
        runBtn.setEnabled(false);
        new Thread(new Runnable() {
            @Override public void run() {
                if (useShizuku()) {
                    boolean ok = ShizukuAdapter.bootstrap(ShellTerminalActivity.this);
                    if (!ok) {
                        log("[!] Shizuku 不可用: " + ShizukuAdapter.lastError());
                    } else {
                        String r = ShizukuAdapter.exec(cmd);
                        log(r == null ? "(null)" : r);
                    }
                } else {
                    int port = adbPort;
                    if (port <= 0) {
                        port = probe0073();
                        if (port > 0) adbPort = port;
                    }
                    if (port <= 0) {
                        log("[!] 没有可用 0073 端口，请先开无线调试并点【探测通道】。");
                    } else {
                        Adb0073 a = new Adb0073();
                        String r = a.run("127.0.0.1", port, cmd);
                        log(a.log() == null ? "" : a.log());
                        log(r == null ? "(null)" : r);
                    }
                }
                ui.post(new Runnable() { @Override public void run() { runBtn.setEnabled(true); } });
            }
        }, "exec").start();
    }

    // ============================================================
    // 工具
    // ============================================================
    private void log(final String s) {
        ui.post(new Runnable() {
            @Override public void run() {
                fullLog.append(s).append("\n");
                output.append(s + "\n");
            }
        });
    }

    private void copyLog() {
        try {
            android.content.ClipboardManager cm =
                    (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(android.content.ClipData.newPlainText("ShellLog", fullLog.toString()));
            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
        } catch (Throwable t) {
            Toast.makeText(this, "复制失败: " + t, Toast.LENGTH_LONG).show();
        }
    }

    private void saveLog() {
        try {
            String body = "Shell log\nmodel=" + android.os.Build.MODEL + "\n" + fullLog;
            java.io.FileOutputStream f = new java.io.FileOutputStream("/sdcard/ShellTerminal_log.txt");
            f.write(body.getBytes());
            f.flush();
            f.close();
            Toast.makeText(this, "已保存 /sdcard/ShellTerminal_log.txt", Toast.LENGTH_LONG).show();
        } catch (Throwable t) {
            Toast.makeText(this, "保存失败: " + t, Toast.LENGTH_LONG).show();
        }
    }
}