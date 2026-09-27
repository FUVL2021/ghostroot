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
    private Button runBtn, probeBtn, copyBtn, saveBtn;
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
        portIn.setHint("留空=自动扫描 30000-50000");
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
        LinearLayout ops = new LinearLayout(this);
        ops.setOrientation(LinearLayout.HORIZONTAL);
        copyBtn = new Button(this);
        copyBtn.setText("复制日志");
        saveBtn = new Button(this);
        saveBtn.setText("保存到 /sdcard");
        ops.addView(copyBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        ops.addView(saveBtn, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(ops);

        setContentView(root);

        probeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { probe(); }
        });
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { exec(); }
        });
        copyBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { copyLog(); }
        });
        saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { saveLog(); }
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

    /** 扫描无线调试端口：先猜常见值，再范围扫。 */
    private int probe0073() {
        // 用户手填优先
        String manual = portIn.getText() == null ? "" : portIn.getText().toString().trim();
        if (!manual.isEmpty()) {
            try { return Integer.parseInt(manual); } catch (Throwable ignored) {}
        }
        log("[0073] 扫描 127.0.0.1 上监听的端口……");
        // 用 /proc/net/tcp 找本机 LISTEN 的端口（App 可读自己 uid 的，shell 不行——
        // 这里退化为纯连接测试常见端口段）
        int[] common = {5555, 37000, 37001, 38000, 39000, 40000, 41000, 42000, 43000, 44000, 45000};
        for (int p : common) {
            if (tcpAlive(p)) { log("[0073] 命中端口 " + p); return p; }
        }
        return -1;
    }

    private boolean tcpAlive(int port) {
        java.net.Socket s = null;
        try {
            s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 300);
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
