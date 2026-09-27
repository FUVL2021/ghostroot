package com.fuxi.ghostroot;

import android.content.Context;

/**
 * Shell 通道实现之二：Shizuku（兜底）。
 *
 * 前提：Shizuku 已用「ADB 模式」启动，且本 App 已被授权。
 * 此时借到的 uid = 2000 (shell)，与 0073 等价。
 *
 * 推送 8550 的策略（方案②）：
 *   Shizuku 是 shell 域，能直接读 App 的 native 库目录，
 *   所以一条 cp 就能把 libfuxi8550.so 搬到 /data/local/tmp/。
 *   （APK 里 libfuxi8550.so 和真正的 8550 是同一个文件。）
 */
public class ShizukuShell implements Shell {

    private final Context ctx;
    private final StringBuilder logBuf = new StringBuilder();

    public ShizukuShell(Context ctx) {
        this.ctx = ctx;
    }

    @Override public String name() { return "Shizuku"; }

    @Override public String exec(String cmd) {
        String r = ShizukuBridge.exec(cmd);
        if (r == null) {
            logBuf.append("[-] Shizuku exec failed: ").append(cmd).append("\n");
        }
        return r;
    }

    @Override public String log() { return logBuf.toString(); }

    /**
     * 推送：Shizuku 下直接 cp App 自带的 libfuxi8550.so 到远端。
     * data 参数只有在 caller 传的是 libfuxi8550.so 的内容时才准确；
     * 这里统一按"从 native lib 目录 cp"来做，保证与 APK 内文件一致。
     */
    @Override public boolean push(byte[] data, String remote) {
        try {
            String libDir = ctx.getApplicationInfo().nativeLibraryDir;
            String src = libDir + "/libfuxi8550.so";
            logBuf.append("[*] shizuku cp ").append(src).append(" -> ").append(remote).append("\n");

            String c = ShizukuBridge.exec(
                    "cp " + src + " " + remote + " 2>&1; "
                    + "chmod 755 " + remote + " 2>&1; "
                    + "ls -l " + remote + "; stat -c %s " + remote);
            logBuf.append(c == null ? "(null)" : c).append("\n");
            if (c == null) return false;

            // 校验：文件大小必须与 data 长度一致
            return c.indexOf(String.valueOf(data.length)) >= 0;
        } catch (Throwable t) {
            logBuf.append("[-] push error: ").append(t).append("\n");
            return false;
        }
    }

    @Override public boolean verify() {
        String id = ShizukuBridge.exec("id");
        if (id == null) return false;
        return id.indexOf("uid=2000") >= 0 || id.indexOf("uid=0") >= 0;
    }

    @Override public void close() {
        // 保持 binder 存活，不做清理
    }
}