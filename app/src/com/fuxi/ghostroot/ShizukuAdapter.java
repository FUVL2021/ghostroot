package com.fuxi.ghostroot;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuBinderWrapper;
import rikka.shizuku.ShizukuRemoteProcess;

/**
 * Shizuku 备用通道（兜底）。
 *
 * 定位：借用 Shizuku(ADB 模式) 的 uid=2000 shell 域，取得与 0073 等价的 shell。
 *
 * ===== 接入机制（2026-09-27 修正，重要） =====
 * 现代 Shizuku 13.x **不是** App 去 call Shizuku 的 provider（那样会撞
 * Permission Denial: INTERACT_ACROSS_USERS_FULL）。正确方向是**反过来的**：
 *
 *   Shizuku 服务端（shell 域）
 *      └─ call(content://<本App包名>.shizuku, "sendBinder", bundle{EXTRA_BINDER:BinderContainer})
 *             ↓ 推到本 App 自己声明的 provider
 *   rikka.shizuku.ShizukuProvider.handleSendBinder()
 *      └─ BinderContainer.binder → Shizuku.onBinderReceived(binder, pkgName)
 *             ↓ Shizuku 内部保存
 *   之后 Shizuku.pingBinder() == true，即可 exec
 *
 * 所以 Manifest 里必须声明（authority 必须是 <包名>.shizuku）：
 *   <provider android:name="rikka.shizuku.ShizukuProvider"
 *             android:authorities="com.fuxi.ghostroot.shizuku"
 *             android:exported="true" android:multiprocess="false"/>
 *
 * 若进程不是 provider 所在进程（多进程场景），官方提供
 * ShizukuProvider.requestBinderForNonProviderProcess(ctx)：它会
 *   1) 注册 BINDER_RECEIVED 广播接收器；
 *   2) call 自己的 provider 的 "getBinder"；
 *   3) 从返回 Bundle 取 BinderContainer.binder。
 * 本 App 单进程，直接复用官方 API 即可，不自己造轮子。
 */
public final class ShizukuAdapter {

    private ShizukuAdapter() {}

    /** Shizuku 包名（服务端与 UI 同包）。 */
    public static final String PKG = "moe.shizuku.privileged.api";
    /** 本 App 的 provider authority（必须是 <包名>.shizuku）。 */
    public static final String AUTHORITY = "com.fuxi.ghostroot.shizuku";
    /** binder 在 Bundle 里的 key（= ShizukuProvider.EXTRA_BINDER）。 */
    public static final String EXTRA_BINDER = "moe.shizuku.privileged.api.intent.extra.BINDER";

    private static boolean bootstrapped = false;
    private static String lastError = "";

    public static String lastError() { return lastError; }

    /**
     * 完成接入。做法：
     *   A) 先看 binder 是否已经在（Shizuku 推送成功后 Shizuku.pingBinder() 为 true）
     *   B) 否则调官方 ShizukuProvider.requestBinderForNonProviderProcess(ctx) 主动要一次
     *   C) 再不行，直接 call 自己的 provider "getBinder" 兜底
     */
    public static synchronized boolean bootstrap(Context ctx) {
        if (bootstrapped && Shizuku.pingBinder()) { lastError = ""; return true; }
        lastError = "";

        // A) 已经有了？
        try {
            if (Shizuku.pingBinder()) { bootstrapped = true; return true; }
        } catch (Throwable ignored) {}

        // B) 官方 API：请求 binder（内部会注册广播 + call 自己的 provider）
        try {
            rikka.shizuku.ShizukuProvider.requestBinderForNonProviderProcess(ctx);
        } catch (Throwable t) {
            lastError = "requestBinder 异常: " + t;
        }

        // 给 Shizuku 一点时间完成 binder 传递
        try { Thread.sleep(300); } catch (Throwable ignored) {}

        try {
            if (Shizuku.pingBinder()) { bootstrapped = true; lastError = ""; return true; }
        } catch (Throwable ignored) {}

        // C) 兜底：直接 call 自己 provider 的 getBinder
        try {
            ContentResolver cr = ctx.getContentResolver();
            Bundle reply = cr.call(Uri.parse("content://" + AUTHORITY),
                    "getBinder", null, new Bundle());
            if (reply != null) {
                reply.setClassLoader(moe.shizuku.api.BinderContainer.class.getClassLoader());
                IBinder binder = extractBinder(reply);
                if (binder != null && binder.pingBinder()) {
                    Shizuku.onBinderReceived(binder, ctx.getPackageName());
                    bootstrapped = true;
                    lastError = "";
                    return true;
                }
                lastError = "self-provider getBinder 无 binder, keys=" + reply.keySet();
            } else {
                lastError = "self-provider getBinder 返回 null";
            }
        } catch (Throwable t) {
            lastError = "self-provider call 异常: " + t;
        }

        if (lastError.isEmpty()) {
            lastError = "Shizuku 服务未运行/未授权（请确认 Shizuku 以 ADB 模式启动）";
        }
        return false;
    }

    /** 从 Bundle 取 Shizuku 的 binder（BinderContainer / 直接 IBinder 都兼容）。 */
    private static IBinder extractBinder(Bundle b) {
        try {
            Object o = b.get(EXTRA_BINDER);
            if (o instanceof moe.shizuku.api.BinderContainer) {
                return ((moe.shizuku.api.BinderContainer) o).binder;
            }
            if (o instanceof IBinder) return (IBinder) o;
        } catch (Throwable ignored) {}
        try {
            for (String k : b.keySet()) {
                Object v = b.get(k);
                if (v instanceof moe.shizuku.api.BinderContainer) {
                    return ((moe.shizuku.api.BinderContainer) v).binder;
                }
                if (v instanceof IBinder) return (IBinder) v;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /** Shizuku 的 binder 是否活着（服务在跑）。 */
    public static boolean isBinderAlive() {
        try { return Shizuku.pingBinder(); } catch (Throwable t) { return false; }
    }

    /** 是否已获得 Shizuku 授权。 */
    public static boolean isGranted() {
        try {
            if (!Shizuku.pingBinder()) return false;
            return Shizuku.checkSelfPermission() == 0; // 0 = PERMISSION_GRANTED
        } catch (Throwable t) {
            return false;
        }
    }

    /** 主动请求授权（Shizuku 会弹窗；结果走 addRequestPermissionResultListener）。 */
    public static void requestPermission(int requestCode) {
        try { Shizuku.requestPermission(requestCode); } catch (Throwable ignored) {}
    }

    /** 当前借到的 uid（2000 = shell）。 */
    public static int uid() {
        try { return Shizuku.getUid(); } catch (Throwable t) { return -1; }
    }

    /** 当前借到的 SELinux 上下文，例如 u:r:shell:s0。 */
    public static String selinuxContext() {
        try { return Shizuku.getSELinuxContext(); } catch (Throwable t) { return null; }
    }

    /** Shizuku 服务端版本。 */
    public static int serviceVersion() {
        try { return Shizuku.getVersion(); } catch (Throwable t) { return -1; }
    }

    /**
     * 通过 Shizuku 在 shell 域执行命令，返回合并后的 stdout+stderr 文本。
     * 失败返回 null。
     */
    public static String exec(String cmd) {
        try {
            IBinder binder = Shizuku.getBinder();
            if (binder == null) return null;

            IShizukuService svc =
                    IShizukuService.Stub.asInterface(new ShizukuBinderWrapper(binder));
            if (svc == null) return null;

            IRemoteProcess rp = svc.newProcess(new String[]{"sh", "-c", cmd}, null, null);
            if (rp == null) return null;

            Process p = wrap(rp);
            if (p == null) return null;

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InputStream is = p.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            int guard = 0;
            while ((n = is.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (++guard > 100000) break;  // 防止无限流
            }

            try { p.waitFor(); } catch (Throwable ignored) {}
            return new String(out.toByteArray(), "UTF-8");
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 把 IRemoteProcess 包成 Process。
     * ShizukuRemoteProcess(IRemoteProcess) 是 package-private，只能反射。
     */
    private static Process wrap(IRemoteProcess rp) {
        try {
            Constructor<ShizukuRemoteProcess> c =
                    ShizukuRemoteProcess.class.getDeclaredConstructor(IRemoteProcess.class);
            c.setAccessible(true);
            return c.newInstance(rp);
        } catch (Throwable t) {
            try {
                Constructor<?>[] all = ShizukuRemoteProcess.class.getDeclaredConstructors();
                for (Constructor<?> cc : all) {
                    Class<?>[] ps = cc.getParameterTypes();
                    if (ps.length == 1 && IRemoteProcess.class.isAssignableFrom(ps[0])) {
                        cc.setAccessible(true);
                        return (Process) cc.newInstance(rp);
                    }
                }
            } catch (Throwable ignored) {}
            return null;
        }
    }

    /** 组合信息，用于日志展示。 */
    public static String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("binder=").append(isBinderAlive());
        sb.append(" ver=").append(serviceVersion());
        sb.append(" granted=").append(isGranted());
        sb.append(" uid=").append(uid());
        sb.append(" ctx=").append(selinuxContext());
        return sb.toString();
    }
}