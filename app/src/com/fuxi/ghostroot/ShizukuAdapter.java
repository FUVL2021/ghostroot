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
        // 备注：只有当 binder 与 service 都非 null 才算就绪
        if (bootstrapped && Shizuku.pingBinder()
                && safeGetBinder() != null && fld("service") != null) {
            lastError = "";
            return true;
        }
        // 缓存不可信 -> 清掉，走完整流程
        bootstrapped = false;
        sAttached = false;
        lastError = "";

        // ------------------------------------------------------------
        // 关键：Shizuku.getBinder() 返回的真实 binder 才是有用的。
        // pingBinder() 可能在内部标志为 true 时也返回 true，但 getBinder()
        // 仍是 null（手动 bootstrap 时常见），此时 onBinderReceived(null)
        // 会走「binder 断了」分支，什么都没灌进去，后续 transactRemote 就抛
        // IllegalStateException: binder haven't been received。
        //
        // 所以顺序必须是：
        //   1) 先主动拿到真实 IBinder（官方 API / provider / intent 三条路）
        //   2) 调 onBinderReceived(真实binder, pkg) -> 灌静态字段 + attachApplication
        // ------------------------------------------------------------

        // 路径 1：Shizuku 静态字段里已经有真实 binder
        IBinder b = safeGetBinder();
        if (b == null) {
            // 路径 2：官方 API 主动要一次（内部会 call 自己的 provider）
            try {
                rikka.shizuku.ShizukuProvider.requestBinderForNonProviderProcess(ctx);
            } catch (Throwable t) {
                lastError = "requestBinder 异常: " + t;
            }
            try { Thread.sleep(300); } catch (Throwable ignored) {}
            b = safeGetBinder();
        }

        // 路径 3：直接 call 自己的 provider 拿 binder
        if (b == null) {
            try {
                ContentResolver cr = ctx.getContentResolver();
                Bundle reply = cr.call(Uri.parse("content://" + AUTHORITY),
                        "getBinder", null, new Bundle());
                if (reply != null) {
                    reply.setClassLoader(moe.shizuku.api.BinderContainer.class.getClassLoader());
                    b = extractBinder(reply);
                } else {
                    lastError = "self-provider getBinder 返回 null";
                }
            } catch (Throwable t) {
                lastError = "self-provider call 异常: " + t;
            }
        }

        if (b == null || !b.pingBinder()) {
            if (lastError.isEmpty()) {
                lastError = "未拿到可用的 Shizuku binder（请确认 Shizuku 以 ADB 模式启动）";
            }
            return false;
        }

        // 拿到真实 binder -> 灌进 Shizuku 静态字段，并完成 attachApplication
        try {
            Shizuku.onBinderReceived(b, ctx.getPackageName());
            sAttached = true;
        } catch (Throwable t) {
            lastError = "onBinderReceived 异常: " + t;
        }

        if (safeGetBinder() == null) {
            lastError = "onBinderReceived 后 binder 仍为 null";
            return false;
        }

        bootstrapped = true;
        lastError = "";
        return true;
    }

    /** 安全地取 Shizuku 的静态 binder（可能为 null）。 */
    private static IBinder safeGetBinder() {
        try { return Shizuku.getBinder(); } catch (Throwable t) { return null; }
    }

    private static boolean safePing() {
        try { return Shizuku.pingBinder(); } catch (Throwable t) { return false; }
    }

    /** 反射读 Shizuku 的私有静态字段（诊断用）。 */
    private static String fld(String name) {
        try {
            java.lang.reflect.Field f = Shizuku.class.getDeclaredField(name);
            f.setAccessible(true);
            Object v = f.get(null);
            if (v == null) return "null";
            if (v instanceof Boolean) return String.valueOf(v);
            return "ok";
        } catch (Throwable t) {
            return "ERR:" + t.getClass().getSimpleName();
        }
    }

    private static boolean sAttached = false;

    /**
     * 完成 attachApplication：把 binder 交给 Shizuku.onBinderReceived()，
     * 内部会调 IShizukuService.Stub.TRANSACTION_attachApplication(=18)。
     * 只做一次。
     */
    private static void attachOnce(Context ctx) {
        if (sAttached) return;
        try {
            Shizuku.onBinderReceived(Shizuku.getBinder(), ctx.getPackageName());
            sAttached = true;
        } catch (Throwable t) {
            lastError = "attachApplication 异常: " + t;
        }
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
            int st = Shizuku.checkSelfPermission();
            if (st == 0) return true; // PERMISSION_GRANTED
            // checkSelfPermission 在手动 bootstrap 的绑定下不可靠，
            // 退化判定：能读到 uid -> 说明调用已放行。
            return Shizuku.getUid() > 0;
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
                if (++guard > 100000) break;
            }
            try { p.waitFor(); } catch (Throwable ignored) {}
            return new String(out.toByteArray(), "UTF-8");
        } catch (Throwable t) {
            lastError = "exec 异常: " + t;
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