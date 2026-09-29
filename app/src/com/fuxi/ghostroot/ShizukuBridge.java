package com.fuxi.ghostroot;

import android.content.Context;

import java.lang.reflect.Method;

/**
 * ShizukuAdapter 的反射桥（放在业务层，供 MainActivity / ShellTerminalActivity /
 * ShizukuShell 调用）。
 *
 * 背景：ShizukuAdapter 里会直接引用 moe.shizuku.api.BinderContainer 等 Shizuku 类，
 * 而这些类所在的 dex 与业务 dex 分属两个 ClassLoader，跨层解析只能单向通过
 * parent 链。为了让两边都能正确解析，ShizukuAdapter 被放在「壳层」，
 * 业务层这边统一通过本桥反射调用它。
 *
 * 本类的方法签名与 ShizukuAdapter 一一对应，调用方无需关心实现细节。
 */
final class ShizukuBridge {

    /** 缓存壳层（AppClassLoader）的 ClassLoader。 */
    private static volatile ClassLoader sShellLoader;

    private ShizukuBridge() {
    }

    private static Method m(String name, Class<?>... types) throws Exception {
        Method x = mClass().getMethod(name, types);
        x.setAccessible(true);
        return x;
    }

    /**
     * 拿到壳层（AppClassLoader）里的 ShizukuAdapter 类。
     *
     * 不能用 Class.forName("...")（会用业务层的 loader），
     * 也不能只靠 getSystemClassLoader()（它拿到的 loader 未必是加载壳 dex 的那个）。
     *
     * 可靠做法：从 Application 实例（壳层类 StubApp）反推它的 ClassLoader ——
     * 那是确凿加载了壳 dex 的 loader。拿不到时再退回系统 ClassLoader。
     */
    private static Class<?> mClass() throws Exception {
        ClassLoader cl = shellLoader();
        if (cl == null) cl = ClassLoader.getSystemClassLoader();
        if (cl == null) cl = ShizukuBridge.class.getClassLoader();
        return Class.forName("com.fuxi.ghostroot.ShizukuAdapter", true, cl);
    }

    /** 通过反射从当前 Application 实例拿到壳层 ClassLoader。 */
    private static ClassLoader shellLoader() {
        if (sShellLoader != null) return sShellLoader;
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            Object app = at.getMethod("getApplication").invoke(thread);
            if (app != null) {
                sShellLoader = app.getClass().getClassLoader();
            }
        } catch (Throwable ignored) {
        }
        return sShellLoader;
    }

    static String lastError() {
        try {
            return (String) m("lastError").invoke(null);
        } catch (Throwable t) {
            return "ShizukuAdapter 反射失败: " + t;
        }
    }

    static boolean bootstrap(Context ctx) {
        try {
            Object r = m("bootstrap", Context.class).invoke(null, ctx);
            return r instanceof Boolean && (Boolean) r;
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean isBinderAlive() {
        try {
            Object r = m("isBinderAlive").invoke(null);
            return r instanceof Boolean && (Boolean) r;
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean isGranted() {
        try {
            Object r = m("isGranted").invoke(null);
            return r instanceof Boolean && (Boolean) r;
        } catch (Throwable t) {
            return false;
        }
    }

    static void requestPermission(int requestCode) {
        try {
            m("requestPermission", int.class).invoke(null, requestCode);
        } catch (Throwable ignored) {
        }
    }

    static int uid() {
        try {
            Object r = m("uid").invoke(null);
            return r instanceof Integer ? (Integer) r : -1;
        } catch (Throwable t) {
            return -1;
        }
    }

    static String selinuxContext() {
        try {
            Object r = m("selinuxContext").invoke(null);
            return r == null ? "" : (String) r;
        } catch (Throwable t) {
            return "";
        }
    }

    static int serviceVersion() {
        try {
            Object r = m("serviceVersion").invoke(null);
            return r instanceof Integer ? (Integer) r : -1;
        } catch (Throwable t) {
            return -1;
        }
    }

    static String exec(String cmd) {
        try {
            Object r = m("exec", String.class).invoke(null, cmd);
            return r == null ? "" : (String) r;
        } catch (Throwable t) {
            // InvocationTargetException 里包着真实原因（如 binder haven't been received）
            Throwable c = (t instanceof java.lang.reflect.InvocationTargetException
                    && t.getCause() != null) ? t.getCause() : t;
            return "[EXEC_THROW] " + c;
        }
    }

    static String describe() {
        try {
            Object r = m("describe").invoke(null);
            return r == null ? "" : (String) r;
        } catch (Throwable t) {
            return "ShizukuAdapter 反射失败: " + t;
        }
    }
}