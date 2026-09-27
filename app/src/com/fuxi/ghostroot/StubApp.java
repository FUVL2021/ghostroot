package com.fuxi.ghostroot;

import android.app.Application;
import android.content.Context;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * DEX 加密壳（v31）。
 *
 * 原理：
 *   · 真正的业务 dex 被 AES 加密后放进 assets/app.dex.enc；
 *   · 本类作为 Application 在进程最早执行，解密出明文 dex 字节，
 *     用 InMemoryDexClassLoader 加载进内存（不落盘）。
 *
 * 目的：直接解包 APK 只能看到一个空壳 Application，
 *      业务代码/ApiKey/端口逻辑不在明文 classes.dex 里，
 *      显著提高「随手改」的门槛（非绝对安全，静态分析仍可逆向壳）。
 */
public class StubApp extends Application {

    /** 16 字节 AES 密钥（与打包脚本一致）。 */
    private static final byte[] KEY = {
            0x56, 0x69, 0x6E, 0x47, 0x68, 0x6F, 0x73, 0x74,
            0x52, 0x6F, 0x6F, 0x74, 0x32, 0x30, 0x32, 0x36
    };

    private static ClassLoader sLoader;

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            byte[] enc = readAsset(this, "app.dex.enc");
            if (enc != null && enc.length > 0) {
                byte[] dex = aesDecrypt(enc, KEY);
                ClassLoader parent = getClassLoader();
                if (Build.VERSION.SDK_INT >= 26) {
                    // API 26+：官方 InMemoryDexClassLoader
                    sLoader = (ClassLoader) Class
                            .forName("dalvik.system.InMemoryDexClassLoader")
                            .getConstructor(java.nio.ByteBuffer.class, ClassLoader.class)
                            .newInstance(java.nio.ByteBuffer.wrap(dex), parent);
                } else {
                    // 低版本兜底：写私有目录再 DexClassLoader（本工程 minSdk=23）
                    java.io.File f = new java.io.File(getDir("dex", 0), "a.dex");
                    java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
                    fo.write(dex);
                    fo.close();
                    sLoader = new dalvik.system.DexClassLoader(
                            f.getAbsolutePath(), getDir("odex", 0).getAbsolutePath(),
                            null, parent);
                }
                // 关键：把「解密 loader」挂进父 loader 的 parent 链，
                // 而不是把它的 dexElements 合并进父 loader ——
                // 后者会让同一个 dex 被两个 ClassLoader 注册，
                // ART 直接抛 InternalError:
                //   "Attempt to register dex file ... with multiple class loaders"
                patchClassLoader(parent, sLoader);
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * 让系统组件（Activity / Provider）也能加载业务类。
     *
     * 方案：把父 loader 的 {@code parent} 指向解密 loader。
     *
     * 追溯顺序变成：
     *   AppClassLoader → (parent) 解密Loader → (parent) BootClassLoader
     * 于是 AppClassLoader 找不到类时会顺着 parent 链落到解密 loader，
     * 业务类就能被解析；而 dex 只被解密 loader 注册了一次，不会冲突。
     *
     * （对比：旧实现是把解密 loader 的 dexElements 追加进 AppClassLoader
     *  的 pathList，导致同一 dex 被两个 loader 注册 → ART InternalError。）
     */
    private static void patchClassLoader(ClassLoader parent, ClassLoader extra) {
        try {
            // 保留原来的祖父 loader，接到解密 loader 后面
            Field pf = ClassLoader.class.getDeclaredField("parent");
            pf.setAccessible(true);
            Object grandParent = pf.get(parent);
            Field ef = ClassLoader.class.getDeclaredField("parent");
            ef.setAccessible(true);
            ef.set(extra, grandParent);
            // 把 AppClassLoader 的 parent 换成解密 loader
            pf.set(parent, extra);
        } catch (Throwable ignored) {
        }
    }

    private static byte[] readAsset(Context c, String name) throws Exception {
        InputStream in = c.getAssets().open(name);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        in.close();
        return bo.toByteArray();
    }

    private static byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }
}