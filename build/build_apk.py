#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostRoot 打包脚本（官方 aapt 路径）
===================================
不再手改二进制 AXML！改为：
  1) 用文本 AndroidManifest.xml + res/ -> aapt package 编译出官方骨架
     (含官方 AndroidManifest.xml + resources.arsc + res/layout/main.xml)
  2) 从已编译好的 classes.dex / lib/* 叠加进去
  3) zipalign -> apksigner

用法: python3 build_apk.py <classes.dex|stub.dex> <lib_dir> <out.apk> [assets/app.dex.enc]
"""
import os, sys, zipfile, subprocess, shutil

QEMU = 'qemu-x86_64-static'
AAPT = '/tmp/btx/android-14/aapt'
ZIPALIGN = '/tmp/btx/android-14/zipalign'
APKSIGNER = '/tmp/btx/android-14/lib/apksigner.jar'
ANDROID_JAR = '/tmp/android34.jar'
KEYSTORE = '/sdcard/工作区/fuxi-ghostroot/build/debug.keystore'

APP = '/sdcard/工作区/fuxi-ghostroot/app'
WORK = '/tmp/grx'


def run(cmd, **kw):
    print('+', ' '.join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.stdout:
        print(r.stdout[-2000:])
    if r.returncode != 0:
        print('STDERR:', r.stderr[-2000:])
        raise SystemExit('FAILED rc=%d' % r.returncode)
    return r


def main():
    dex = sys.argv[1] if len(sys.argv) > 1 else '/tmp/grbuild/dexout/classes.dex'
    libdir = sys.argv[2] if len(sys.argv) > 2 else '/sdcard/工作区/fuxi-ghostroot/app/lib/arm64-v8a'
    out = sys.argv[3] if len(sys.argv) > 3 else '/tmp/grx/GhostRoot.apk'
    payload = sys.argv[4] if len(sys.argv) > 4 else None

    os.makedirs(WORK, exist_ok=True)
    # ---- 1) aapt 编译骨架 ----
    skeleton = os.path.join(WORK, 'skeleton.apk')
    run([QEMU, AAPT, 'package', '-f',
         '-M', os.path.join(APP, 'AndroidManifest.xml'),
         '-S', os.path.join(APP, 'res'),
         '-I', ANDROID_JAR,
         '-F', skeleton])

    # ---- 2) 组装 ----
    raw = os.path.join(WORK, 'raw.apk')
    z = zipfile.ZipFile(skeleton)
    w = zipfile.ZipFile(raw, 'w', zipfile.ZIP_DEFLATED)
    w.writestr('AndroidManifest.xml', z.read('AndroidManifest.xml'))
    # 通用拷贝骨架里的 res/* （layout / drawable 图标等全部带上）
    for name in z.namelist():
        if name.startswith('res/') and not name.endswith('/'):
            w.writestr(name, z.read(name))
    # arsc 必须 STORED（Android 10+ 要求未压缩）
    w.writestr(zipfile.ZipInfo('resources.arsc'), z.read('resources.arsc'), zipfile.ZIP_STORED)
    w.writestr('classes.dex', open(dex, 'rb').read())
    # 加密业务 dex -> assets/app.dex.enc（由 StubApp 运行时解密）
    if payload:
        w.writestr('assets/app.dex.enc', open(payload, 'rb').read())
    # lib/*.so 保持 STORED（与 extractNativeLibs=true 匹配）
    for fn in sorted(os.listdir(libdir)):
        if fn.endswith('.so'):
            w.writestr('lib/arm64-v8a/' + fn, open(os.path.join(libdir, fn), 'rb').read(),
                       zipfile.ZIP_STORED)
    w.close()

    # ---- 3) 对齐 + 签名 ----
    aligned = os.path.join(WORK, 'aligned.apk')
    run([QEMU, ZIPALIGN, '-f', '-p', '4', raw, aligned])
    run([QEMU, ZIPALIGN, '-c', '4', aligned])
    run(['java', '-jar', APKSIGNER, 'sign',
         '--ks', KEYSTORE, '--ks-pass', 'pass:android',
         '--ks-key-alias', 'androiddebugkey', '--key-pass', 'pass:android',
         '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
         '--v3-signing-enabled', 'true', '--out', out, aligned])

    print('\n=== 产出 ===')
    print(out, os.path.getsize(out), 'bytes')


if __name__ == '__main__':
    main()
