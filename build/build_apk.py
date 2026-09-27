#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostRoot APK 打包脚本
======================

不使用 Gradle / aapt2。流程：
  1) 用文本 AndroidManifest.xml + res/ -> aapt package 编译出官方骨架
     （产出官方 AndroidManifest.xml + resources.arsc + res/layout/main.xml）
  2) 叠加已编译好的 classes.dex 和 lib/*.so
  3) zipalign -> apksigner

关键点（踩过的坑）：
  * 绝对不要手写 Python 拼二进制 AXML —— PackageParser 会拒绝
  * resources.arsc 必须用 STORED（不压缩），Android 10+ 的硬要求
  * aapt / zipalign 是 x86_64 的，需用 qemu-x86_64-static 包一层

用法:
    python3 build_apk.py <classes.dex> <lib目录> <输出.apk>

示例:
    python3 build_apk.py dexout/classes.dex lib/arm64-v8a GhostRoot.apk
"""

import os
import sys
import zipfile
import subprocess

# ---- 按需修改这些路径 ----
QEMU      = 'qemu-x86_64-static'          # x86_64 工具需 qemu 包一层；本机原生则设为 ''
AAPT      = 'aapt'
ZIPALIGN  = 'zipalign'
APKSIGNER = 'apksigner.jar'
ANDROID_JAR = 'android34.jar'             # API 34
KEYSTORE  = 'build/debug.keystore'

APP_DIR = 'app'                           # 含 AndroidManifest.xml 和 res/
WORK    = '/tmp/grx'                      # 临时目录


def run(cmd):
    print('+', ' '.join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout:
        print(r.stdout[-2000:])
    if r.returncode != 0:
        print('STDERR:', r.stderr[-2000:])
        raise SystemExit('FAILED rc=%d' % r.returncode)
    return r


def main():
    dex = sys.argv[1] if len(sys.argv) > 1 else '/tmp/grbuild/dexout/classes.dex'
    libdir = sys.argv[2] if len(sys.argv) > 2 else 'lib/arm64-v8a'
    out = sys.argv[3] if len(sys.argv) > 3 else 'GhostRoot.apk'

    os.makedirs(WORK, exist_ok=True)

    def q(binary):
        """x86_64 二进制用 qemu 包一层，否则 SIGILL。"""
        return [QEMU, binary] if QEMU else [binary]

    # ---- 1) aapt 编译骨架（官方 Manifest + arsc + layout）----
    skeleton = os.path.join(WORK, 'skeleton.apk')
    run(q(AAPT) + ['package', '-f',
                   '-M', os.path.join(APP_DIR, 'AndroidManifest.xml'),
                   '-S', os.path.join(APP_DIR, 'res'),
                   '-I', ANDROID_JAR,
                   '-F', skeleton])

    # ---- 2) 组装 ----
    raw = os.path.join(WORK, 'raw.apk')
    z = zipfile.ZipFile(skeleton)
    w = zipfile.ZipFile(raw, 'w', zipfile.ZIP_DEFLATED)

    w.writestr('AndroidManifest.xml', z.read('AndroidManifest.xml'))
    w.writestr('res/layout/main.xml', z.read('res/layout/main.xml'))

    # arsc 必须 STORED（不压缩）—— Android 10+ 硬要求
    w.writestr(zipfile.ZipInfo('resources.arsc'),
               z.read('resources.arsc'), zipfile.ZIP_STORED)

    w.writestr('classes.dex', open(dex, 'rb').read())

    # native lib 保持 STORED（与 extractNativeLibs=true 匹配）
    if os.path.isdir(libdir):
        for fn in sorted(os.listdir(libdir)):
            if fn.endswith('.so'):
                w.writestr('lib/arm64-v8a/' + fn,
                           open(os.path.join(libdir, fn), 'rb').read(),
                           zipfile.ZIP_STORED)
    w.close()

    # ---- 3) 对齐 + 签名 ----
    aligned = os.path.join(WORK, 'aligned.apk')
    run(q(ZIPALIGN) + ['-f', '-p', '4', raw, aligned])
    run(q(ZIPALIGN) + ['-c', '4', aligned])

    run(['java', '-jar', APKSIGNER, 'sign',
         '--ks', KEYSTORE, '--ks-pass', 'pass:android',
         '--ks-key-alias', 'androiddebugkey', '--key-pass', 'pass:android',
         '--v1-signing-enabled', 'true',
         '--v2-signing-enabled', 'true',
         '--v3-signing-enabled', 'true',
         '--out', out, aligned])

    print('\n=== 产出 ===')
    print(out, os.path.getsize(out), 'bytes')
    print('\n验证:')
    print('  aapt dump badging', out)
    print('  java -jar apksigner.jar verify', out)


if __name__ == '__main__':
    main()