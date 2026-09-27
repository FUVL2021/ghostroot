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

            /* feed the base64 stream in big chunks -- a pipe has no line limit */
            java.util.Base64.Encoder enc = java.util.Base64.getEncoder();
            final int CHUNK = 64 * 1024;
            int batch = 0;
            long deadline = System.currentTimeMillis() + 600000L;
            for (int off = 0; off < data.length; off += CHUNK) {
                if (System.currentTimeMillis() > deadline) {
                    v("[-] timeout at " + off + "/" + data.length);
                    return null;
                }
                int end = Math.min(off + CHUNK, data.length);
                /* base64 of a whole chunk, no trailing newline handling needed:
                 * base64 -d ignores whitespace, so emit one long stream. */
                String b64 = enc.encodeToString(
                        java.util.Arrays.copyOfRange(data, off, end));
                writeAll(sout, packPacket(CMD_WRTE, localId, remoteId,
                        b64.getBytes("UTF-8")));
                batch++;
                /* drain whatever adbd pushed back (ACKs / shell output) */
                drain(sin, sout, localId, remoteId, sink);
                if (batch % 4 == 0) {
                    v("[*] raw fed " + end + "/" + data.length);
                }
            }
            v("[*] raw fed " + data.length + "/" + data.length);

            /* terminate the base64 stream and ask the shell to materialise it */
            /* close stdin so base64 -d sees EOF and writes the file out */
            writeAll(sout, packPacket(CMD_CLSE, localId, remoteId, null));

            /* collect the shell tail output (ls + SZSIZE + GHDONE) */
            long t2 = System.currentTimeMillis() + 120000L;
            while (System.currentTimeMillis() < t2) {
                Pkt p = readPacket(sin);
                if (p.cmd == CMD_WRTE) {
                    sink.append(new String(p.payload, "UTF-8"));
                    writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
                } else if (p.cmd == CMD_OKAY) {
                    continue;
                } else if (p.cmd == CMD_CLSE) {
                    break;
                } else {
                    break;
                }
                if (sink.indexOf("GHDONE") >= 0) {
                    break;
                }
            }

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
