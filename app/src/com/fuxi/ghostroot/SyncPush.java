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
            if (!syncWrite(sin, sout, localId, remoteId, h.toByteArray())) {
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
    private boolean syncWrite(InputStream sin, OutputStream sout, int localId,
                              int remoteId, byte[] req) throws IOException {
        writeAll(sout, packPacket(CMD_WRTE, localId, remoteId, req));
        for (int i = 0; i < 32; i++) {
            Pkt p = readPacket(sin);
            if (p.cmd == CMD_OKAY) {
                return true;
            } else if (p.cmd == CMD_WRTE) {
                /* adbd may speak first (e.g. FAIL); surface it */
                String m = new String(p.payload, "UTF-8");
                v("[*] sync says: " + m.replace("\n", " "));
                writeAll(sout, packPacket(CMD_OKAY, localId, remoteId, null));
                if (m.startsWith("FAIL")) {
                    return false;
                }
            } else if (p.cmd == CMD_CLSE) {
                return false;
            }
        }
        return false;
    }
