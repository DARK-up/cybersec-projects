#!/usr/bin/env python3
"""Fake service banners for NetRecon fingerprinting practice (local only)."""
import socket
import threading

BANNERS = {
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    2121: b"220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n",
    2525: b"220 mail.demo.local ESMTP Postfix (Ubuntu)\r\n",
    6380: b"+PONG\r\n",
    1143: b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n",
}


def serve(port: int, banner: bytes):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(50)
    while True:
        c, _ = s.accept()
        try:
            c.sendall(banner)
            c.settimeout(1.0)
            try:
                c.recv(1024)
            except Exception:
                pass
        finally:
            c.close()


def main():
    threads = []
    for port, banner in BANNERS.items():
        t = threading.Thread(target=serve, args=(port, banner), daemon=True)
        t.start()
        threads.append(t)
        print(f"[demo-lab] fake service on port {port}: {banner[:40]!r}")
    print("[demo-lab] press Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[demo-lab] stopped")


if __name__ == "__main__":
    main()
