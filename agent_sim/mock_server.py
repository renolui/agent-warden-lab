#!/usr/bin/env python3
import socket
import sys
import time

def run_server(port=8888, timeout=15):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    sock.settimeout(timeout)
    print(f"[*] Mock Exfiltration Listener started on 127.0.0.1:{port} (Watchdog timeout: {timeout}s)")
    sys.stdout.flush()

    try:
        conn, addr = sock.accept()
        print(f"[+] Received exfiltration connection from {addr}")
        data = conn.recv(1024)
        print(f"[+] Exfiltrated data payload: {data.decode('utf-8', errors='ignore').strip()}")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        conn.close()
    except socket.timeout:
        print("[*] Listener timed out (Watchdog triggered). Exiting cleanly.")
    except Exception as e:
        print(f"[-] Listener error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    run_server(port)

