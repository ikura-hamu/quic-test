#!/usr/bin/env python3
"""Correlate a UDP return-path check with the server's receive log."""
import argparse
import secrets
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=4433)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    nonce = secrets.token_hex(16)
    packet = f"QUIC-PROBE/1 {nonce}".encode("ascii")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(4)
            udp.connect((args.host, args.port))
            print(f"[INFO] UDP probe peer={udp.getpeername()} nonce={nonce}", flush=True)
            udp.send(packet)
            if udp.recv(256) != packet:
                raise ValueError("unexpected UDP reply")
    except (OSError, ValueError) as error:
        print(f"[FAIL] UDP reply missing or invalid ({error})")
        print(f"[INFO] Search the server logs for nonce={nonce}")
        return 1
    print("[PASS] UDP packet received and echoed from the expected address and port")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
