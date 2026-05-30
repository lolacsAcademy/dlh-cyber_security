#!/usr/bin/env python3
import socket


def check_port(host, port):
    """Checks if a specific port is open on a host."""
    try:
        sock = socket.socket()
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


if __name__ == "__main__":
    pass
