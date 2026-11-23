"""Cross-platform checks for the PythonTlsServer SMTP stub. Not for upstream."""

import platform
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.python_tls_server import PythonTlsServer


def talk(commands: list[bytes]) -> list[bytes]:
    with PythonTlsServer(should_do_smtp_starttls=True) as server:
        client = socket.create_connection((server.ip_address, server.port), timeout=3)
        reader = client.makefile("rb")
        replies = [reader.readline()]
        for command in commands:
            client.sendall(command)
            while True:
                line = reader.readline()
                replies.append(line)
                if not line or line[3:4] != b"-":
                    break
        try:
            tail = client.recv(100)
            replies.append(b"after: " + (tail or b"<closed>"))
        except TimeoutError:
            replies.append(b"after: <still open>")
        except ConnectionResetError:
            replies.append(b"after: <reset>")
        client.close()
        return replies


EXPECTED_LAST = {
    "happy": (b"220 2.0.0", b"after: <still open>"),
    "no EHLO": (b"503 ", None),
    "MAIL instead of STARTTLS": (b"530 ", None),
}
failures = 0
for name, commands in [
    ("happy", [b"EHLO x\r\n", b"STARTTLS\r\n"]),
    ("no EHLO", [b"HELO x\r\n"]),
    ("MAIL instead of STARTTLS", [b"EHLO x\r\n", b"MAIL FROM:<a@b>\r\n"]),
]:
    replies = talk(commands)
    reply_prefix, after = EXPECTED_LAST[name]
    ok = replies[-2].startswith(reply_prefix) and (after is None or replies[-1] == after)
    if after is None:
        ok = ok and replies[-1] in (b"after: <closed>", b"after: <reset>")
    failures += not ok
    print(f"{'OK  ' if ok else 'FAIL'} {name}: {replies}")

start = time.monotonic()
with PythonTlsServer():
    pass
print(f"INFO {platform.system()}: empty PythonTlsServer lifecycle took {time.monotonic() - start:.2f}s")

listening_socket = socket.create_server(("127.0.0.1", 0))
try:
    listening_socket.shutdown(socket.SHUT_RDWR)
    print(f"INFO {platform.system()}: shutdown() on a listening socket succeeded")
except OSError as e:
    print(f"INFO {platform.system()}: shutdown() on a listening socket raised {e!r}")
finally:
    listening_socket.close()

sys.exit(1 if failures else 0)
