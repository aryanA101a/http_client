import os
import socket
import ssl
import subprocess
import threading


class ScriptedHTTPServer:
    def __init__(self, responses, tls_context=None):
        self._responses = [
            [response] if isinstance(response, bytes) else list(response)
            for response in responses
        ]
        self._tls_context = tls_context
        self.requests = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._sock.settimeout(5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._thread.join(timeout=6)
        self._sock.close()

    def _serve(self):
        try:
            for response in self._responses:
                try:
                    conn, _ = self._sock.accept()
                except socket.timeout:
                    break

                conn.settimeout(5)
                try:
                    if self._tls_context is not None:
                        conn = self._tls_context.wrap_socket(
                            conn, server_side=True
                        )
                    with conn:
                        self.requests.append(read_request(conn))
                        for chunk in response:
                            conn.sendall(chunk)
                except (ConnectionError, OSError, ssl.SSLError):
                    conn.close()
        finally:
            self._sock.close()


class ClosingTCPServer:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._sock.settimeout(5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._thread.join(timeout=6)
        self._sock.close()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            conn.close()
        except (OSError, socket.timeout):
            pass
        finally:
            self._sock.close()


def create_tls_server_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context


def read_request(conn):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def run_client(binary, tmp_path, url):
    if os.environ.get("HTTP_CLIENT_LLDB"):
        breakpoint_name = os.environ.get("HTTP_CLIENT_LLDB_BREAK", "main")
        args = [
            "lldb",
            "--one-line",
            f"breakpoint set --name {breakpoint_name}",
            "--one-line",
            "run",
            "--",
            str(binary),
            url,
        ]
        proc = subprocess.run(args, cwd=tmp_path, text=True)
        return subprocess.CompletedProcess(args, proc.returncode, "", "")

    return subprocess.run(
        [str(binary), url],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=5,
    )


def assert_basic_get_request(request, path, port, hostname="127.0.0.1"):
    text = request.decode("ascii")
    assert text.startswith(f"GET {path} HTTP/1.1\r\n")
    assert f"Host: {hostname}:{port}\r\n" in text
    assert "User-Agent: aryan-http-client/0.1\r\n" in text
    assert "Accept: */*\r\n" in text
    assert "Accept-Encoding: identity\r\n" in text
    assert "Connection: close\r\n" in text
