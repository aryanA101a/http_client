import socket
import subprocess
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "http_client.c"


class ScriptedHTTPServer:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self._sock.settimeout(5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._thread.join(timeout=5)
        self._sock.close()

    def _serve(self):
        try:
            for response in self._responses:
                try:
                    conn, _ = self._sock.accept()
                except socket.timeout:
                    break
                with conn:
                    conn.settimeout(5)
                    self.requests.append(self._read_request(conn))
                    conn.sendall(response)
        finally:
            self._sock.close()

    @staticmethod
    def _read_request(conn):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)


@pytest.fixture(scope="session")
def http_client_bin(tmp_path_factory):
    out = tmp_path_factory.mktemp("bin") / "http_client"
    subprocess.run(
        ["cc", "-Wall", "-Wextra", "-o", str(out), str(SRC)],
        check=True,
        text=True,
        capture_output=True,
    )
    return out


def run_client(http_client_bin, tmp_path, server, path):
    return subprocess.run(
        [
            str(http_client_bin),
            "-p",
            str(server.port),
            f"http://127.0.0.1{path}",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=5,
    )


def assert_basic_get_request(request, path, port):
    text = request.decode("ascii")
    assert text.startswith(f"GET {path} HTTP/1.1\r\n")
    assert f"Host: 127.0.0.1:{port}\r\n" in text
    assert "User-Agent: aryan-http-client/0.1\r\n" in text
    assert "Accept: */*\r\n" in text


def test_http_get_with_content_length(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Content-Length: 6\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/get")

    # Curl seed: curl/tests/http/test_01_basic.py::TestBasic::test_01_01_http_get
    # and curl/tests/http/test_02_download.py::TestDownload::test_02_01_download_1.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/get", server.port)
    assert (tmp_path / "get").read_bytes() == b"-foo-\n"


def test_chunked_response(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 funky chunky!\r\n"
        b"Server: fakeit/0.9 fakeitbad/1.0\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"4\r\n"
        b"aaaa\r\n"
        b"3\r\n"
        b"bbb\r\n"
        b"5;heresatest=moooo\r\n"
        b"ccccc\r\n"
        b"0\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/chunked")

    # Curl seed: curl/tests/data/test339 sends a chunked HTTP/1.1 response with
    # fake server headers and chunk extensions.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/chunked", server.port)
    assert (tmp_path / "chunked").read_bytes() == b"aaaabbbccccc"


def test_chunked_response_ignores_trailers(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 funky chunky!\r\n"
        b"Server: fakeit/0.9 fakeitbad/1.0\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"4\r\n"
        b"aaaa\r\n"
        b"3\r\n"
        b"bbb\r\n"
        b"0\r\n"
        b"chunky-trailer: header data\r\n"
        b"another-header: yes\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/chunked-trailers")

    # Curl seed: curl/tests/data/test1116 sends chunk trailers after the
    # terminating zero-size chunk.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/chunked-trailers", server.port)
    assert (tmp_path / "chunked-trailers").read_bytes() == b"aaaabbb"


def test_connection_close_body(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"body until close"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/close-body")

    # Curl seed: curl/tests/http/test_05_errors.py::TestErrors::
    # test_05_04_unclean_tls_shutdown covers body end detection by close.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/close-body", server.port)
    assert (tmp_path / "close-body").read_bytes() == b"body until close"


def test_connection_close_body_larger_than_read_buffer(http_client_bin, tmp_path):
    body = b"Z" * 4097
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/large-close-body")

    # Curl seed: curl/tests/data/test559 has a 2049-byte HTTP body to cross
    # an internal read-buffer boundary.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/large-close-body", server.port)
    assert (tmp_path / "large-close-body").read_bytes() == body


def test_duplicate_matching_content_length_is_accepted(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Content-Length: 6\r\n"
        b"Content-Length: 6\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/dup-cl")

    # Curl seed: curl/tests/data/test767 accepts duplicate Content-Length
    # fields when they agree.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/dup-cl", server.port)
    assert (tmp_path / "dup-cl").read_bytes() == b"-foo-\n"


@pytest.mark.xfail(strict=True, reason="conflicting Content-Length is not rejected yet")
def test_conflicting_content_length_is_rejected(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Content-Length: 44\r\n"
        b"Content-Length: 6\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/conflicting-cl")

    # Curl seed: curl/tests/data/test771 rejects response headers with
    # conflicting Content-Length values.
    assert proc.returncode != 0
    assert "http_client: header.invalid_content_length" in proc.stderr
    assert_basic_get_request(server.requests[0], "/conflicting-cl", server.port)


@pytest.mark.xfail(strict=True, reason="comma-list Content-Length is not parsed yet")
def test_equivalent_comma_list_content_length_is_accepted(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Content-Length: 6,06,6\r\n"
        b"Content-Length: 6,    6\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/comma-cl")

    # Curl seed: curl/tests/data/test770 accepts comma-separated
    # Content-Length lists when every member is the same length.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/comma-cl", server.port)
    assert (tmp_path / "comma-cl").read_bytes() == b"-foo-\n"


def test_invalid_content_length_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: -6\r\n"
        b"\r\n"
        b"mooooo"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-cl")

    # Curl seed: curl/tests/data/test178 sends a negative Content-Length.
    assert proc.returncode != 0
    assert "http_client: header.invalid_content_length: -6" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-cl", server.port)


def test_non_numeric_content_length_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: abc\r\n"
        b"\r\n"
        b"mooooo"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-cl-alpha")

    # Curl seed: local diagnostic variant of curl/tests/data/test178's invalid
    # Content-Length coverage.
    assert proc.returncode != 0
    assert "http_client: header.invalid_content_length: abc" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-cl-alpha", server.port)


def test_unsupported_transfer_encoding_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: gzip\r\n"
        b"\r\n"
        b"mooooo"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-te")

    # Curl seed: curl/tests/data/test1170 uses an unsupported gzip transfer
    # coding before chunked.
    assert proc.returncode != 0
    assert "http_client: header.unsupported_transfer_encoding: gzip" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-te", server.port)


def test_combined_transfer_encoding_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked, identity\r\n"
        b"Content-Length: 19\r\n"
        b"\r\n"
        b"stuff server sends"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-te-list")

    # Curl seed: curl/tests/data/test1495 rejects a combined
    # "chunked, identity" Transfer-Encoding value.
    assert proc.returncode != 0
    assert (
        "http_client: header.unsupported_transfer_encoding: chunked, identity"
        in proc.stderr
    )
    assert_basic_get_request(server.requests[0], "/bad-te-list", server.port)


def test_compressed_transfer_encoding_chain_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: gzip, chunked\r\n"
        b"\r\n"
        b"2c\r\n"
        b"compressed bytes would be here\r\n"
        b"0\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-te-chain")

    # Curl seed: curl/tests/data/test1170 exercises a "gzip, chunked"
    # Transfer-Encoding chain.
    assert proc.returncode != 0
    assert (
        "http_client: header.unsupported_transfer_encoding: gzip, chunked"
        in proc.stderr
    )
    assert_basic_get_request(server.requests[0], "/bad-te-chain", server.port)


def test_malformed_header_line_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Broken Header\r\n"
        b"\r\n"
        b"mooooo"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-header")

    # Local diagnostic seed: malformed response header with no colon, added to
    # make the parser's header.malformed branch observable.
    assert proc.returncode != 0
    assert "http_client: header.malformed: Broken Header" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-header", server.port)


@pytest.mark.xfail(strict=True, reason="maximum response header line length is not enforced yet")
def test_too_long_response_header_is_rejected(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 6\r\n"
        b"Connection: close\r\n"
        b"Long: "
        + b"A" * 102400
        + b"\r\n"
        b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/huge-header")

    # Curl seed: curl/tests/data/test1154 rejects a 100K response header.
    assert proc.returncode != 0
    assert "http_client: header.too_large" in proc.stderr
    assert_basic_get_request(server.requests[0], "/huge-header", server.port)


@pytest.mark.xfail(strict=True, reason="maximum response header count is not enforced yet")
def test_too_many_response_headers_are_rejected(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 6\r\n"
        b"Connection: close\r\n"
        + b"Tiny: but many.\r\n" * 5001
        + b"\r\n"
        b"-foo-\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/too-many-headers")

    # Curl seed: curl/tests/data/test747 rejects more than 5000 response
    # header fields.
    assert proc.returncode != 0
    assert "http_client: header.too_many" in proc.stderr
    assert_basic_get_request(server.requests[0], "/too-many-headers", server.port)


def test_invalid_chunk_size_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 funky chunky!\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\n"
        b"a\n\r\n"
        b"ILLEGAL\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-chunk")

    # Curl seed: curl/tests/data/test36 covers bad chunked Transfer-Encoding.
    assert proc.returncode != 0
    assert "http_client: body.invalid_chunk_size" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-chunk", server.port)


@pytest.mark.xfail(strict=True, reason="chunked precedence over Content-Length is not implemented yet")
def test_chunked_takes_precedence_over_content_length(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: test-server/fake\r\n"
        b"Content-Length: 123456\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"10\r\n"
        b"chunked data fun\r\n"
        b"0\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/te-wins")

    # Curl seed: curl/tests/data/test365 expects Transfer-Encoding: chunked
    # to override a conflicting Content-Length.
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert_basic_get_request(server.requests[0], "/te-wins", server.port)
    assert (tmp_path / "te-wins").read_bytes() == b"chunked data fun"


@pytest.mark.xfail(strict=True, reason="premature chunked EOF is not classified as truncated yet")
def test_premature_chunked_close_is_truncated(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 200 funky chunky!\r\n"
        b"Server: fakeit/0.9 fakeitbad/1.0\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"41\r\n"
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/partial-chunk")

    # Curl seed: curl/tests/data/test207 covers chunked Transfer-Encoding
    # closed before the terminating zero-size chunk.
    assert proc.returncode != 0
    assert "http_client: body.truncated" in proc.stderr
    assert_basic_get_request(server.requests[0], "/partial-chunk", server.port)


@pytest.mark.parametrize(
    ("status", "returncode", "stderr"),
    [
        (401, 21, "http_client: response.unsupported: 401 Authorization Required"),
        (404, 51, "http_client: client.error"),
        (502, 50, "http_client: server.error"),
    ],
)
def test_status_code_error_is_observable(
    http_client_bin, tmp_path, status, returncode, stderr
):
    response = (
        f"HTTP/1.1 {status} Test Status\r\n".encode("ascii")
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )
    path = f"/status-{status}"

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, path)

    # Curl seed: curl/tests/http/test_02_download.py::TestDownload::
    # test_02_14_not_found plus curl/tests/http/test_05_errors.py retry tests
    # for 401 and 502 status handling.
    assert proc.returncode == returncode
    assert stderr in proc.stderr
    assert_basic_get_request(server.requests[0], path, server.port)


def test_http_1_0_status_code_error_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.0 401 BAD BOY\r\n"
        b"Server: swsclose\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"This contains a response code >= 400."
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/http10-401")

    # Curl seed: curl/tests/data/test151 uses HTTP/1.0 with a 401 status.
    assert proc.returncode != 0
    assert "http_client: response.unsupported: 401 Authorization Required" in proc.stderr
    assert_basic_get_request(server.requests[0], "/http10-401", server.port)


def test_status_code_error_body_is_not_written(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 404 Nah\r\n"
        b"Connection: close\r\n"
        b"Content-Length: 13\r\n"
        b"Funny-head: yesyes\r\n"
        b"\r\n"
        b"0123456789123"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/status-body")

    # Curl seed: curl/tests/data/test99 has a 404 response with a body; this
    # client classifies the response before copying the body.
    assert proc.returncode == 51
    assert "http_client: client.error" in proc.stderr
    assert_basic_get_request(server.requests[0], "/status-body", server.port)
    assert not (tmp_path / "status-body").exists()


def test_invalid_status_line_is_observable(http_client_bin, tmp_path):
    response = (
        b"No headers at all, only data swsclose\r\n"
        b"\r\n"
        b"Let's get a little test data"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/bad-status-line")

    # Curl seed: curl/tests/data/test1144 sends body-like bytes where an HTTP
    # status line should be.
    assert proc.returncode != 0
    assert "http_client: status.invalid_line" in proc.stderr
    assert_basic_get_request(server.requests[0], "/bad-status-line", server.port)


def test_redirect_status_without_location_is_observable(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 307 Temporary Redirect\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/redirect-no-location")

    # Curl seed: curl/tests/data/test3034 uses a 307 redirect status; this
    # local variant pins the no-Location diagnostic path.
    assert proc.returncode != 0
    assert "http_client: response.unsupported: redirect without Location" in proc.stderr
    assert_basic_get_request(server.requests[0], "/redirect-no-location", server.port)


def test_redirect_location_is_followed(http_client_bin, tmp_path):
    redirect = (
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Location: /final\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    final = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
        b"final body"
    )

    with ScriptedHTTPServer([redirect, final]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/redirect")

    # Curl seed: curl/tests/data/test1942 and curl/tests/data/test1973 follow a
    # relative Location header.
    assert proc.returncode == 0, proc.stderr
    assert len(server.requests) == 2
    assert_basic_get_request(server.requests[0], "/redirect", server.port)
    assert_basic_get_request(server.requests[1], "/final", server.port)
    assert (tmp_path / "final").read_bytes() == b"final body"


def test_redirect_location_with_extra_spaces_is_followed(http_client_bin, tmp_path):
    redirect = (
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Location:  /spaced/final?logout=TRUE\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    final = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"space final"
    )

    with ScriptedHTTPServer([redirect, final]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/want/redirect")

    # Curl seed: curl/tests/data/test28 follows a Location header whose value
    # has extra leading spaces.
    assert proc.returncode == 0, proc.stderr
    assert len(server.requests) == 2
    assert_basic_get_request(server.requests[0], "/want/redirect", server.port)
    assert_basic_get_request(server.requests[1], "/spaced/final?logout=TRUE", server.port)
    assert (tmp_path / "final?logout=TRUE").read_bytes() == b"space final"


@pytest.mark.xfail(strict=True, reason="relative redirect following is not implemented yet")
def test_relative_redirect_location_is_followed(http_client_bin, tmp_path):
    redirect = (
        b"HTTP/1.1 302 OK\r\n"
        b"Location: ./final\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    final = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 13\r\n"
        b"\r\n"
        b"relative body"
    )

    with ScriptedHTTPServer([redirect, final]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/dir/redirect")

    # Curl seed: curl/tests/data/test52 follows a Location with a ./-prefixed
    # relative target from the current request path.
    assert proc.returncode == 0, proc.stderr
    assert len(server.requests) == 2
    assert_basic_get_request(server.requests[0], "/dir/redirect", server.port)
    assert_basic_get_request(server.requests[1], "/dir/final", server.port)
    assert (tmp_path / "redirect").read_bytes() == b"relative body"


@pytest.mark.xfail(strict=True, reason="relative redirect without a leading slash is not implemented yet")
def test_bare_relative_redirect_location_is_followed(http_client_bin, tmp_path):
    redirect = (
        b"HTTP/1.1 302 OK\r\n"
        b"Location: final\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    final = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
        b"bare final"
    )

    with ScriptedHTTPServer([redirect, final]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/dir/base")

    # Curl seed: curl/tests/data/test55 follows a relative Location value
    # with no leading slash.
    assert proc.returncode == 0, proc.stderr
    assert len(server.requests) == 2
    assert_basic_get_request(server.requests[0], "/dir/base", server.port)
    assert_basic_get_request(server.requests[1], "/dir/final", server.port)
    assert (tmp_path / "base").read_bytes() == b"bare final"


@pytest.mark.xfail(strict=True, reason="dot-dot redirect normalization is not implemented yet")
def test_dotdot_relative_redirect_location_is_followed(http_client_bin, tmp_path):
    redirect = (
        b"HTTP/1.1 301 OK\r\n"
        b"Content-Length: 6\r\n"
        b"Location: ../final\r\n"
        b"\r\n"
        b"-foo-\n"
    )
    final = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"dotdot body"
    )

    with ScriptedHTTPServer([redirect, final]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/dir/base")

    # Curl seed: curl/tests/data/test391 follows a ../ relative Location.
    assert proc.returncode == 0, proc.stderr
    assert len(server.requests) == 2
    assert_basic_get_request(server.requests[0], "/dir/base", server.port)
    assert_basic_get_request(server.requests[1], "/final", server.port)
    assert (tmp_path / "base").read_bytes() == b"dotdot body"


def test_1xx_response_then_final_response(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 100 Continue\r\n"
        b"\r\n"
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 7\r\n"
        b"\r\n"
        b"final!\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/continue")

    # Curl seed: curl/tests/data/test246, test1002, and test2059 send a 100
    # Continue response before the final response.
    assert proc.returncode == 0, proc.stderr
    assert_basic_get_request(server.requests[0], "/continue", server.port)
    assert (tmp_path / "continue").read_bytes() == b"final!\n"


def test_1xx_response_then_status_error(http_client_bin, tmp_path):
    response = (
        b"HTTP/1.1 100 Continue\r\n"
        b"Server: Microsoft-IIS/5.0\r\n"
        b"\r\n"
        b"HTTP/1.1 401 authentication please\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )

    with ScriptedHTTPServer([response]) as server:
        proc = run_client(http_client_bin, tmp_path, server, "/continue-then-401")

    # Curl seed: curl/tests/data/test1002 sends a 100 Continue response before
    # the final 401 response.
    assert proc.returncode != 0
    assert "http_client: response.unsupported: 401 Authorization Required" in proc.stderr
    assert_basic_get_request(server.requests[0], "/continue-then-401", server.port)
