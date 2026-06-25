import shutil
import subprocess
from pathlib import Path

import pytest

from http_test_support import (
    ClosingTCPServer,
    ScriptedHTTPServer,
    StalledTCPServer,
    assert_basic_get_request,
    create_tls_server_context,
    run_client,
)

@pytest.fixture(scope="session")
def freebsd_src():
    result = subprocess.run(
        ["bmake", "-V", "${FREEBSD_SRC}"],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        text=True,
        capture_output=True,
    )
    return Path(result.stdout.strip())


@pytest.fixture(scope="session")
def tls_material(tmp_path_factory, freebsd_src):
    cert_dir = tmp_path_factory.mktemp("tls-certs")
    roots_dir = cert_dir / "roots"
    roots_dir.mkdir()

    source_dir = freebsd_src / "crypto/openssl/demos/guide"
    source_ca = source_dir / "rootcert.pem"
    server_cert = source_dir / "servercert.pem"
    server_key = source_dir / "serverkey.pem"

    for path in (source_ca, server_cert, server_key):
        if not path.is_file():
            pytest.fail(f"missing FreeBSD TLS test fixture: {path}")

    ca_cert = roots_dir / "ca.pem"
    shutil.copyfile(source_ca, ca_cert)

    return {
        "roots": roots_dir,
        "cert": server_cert,
        "key": server_key,
    }


@pytest.fixture(scope="session")
def tls_client_bin(tmp_path_factory, tls_material):
    objdir = tmp_path_factory.mktemp("tls-build")
    subprocess.run(
        [
            "bmake",
            "-B",
            f"OBJDIR={objdir}",
            f"CAROOT_DIR={tls_material['roots']}",
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        text=True,
        capture_output=True,
    )
    return objdir / "http_client"


def test_https_get(tls_client_bin, tls_material, tmp_path):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure"
    context = create_tls_server_context(
        tls_material["cert"], tls_material["key"]
    )

    with ScriptedHTTPServer([response], tls_context=context) as server:
        proc = run_client(
            tls_client_bin,
            tmp_path,
            f"https://localhost:{server.port}/secure",
        )

    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "secure").read_bytes() == b"secure"
    assert_basic_get_request(
        server.requests[0], "/secure", server.port, hostname="localhost"
    )


def test_https_rejects_hostname_mismatch(
    tls_client_bin, tls_material, tmp_path
):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure"
    context = create_tls_server_context(
        tls_material["cert"], tls_material["key"]
    )

    with ScriptedHTTPServer([response], tls_context=context) as server:
        proc = run_client(
            tls_client_bin,
            tmp_path,
            f"https://127.0.0.1:{server.port}/mismatch",
        )

    assert proc.returncode != 0
    assert not (tmp_path / "mismatch").exists()


def test_https_fragmented_response(
    tls_client_bin, tls_material, tmp_path
):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfragmented"
    fragments = [response[i : i + 1] for i in range(len(response))]
    context = create_tls_server_context(
        tls_material["cert"], tls_material["key"]
    )

    with ScriptedHTTPServer([fragments], tls_context=context) as server:
        proc = run_client(
            tls_client_bin,
            tmp_path,
            f"https://localhost:{server.port}/fragmented",
        )

    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "fragmented").read_bytes() == b"fragmented"


def test_https_handshake_close_is_observable(tls_client_bin, tmp_path):
    with ClosingTCPServer() as server:
        proc = run_client(
            tls_client_bin,
            tmp_path,
            f"https://localhost:{server.port}/closed",
        )

    assert proc.returncode != 0
    assert not (tmp_path / "closed").exists()


def test_https_handshake_stall_times_out(tls_client_bin, tmp_path):
    with StalledTCPServer() as server:
        proc = run_client(
            tls_client_bin,
            tmp_path,
            f"https://localhost:{server.port}/stall",
            timeout=20,
        )

    assert proc.returncode != 0
    assert "http_client: io: sending request" in proc.stderr
    assert not (tmp_path / "stall").exists()


def test_http_redirect_to_https(
    tls_client_bin, tls_material, tmp_path
):
    final = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal"
    context = create_tls_server_context(
        tls_material["cert"], tls_material["key"]
    )

    with ScriptedHTTPServer([final], tls_context=context) as tls_server:
        redirect = (
            "HTTP/1.1 302 Found\r\n"
            f"Location: https://localhost:{tls_server.port}/final\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode("ascii")
        with ScriptedHTTPServer([redirect]) as http_server:
            proc = run_client(
                tls_client_bin,
                tmp_path,
                f"http://127.0.0.1:{http_server.port}/redirect",
            )

    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "final").read_bytes() == b"final"
    assert_basic_get_request(
        tls_server.requests[0],
        "/final",
        tls_server.port,
        hostname="localhost",
    )
