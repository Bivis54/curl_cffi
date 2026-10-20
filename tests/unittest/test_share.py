"""CurlShare: a TLS session cache that curl handles keep in common."""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import ssl
import threading
from io import BytesIO

import pytest

from curl_cffi import (
    Curl,
    CurlError,
    CurlInfo,
    CurlLockData,
    CurlOpt,
    CurlShare,
    CurlShECode,
    CurlShOpt,
    Session,
    WebSocket,
)

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# IPv4 only: the server listens on 127.0.0.1, "localhost" is kept for SNI.
OPTS = {CurlOpt.IPRESOLVE: 1}


class ResumeServer:
    """TLS server recording whether each connection resumed a session; answers
    GET with 200 and a WebSocket upgrade with 101."""

    def __init__(self, certfile: str, keyfile: str, tls12: bool = False):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile, keyfile)
        if tls12:
            self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.resumed: list[bool] = []
        self.lock = threading.Lock()
        self.done = threading.Condition(self.lock)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        port = self.sock.getsockname()[1]
        self.https = f"https://localhost:{port}/"
        self.wss = f"wss://localhost:{port}/ws"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        conn.settimeout(10)
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
            with self.done:
                self.resumed.append(tls.session_reused)
                self.done.notify_all()
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                head += chunk
            key = re.search(rb"(?im)^sec-websocket-key:\s*(\S+)", head)
            if key:
                accept = base64.b64encode(hashlib.sha1(key.group(1) + WS_GUID).digest())
                tls.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    b"Connection: Upgrade\r\nSec-WebSocket-Accept: "
                    + accept
                    + b"\r\n\r\n"
                )
                while tls.recv(4096):
                    pass
            else:
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: close\r\n\r\nok"
                )
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def wait(self, count: int) -> list[bool]:
        with self.done:
            self.done.wait_for(lambda: len(self.resumed) >= count, timeout=10)
            return list(self.resumed)

    def close(self):
        self.sock.close()


@pytest.fixture
def tls_server(cert_pem_file, cert_private_key_file):
    server = ResumeServer(cert_pem_file, cert_private_key_file)
    yield server
    server.close()


@pytest.fixture
def tls12_server(cert_pem_file, cert_private_key_file):
    server = ResumeServer(cert_pem_file, cert_private_key_file, tls12=True)
    yield server
    server.close()


def get(url: str, ca: str, share: CurlShare | None) -> None:
    with Session(share=share, verify=ca, impersonate="chrome", curl_options=OPTS) as s:
        assert s.get(url, timeout=10).status_code == 200


def ws(url: str, ca: str, share: CurlShare | None) -> None:
    sock = WebSocket(share=share)
    sock.connect(url, verify=ca, impersonate="chrome", timeout=10, curl_options=OPTS)
    sock.terminate()


def test_share_close_and_context_manager():
    share = CurlShare()
    assert not share.closed
    share.close()
    assert share.closed
    share.close()  # a no-op
    with CurlShare([CurlLockData.SSL_SESSION, CurlLockData.DNS]) as share:
        share.setopt(CurlShOpt.UNSHARE, CurlLockData.DNS)
    assert share.closed


def test_share_bad_options():
    with CurlShare() as share:
        with pytest.raises(NotImplementedError):
            share.setopt(CurlShOpt.LOCKFUNC, 0)
        with pytest.raises(CurlError) as e:
            share.setopt(CurlShOpt.SHARE, 99)
        assert e.value.code == CurlShECode.BAD_OPTION


def test_share_in_use_until_handle_closed():
    share = CurlShare()
    c = Curl()
    c.setopt(CurlOpt.SHARE, share)
    c.reset()  # curl keeps the share across curl_easy_reset()
    with pytest.raises(CurlError) as e:
        share.close()
    assert e.value.code == CurlShECode.IN_USE
    assert not share.closed
    c.close()
    share.close()
    assert share.closed


def test_curl_setopt_share_none_detaches():
    share = CurlShare()
    c = Curl()
    c.setopt(CurlOpt.SHARE, share)
    c.setopt(CurlOpt.SHARE, None)
    share.close()
    c.close()


def test_curl_setopt_share_type():
    c = Curl()
    with pytest.raises(TypeError):
        c.setopt(CurlOpt.SHARE, "share")
    share = CurlShare()
    share.close()
    with pytest.raises(CurlError):
        c.setopt(CurlOpt.SHARE, share)
    c.close()


def test_sessions_resume_through_share(tls_server, ca_cert_pem_file):
    with CurlShare() as share:
        get(tls_server.https, ca_cert_pem_file, share)
        get(tls_server.https, ca_cert_pem_file, share)
    assert tls_server.wait(2) == [False, True]


def test_no_share_no_resumption(tls_server, ca_cert_pem_file):
    get(tls_server.https, ca_cert_pem_file, None)
    get(tls_server.https, ca_cert_pem_file, None)
    assert tls_server.wait(2) == [False, False]


def test_websocket_reconnect_resumes(tls_server, ca_cert_pem_file):
    with CurlShare() as share:
        ws(tls_server.wss, ca_cert_pem_file, share)
        ws(tls_server.wss, ca_cert_pem_file, share)
    assert tls_server.wait(2) == [False, True]


def test_websocket_reconnect_resumes_tls12(tls12_server, ca_cert_pem_file):
    with CurlShare() as share:
        ws(tls12_server.wss, ca_cert_pem_file, share)
        ws(tls12_server.wss, ca_cert_pem_file, share)
    assert tls12_server.wait(2) == [False, True]


def test_websocket_connect_share_argument(tls_server, ca_cert_pem_file):
    with CurlShare() as share:
        get(tls_server.https, ca_cert_pem_file, share)
        sock = WebSocket()
        sock.connect(
            tls_server.wss,
            verify=ca_cert_pem_file,
            impersonate="chrome",
            timeout=10,
            curl_options=OPTS,
            share=share,
        )
        sock.terminate()
    assert tls_server.wait(2) == [False, True]


def test_session_ws_connect_uses_share(tls_server, ca_cert_pem_file):
    with (
        CurlShare() as share,
        Session(
            share=share,
            verify=ca_cert_pem_file,
            impersonate="chrome",
            curl_options=OPTS,
        ) as s,
    ):
        assert s.get(tls_server.https, timeout=10).status_code == 200
        s.ws_connect(tls_server.wss, timeout=10).terminate()
    assert tls_server.wait(2) == [False, True]


def test_separate_shares_keep_sessions_apart(tls_server, ca_cert_pem_file):
    with CurlShare() as a, CurlShare() as b:
        get(tls_server.https, ca_cert_pem_file, a)
        get(tls_server.https, ca_cert_pem_file, b)
    assert tls_server.wait(2) == [False, False]


def test_share_across_threads(tls_server, ca_cert_pem_file):
    share = CurlShare()
    codes: list[int] = []
    errors: list[BaseException] = []

    def worker():
        c = Curl()
        try:
            for _ in range(10):
                c.reset()
                c.impersonate("chrome")
                c.setopt(CurlOpt.URL, tls_server.https)
                c.setopt(CurlOpt.CAINFO, ca_cert_pem_file)
                c.setopt(CurlOpt.FORBID_REUSE, 1)
                c.setopt(CurlOpt.IPRESOLVE, 1)
                c.setopt(CurlOpt.SHARE, share)
                c.setopt(CurlOpt.WRITEDATA, BytesIO())
                c.perform()
                codes.append(int(c.getinfo(CurlInfo.RESPONSE_CODE)))
        except BaseException as e:
            errors.append(e)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    share.close()
    assert not errors
    assert codes == [200] * 40
    assert any(tls_server.wait(40))
