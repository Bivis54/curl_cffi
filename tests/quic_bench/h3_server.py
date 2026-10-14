"""Local HTTP/3 test server (aioquic) for offline QUIC tests.

Answers every request with JSON describing the connection: whether the TLS
session was resumed, whether the request arrived as 0-RTT early data, and the
request headers. Session tickets are kept in memory so clients can resume;
--reject-early-data forgets them, so a client offering 0-RTT gets a full
handshake and has to send its request again.

usage: h3_server.py PORT [--log FILE] [--reject-early-data]
       [--cert FILE --key FILE]   (a self-signed localhost cert by default)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import tempfile
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent
from aioquic.tls import SessionTicket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def self_signed(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class TicketStore:
    def __init__(self, reject: bool) -> None:
        self.tickets: dict[bytes, SessionTicket] = {}
        self.reject = reject

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> SessionTicket | None:
        ticket = self.tickets.pop(label, None)
        return None if self.reject else ticket


class Handler(QuicConnectionProtocol):
    log_path: str | None = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                self.respond(ev)

    def respond(self, ev: HeadersReceived) -> None:
        tls = self._quic.tls
        info = {
            "resumed": bool(tls.session_resumed),
            "early_data": bool(
                tls.early_data_accepted and not self._quic._handshake_complete
            ),
            "stream_id": ev.stream_id,
            "headers": [(k.decode(), v.decode()) for k, v in ev.headers],
        }
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(info) + "\n")
        body = json.dumps(info).encode()
        assert self._http is not None
        self._http.send_headers(
            ev.stream_id,
            [
                (b":status", b"200"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        )
        self._http.send_data(ev.stream_id, body, end_stream=True)
        self.transmit()


async def run(args: argparse.Namespace) -> None:
    if args.cert:
        cert, key = Path(args.cert), Path(args.key)
    else:
        cert, key = self_signed(Path(tempfile.mkdtemp()))
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(cert, key)
    store = TicketStore(args.reject_early_data)
    Handler.log_path = args.log
    await serve(
        "127.0.0.1",
        args.port,
        configuration=config,
        create_protocol=Handler,
        session_ticket_fetcher=store.pop,
        session_ticket_handler=store.add,
    )
    print(f"listening on 127.0.0.1:{args.port} cert={cert}", flush=True)
    await asyncio.Future()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--log", default=None)
    parser.add_argument("--reject-early-data", action="store_true")
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
