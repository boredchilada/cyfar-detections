"""Generate minimal pcaps from YAML fixture specs for Suricata rule testing.

HTTP fixtures receive a complete TCP/HTTP exchange. Raw TCP fixtures provide a
server banner, client payload, and server response so non-HTTP protocols can be
tested without disguising their bytes as HTTP.
"""

import os

from scapy.all import IP, TCP, Raw, wrpcap


def build_http_request(spec):
    """Turn a fixture request spec into a raw HTTP/1.1 request string."""
    method = spec["method"]
    uri = spec["uri"]
    host = spec.get("host", "target.example.com")
    headers = spec.get("headers", {})
    body = spec.get("body", "")

    lines = [f"{method} {uri} HTTP/1.1"]
    lines.append(f"Host: {host}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        body_bytes = body.encode("utf-8")
        lines.append(f"Content-Length: {len(body_bytes)}")
    else:
        body_bytes = b""
    lines.append("")  # header-body separator: join produces \r\n here ...
    lines.append("")  # ... and \r\n here, giving the required \r\n\r\n
    raw = "\r\n".join(lines).encode("utf-8") + body_bytes
    return raw


def build_http_response():
    """Minimal 200 OK so Suricata sees a complete HTTP transaction."""
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"OK"
    )


def _wire_bytes(value):
    """Encode fixture text and normalize line endings to CRLF."""
    if isinstance(value, list):
        value = "\n".join(value)
    return str(value).replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def _hex_bytes(value):
    """Decode fixture hex (string or list of strings) into raw bytes."""
    if isinstance(value, list):
        value = "".join(value)
    return bytes.fromhex("".join(str(value).split()))


def craft_pcap(request_spec, output_path, client_port=49152):
    """Write a pcap with a complete established TCP conversation.

    HTTP remains the default. A fixture with ``raw``, ``raw_segments``,
    ``raw_hex`` or ``raw_hex_segments`` uses those bytes as to-server payloads
    and may add a server banner and response. Hex fields carry binary protocols
    (DNS over TCP, TLS records) that text fields cannot express.
    """
    raw_mode = any(
        key in request_spec for key in ("raw", "raw_segments", "raw_hex", "raw_hex_segments")
    )
    client_ip = request_spec.get("client_ip", "198.51.100.10" if raw_mode else "10.0.0.1")
    server_ip = request_spec.get("server_ip", "10.0.0.2")
    server_port = request_spec.get("port", 21 if raw_mode else 80)
    client_seq = 1000
    server_seq = 2000

    if raw_mode:
        if "raw_hex_segments" in request_spec:
            client_payloads = [_hex_bytes(value) for value in request_spec["raw_hex_segments"]]
        elif "raw_hex" in request_spec:
            client_payloads = [_hex_bytes(request_spec["raw_hex"])]
        elif "raw_segments" in request_spec:
            client_payloads = [_wire_bytes(value) for value in request_spec["raw_segments"]]
        else:
            client_payloads = [_wire_bytes(request_spec["raw"])]
        server_banner = _wire_bytes(request_spec.get("server_banner", ""))
        server_response = _wire_bytes(request_spec.get("server_response", ""))
    else:
        client_payloads = [build_http_request(request_spec)]
        server_banner = b""
        server_response = build_http_response()

    packets = [
        IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq),
        IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        ),
        IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        ),
    ]
    client_seq += 1
    server_seq += 1

    if server_banner:
        packets.append(
            IP(src=server_ip, dst=client_ip)
            / TCP(
                sport=server_port,
                dport=client_port,
                flags="PA",
                seq=server_seq,
                ack=client_seq,
            )
            / Raw(load=server_banner)
        )
        server_seq += len(server_banner)
        packets.append(
            IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=client_port,
                dport=server_port,
                flags="A",
                seq=client_seq,
                ack=server_seq,
            )
        )

    for client_payload in client_payloads:
        packets.append(
            IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=client_port,
                dport=server_port,
                flags="PA",
                seq=client_seq,
                ack=server_seq,
            )
            / Raw(load=client_payload)
        )
        client_seq += len(client_payload)
        packets.append(
            IP(src=server_ip, dst=client_ip)
            / TCP(
                sport=server_port,
                dport=client_port,
                flags="A",
                seq=server_seq,
                ack=client_seq,
            )
        )

    if server_response:
        packets.append(
            IP(src=server_ip, dst=client_ip)
            / TCP(
                sport=server_port,
                dport=client_port,
                flags="PA",
                seq=server_seq,
                ack=client_seq,
            )
            / Raw(load=server_response)
        )
        server_seq += len(server_response)
        packets.append(
            IP(src=client_ip, dst=server_ip)
            / TCP(
                sport=client_port,
                dport=server_port,
                flags="A",
                seq=client_seq,
                ack=server_seq,
            )
        )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wrpcap(output_path, packets)
    return output_path
