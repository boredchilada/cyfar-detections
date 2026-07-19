"""Generate minimal pcaps from YAML fixture specs for Suricata rule testing.

Each fixture test case describes an HTTP request. This module constructs a
valid TCP 3-way handshake + HTTP request/response exchange so Suricata's
stream engine and HTTP parser can process it properly.
"""

import os
from scapy.all import IP, TCP, Raw, wrpcap, Ether


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


def craft_pcap(request_spec, output_path, client_port=49152):
    """Write a pcap with a full TCP/HTTP conversation.

    The pcap contains: SYN, SYN-ACK, ACK, HTTP request (PSH+ACK),
    server ACK, HTTP response (PSH+ACK), client ACK. Suricata needs the
    3-way handshake so flow:established matches, and both request + response
    so the HTTP parser fully commits the transaction.
    """
    client_ip = request_spec.get("client_ip", "10.0.0.1")
    server_ip = request_spec.get("server_ip", "10.0.0.2")
    server_port = request_spec.get("port", 80)
    client_seq = 1000
    server_seq = 2000

    http_req = build_http_request(request_spec)
    http_resp = build_http_response()

    packets = []

    # --- 3-way handshake ---
    # SYN
    packets.append(
        IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq)
    )
    # SYN-ACK
    packets.append(
        IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )
    # ACK
    packets.append(
        IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    # --- HTTP request ---
    packets.append(
        IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="PA",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
        / Raw(load=http_req)
    )

    req_end_seq = client_seq + 1 + len(http_req)

    # Server ACKs the request
    packets.append(
        IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="A",
            seq=server_seq + 1,
            ack=req_end_seq,
        )
    )

    # --- HTTP response ---
    packets.append(
        IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="PA",
            seq=server_seq + 1,
            ack=req_end_seq,
        )
        / Raw(load=http_resp)
    )

    resp_end_seq = server_seq + 1 + len(http_resp)

    # Client ACKs the response
    packets.append(
        IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=req_end_seq,
            ack=resp_end_seq,
        )
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wrpcap(output_path, packets)
    return output_path
