from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - exercised on installations missing the declared dependency
    dns = None  # type: ignore[assignment]


MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_COUNT = 100
MAX_REDIRECTS = 3
REDIRECT_CODES = {301, 302, 303, 307, 308}


class ProbeError(RuntimeError):
    """A bounded HTTPS request could not be completed safely."""


def normalize_https_url(value: str, *, allow_ip: bool = True) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("URL kosong.")
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise ValueError("URL mengandung karakter kontrol.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() != "https":
        raise ValueError("Hanya alamat HTTPS yang diizinkan.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL tidak boleh memuat username atau password.")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Hostname atau port tidak valid.") from exc
    if not hostname:
        raise ValueError("Hostname tidak ditemukan.")
    if "%" in hostname:
        raise ValueError("Zona IPv6 tidak didukung.")
    try:
        address = ipaddress.ip_address(hostname)
        if not allow_ip:
            raise ValueError("Security Inspector memerlukan nama domain, bukan alamat IP.")
        normalized_host = address.compressed
    except ValueError as exc:
        if str(exc).startswith("Security Inspector"):
            raise
        try:
            normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as idna_error:
            raise ValueError("Nama domain tidak valid.") from idna_error
        if not normalized_host or len(normalized_host) > 253:
            raise ValueError("Nama domain tidak valid.")
        labels = normalized_host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Nama domain tidak valid.")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Port harus berada pada rentang 1–65535.")
    host_for_url = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    netloc = host_for_url if port is None else f"{host_for_url}:{port}"
    path = parsed.path or "/"
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def resolve_host(hostname: str, timeout: float) -> list[str]:
    try:
        return [ipaddress.ip_address(hostname).compressed]
    except ValueError:
        pass
    if dns is None:
        raise ProbeError("Dependensi dnspython belum terpasang; jalankan pip install .")

    resolver = dns.resolver.Resolver(configure=True)
    addresses: set[str] = set()
    errors: list[str] = []
    deadline = time.perf_counter() + max(0.1, timeout)
    for record_type in ("A", "AAAA"):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            errors.append("waktu lookup DNS habis")
            break
        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                lifetime=max(0.1, remaining),
                raise_on_no_answer=False,
            )
            if answer.rrset:
                addresses.update(str(record) for record in answer)
        except dns.resolver.NXDOMAIN:
            errors.append("NXDOMAIN")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers as exc:
            errors.append(f"resolver tidak tersedia: {exc}")
        except dns.exception.Timeout:
            errors.append("timeout DNS")
        except dns.exception.DNSException as exc:
            errors.append(f"error DNS: {exc}")
        except OSError as exc:
            errors.append(f"resolver: {exc}")
    if addresses:
        return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))
    detail = "; ".join(dict.fromkeys(errors)) or "tidak ada record A/AAAA"
    raise ProbeError(f"Hostname tidak dapat di-resolve: {detail}.")


def _cert_summary(cert: dict[str, Any]) -> dict[str, Any]:
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    expiry_iso: str | None = None
    days_remaining: float | None = None
    if not_after:
        try:
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            expiry_iso = expiry.isoformat()
            days_remaining = round((expiry - datetime.now(timezone.utc)).total_seconds() / 86400, 2)
        except (OverflowError, ValueError):
            pass
    subject = [
        [str(key), str(value)]
        for group in cert.get("subject", ())
        for key, value in group
    ]
    issuer = [
        [str(key), str(value)]
        for group in cert.get("issuer", ())
        for key, value in group
    ]
    san = [
        {"type": str(kind), "value": str(value)}
        for kind, value in cert.get("subjectAltName", ())
    ]
    return {
        "verified_by_system_trust_store": True,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": expiry_iso,
        "days_remaining": days_remaining,
        "subject_alt_names": san,
    }


def _read_response_headers(stream: Any) -> tuple[int, str, dict[str, str], int]:
    total_bytes = 0
    for _ in range(4):
        status_line = stream.readline(4097)
        total_bytes += len(status_line)
        if not status_line or len(status_line) > 4096 or total_bytes > MAX_HEADER_BYTES:
            raise ProbeError("Respons server tidak valid atau melewati batas ukuran header.")
        match = re.fullmatch(rb"HTTP/\d(?:\.\d)?[ \t]+(\d{3})(?:[ \t]+([^\r\n]*))?\r?\n", status_line)
        if not match:
            raise ProbeError("Baris status HTTP tidak valid.")
        status_code = int(match.group(1))
        reason = (match.group(2) or b"").decode("latin-1", "replace")
        headers: dict[str, str] = {}
        header_count = 0
        while True:
            line = stream.readline(8193)
            total_bytes += len(line)
            if not line or len(line) > 8192 or total_bytes > MAX_HEADER_BYTES:
                raise ProbeError("Header respons terlalu besar atau tidak lengkap.")
            if line in (b"\r\n", b"\n"):
                break
            header_count += 1
            if header_count > MAX_HEADER_COUNT or line[:1] in (b" ", b"\t") or b":" not in line:
                raise ProbeError("Header respons tidak valid atau melewati batas jumlah.")
            key, value = line.split(b":", 1)
            name = key.decode("ascii", "replace").strip().lower()
            if not name:
                raise ProbeError("Nama header respons tidak valid.")
            text = value.decode("latin-1", "replace").strip()
            headers[name] = f"{headers[name]}, {text}" if name in headers else text
        if status_code < 100 or status_code >= 200:
            return status_code, reason, headers, total_bytes
    raise ProbeError("Server mengirim terlalu banyak respons interim.")


def _request_one(
    url: str, **…**

_This response is too long to display in full._
