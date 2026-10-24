from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime
from typing import Any

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None  # type: ignore[assignment]

from .storage import data_dir, save_latest, timestamp_slug, write_json

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def validate_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Nama domain tidak boleh kosong.")
    if "://" in raw or "/" in raw or "@" in raw or "?" in raw or "#" in raw:
        raise ValueError("Masukkan nama domain saja, bukan URL lengkap.")
    if ":" in raw:
        raise ValueError("Port atau alamat IP literal tidak diterima; masukkan nama domain saja.")
    try:
        ipaddress.ip_address(raw.rstrip("."))
    except ValueError:
        pass
    else:
        raise ValueError("Alamat IP literal tidak diterima; masukkan nama domain.")
    try:
        domain = raw.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nama domain tidak valid.") from exc
    if len(domain) > 253:
        raise ValueError("Nama domain terlalu panjang.")
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Format nama domain tidak valid.")
    return domain


def _format_answer(record_type: str, record: Any) -> str:
    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text(omit_final_dot=True)}"
    if record_type == "NS":
        return record.target.to_text(omit_final_dot=True)
    if record_type == "TXT":
        return record.to_text()
    return record.to_text()


def _query_resolver(
    domain: str,
    label: str,
    resolver: Any,
    timeout: float,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for record_type in RECORD_TYPES:
        started = time.perf_counter()
        try:
            answer = resolver.resolve(
                domain,
                record_type,
                lifetime=timeout,
                raise_on_no_answer=False,
            )
            values = sorted({_format_answer(record_type, record) for record in (answer or [])})
            results[record_type] = {
                "status": "ok" if values else "no_answer",
                "values": values,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        except dns.resolver.NXDOMAIN:
            results[record_type] = {"status": "nxdomain", "values": []}
        except dns.resolver.NoAnswer:
            results[record_type] = {"status": "no_answer", "values": []}
        except dns.exception.Timeout:
            results[record_type] = {"status": "timeout", "values": []}
        except (dns.resolver.NoNameservers, OSError) as exc:
            results[record_type] = {
                "status": "failed",
                "values": [],
                "error": str(exc)[:240],
            }
        except Exception as exc:
            results[record_type] = {
                "status": "failed",
                "values": [],
                "error": f"{type(exc).__name__}: {str(exc)[:200]}",
            }
    return {"label": label, "records": results}


def lookup_domain(
    value: str,
    *,
    timeout: float,
    comparison_resolver: str,
) -> dict[str, Any]:
    domain = validate_domain(value)
    if dns is None:
        raise RuntimeError("dnspython belum terpasang. Jalankan: python -m pip install .")
    try:
        comparison_ip = ipaddress.ip_address(comparison_resolver.strip())
    except ValueError as exc:
        raise ValueError("Resolver pembanding harus berupa alamat IPv4 atau IPv6.") from exc

    system_resolver = dns.resolver.Resolver(configure=True)
    comparison = dns.resolver.Resolver(configure=False)
    comparison.nameservers = [comparison_ip.compressed]
    comparison.timeout = timeout
    checked_at = datetime.now().astimezone().isoformat()
    result = {
        "checked_at": checked_at,
        "domain": domain,
        "timeout_seconds": timeout,
        "resolvers": {
            "system": _query_resolver(domain, "system", system_resolver, timeout),
            "comparison": _query_resolver(domain, comparison_ip.compressed, comparison, timeout),
        },
    }
    previous = load_previous_lookup(domain)
    result["comparison_with_previous"] = compare_lookups(previous, result) if previous else {
        "status": "unavailable",
        "reason": "Belum ada hasil lookup sebelumnya untuk domain ini.",
        "changes": [],
    }
    write_json(data_dir() / "dns" / f"lookup_{timestamp_slug()}.json", result)
    save_latest("dns", result)
    return result


def load_previous_lookup(domain: str) -> dict[str, Any] | None:
    paths = sorted((data_dir() / "dns").glob("lookup_*.json"), reverse=True)
    for path in paths:
        try:
            import json

            result = json.loads(path.read_text(encoding="utf-8"))
            if result.get("domain") == domain:
                return result
        except (OSError, ValueError):
            continue
    return None


def compare_lookups(
    previous: dict[str, Any] | None,
    latest: dict[str, Any],
) -> dict[str, Any]:
    if previous is None:
        return {"status": "unavailable", "reason": "Tidak ada hasil sebelumnya.", "changes": []}
    changes: list[dict[str, Any]] = []
    unknown: list[str] = []
    old_resolvers = previous.get("resolvers", {})
    new_resolvers = latest.get("resolvers", {})
    for resolver_name in sorted(set(old_resolvers) | set(new_resolvers)):
        for record_type in RECORD_TYPES:
            old_record = old_resolvers.get(resolver_name, {}).get("records", {}).get(record_type, {})
            new_record = new_resolvers.get(resolver_name, {}).get("records", {}).get(record_type, {})
            if old_record.get("status") != "ok" or new_record.get("status") != "ok":
                unknown.append(f"{resolver_name}.{record_type}")
                continue
            old_values = sorted(old_record.get("values", []))
            new_values = sorted(new_record.get("values", []))
            if old_values != new_values:
                changes.append(
                    {
                        "resolver": resolver_name,
                        "record_type": record_type,
                        "before": old_values,
                        "after": new_values,
                    }
                )
    return {
        "status": "changed" if changes else ("unchanged" if not unknown else "partial"),
        "changes": changes,
        "unknown": unknown,
    }
