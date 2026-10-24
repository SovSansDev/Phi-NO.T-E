from __future__ import annotations

from typing import Any

from .device import detect_capabilities
from .dns_tools import lookup_domain
from .network import collect_local_network, network_intelligence


def _local_network_status(network: dict[str, Any]) -> str:
    if any(value.get("status") == "ok" for value in network.values() if isinstance(value, dict)):
        return "ok"
    return "unavailable"


def _status_for_dns(result: dict[str, Any]) -> str:
    records = [
        record
        for resolver in result.get("resolvers", {}).values()
        for record in resolver.get("records", {}).values()
    ]
    if any(record.get("status") == "ok" for record in records):
        return "ok"
    if any(record.get("status") in {"timeout", "failed"} for record in records):
        return "failed"
    return "unavailable"


def run_basic_diagnostics(
    *,
    url: str,
    domain: str | None,
    timeout: float,
    comparison_resolver: str,
) -> dict[str, Any]:
    errors: list[str] = []
    capabilities = detect_capabilities()
    connectivity_and_network = network_intelligence(url, timeout)
    local_network = {
        key: connectivity_and_network[key]
        for key in ("local_addresses", "interfaces", "default_route", "traffic_counters")
    }
    checks: list[dict[str, Any]] = [
        {"name": "Device capabilities", "status": "ok", "details": capabilities},
        {
            "name": "HTTPS connectivity",
            "status": connectivity_and_network["connectivity"].get("status", "unknown"),
            "details": connectivity_and_network["connectivity"],
        },
        {
            "name": "Local network",
            "status": _local_network_status(local_network),
            "details": local_network,
        },
    ]
    if connectivity_and_network["connectivity"].get("status") == "failed":
        errors.append(connectivity_and_network["connectivity"].get("error", "Koneksi HTTPS gagal."))

    dns_result = None
    if domain:
        try:
            dns_result = lookup_domain(
                domain,
                timeout=timeout,
                comparison_resolver=comparison_resolver,
            )
            dns_status = _status_for_dns(dns_result)
            checks.append({"name": "DNS lookup", "status": dns_status, "details": dns_result})
            if dns_status == "failed":
                errors.append("Sebagian atau seluruh lookup DNS mengalami kegagalan/timeout.")
        except (ValueError, RuntimeError, OSError) as exc:
            errors.append(str(exc))
            checks.append({"name": "DNS lookup", "status": "failed", "details": {"error": str(exc)}})

    statuses = [item["status"] for item in checks]
    successful_count = statuses.count("ok")
    failed_count = statuses.count("failed")
    unavailable_count = statuses.count("unavailable")
    if failed_count and not successful_count:
        overall = "failed"
    elif failed_count or unavailable_count:
        overall = "partial"
    else:
        overall = "ok"
    return {
        "checked_at": __import__("datetime").datetime.now().astimezone().isoformat(),
        "status": overall,
        "counts": {
            "successful": successful_count,
            "failed": failed_count,
            "unavailable": unavailable_count,
        },
        "checks": checks,
        "errors": errors,
        "follow_up": [
            "Bandingkan hasil dengan snapshot sebelumnya jika ingin melihat perubahan jaringan.",
            "Periksa izin Termux, status Wi-Fi/data, dan resolver perangkat jika data berstatus unavailable atau timeout.",
            "Data yang tidak tersedia tidak dihitung sebagai kegagalan.",
        ],
        "dns_result": dns_result,
           }
