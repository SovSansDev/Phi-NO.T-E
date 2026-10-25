from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any

from .device import detect_capabilities
from .diagnostics import run_basic_diagnostics
from .dns_tools import lookup_domain, validate_domain
from .http_probe import ProbeError, normalize_https_url
from .network import collect_local_network, network_intelligence
from .reports import export_report
from .security import inspector_error
from .snapshots import create_snapshot, diff_snapshots, latest_snapshot, snapshot_files
from .storage import load_settings, save_latest, save_settings
from .traffic import watch_traffic
from .ui import (
    Color,
    clear_screen,
    paint,
    print_banner,
    print_json_summary,
    print_menu,
    print_table,
    prompt,
    status_text,
    wait_for_enter,
)


def _settings() -> dict[str, Any]:
    return load_settings()


def _timeout(settings: dict[str, Any]) -> float:
    return float(settings.get("timeout_seconds", 5.0))


def _show_network(report: dict[str, Any]) -> None:
    connectivity = report["connectivity"]
    print_json_summary("Konektivitas HTTPS", {"connectivity": connectivity})
    if connectivity.get("status") == "ok":
        print(
            f"  HTTP {connectivity['http_status']} · "
            f"{connectivity.get('latency_ms', '—')} ms · "
            f"{connectivity.get('peer_ip', '—')}"
        )
        if connectivity.get("redirect_location"):
            print(f"  Redirect tidak diikuti: {connectivity['redirect_location']}")
    print()
    for title, key in (
        ("Alamat lokal", "local_addresses"),
        ("Antarmuka", "interfaces"),
        ("Default route", "default_route"),
        ("Counter trafik", "traffic_counters"),
    ):
        section = report[key]
        print(paint(title, Color.BOLD))
        if section["status"] != "ok":
            print(f"  {status_text(section['status'])}: {section.get('reason', '')}")
            continue
        if key == "local_addresses":
            print("  " + ", ".join(section["addresses"]))
        elif key == "interfaces":
            print_table(
                ["Nama", "Status", "Alamat", "MAC"],
                [
                    [
                        item.get("name", "—"),
                        item.get("state", "unknown"),
                        ", ".join(item.get("addresses", [])) or "—",
                        item.get("mac") or "—",
                    ]
                    for item in section["items"]
                ],
            )
        elif key == "default_route":
            print_table(
                ["Family", "Gateway", "Interface", "Metric"],
                [
                    [item["family"], item.get("gateway") or "—", item.get("interface") or "—", item.get("metric") or "—"]
                    for item in section["items"]
                ],
            )
        else:
            print_table(
                ["Interface", "RX bytes", "TX bytes"],
                [
                    [name, counters["rx_bytes"], counters["tx_bytes"]]
                    for name, counters in section["interfaces"].items()
                ],
            )


def _network_intelligence() -> None:
    settings = _settings()
    url = prompt("Alamat HTTPS yang akan diperiksa", "https://example.com")
    try:
        normalize_https_url(url)
    except ValueError as exc:
        print(paint(str(exc), Color.RED))
        return
    result = network_intelligence(url, _timeout(settings))
    save_latest("network", result)
    _show_network(result)


def _dns_intelligence() -> None:
    settings = _settings()
    domain_value = prompt("Nama domain (tanpa https://)")
    try:
        domain = validate_domain(domain_value)
        result = lookup_domain(
            domain,
            timeout=_timeout(settings),
            comparison_resolver=str(settings["comparison_resolver"]),
        )
    except (ValueError, RuntimeError, OSError) as exc:
        print(paint(f"Lookup tidak dapat dijalankan: {exc}", Color.RED))
        return
    print(f"\nDomain: {result['domain']} | Diperiksa: {result['checked_at']}")
    for resolver_key, resolver in result["resolvers"].items():
        print(paint(f"\nResolver: {resolver['label']}", Color.BOLD + Color.CYAN))
        rows = []
        for record_type, item in resolver["records"].items():
            rows.append(
                [
                    record_type,
                    status_text(item["status"]),
                    "; ".join(item.get("values", [])) or item.get("error", "—"),
                    f"{item.get('latency_ms', '—')} ms",
                ]
            )
        print_table(["Type", "Status", "Jawaban / error", "Waktu"], rows)
    previous = result["comparison_with_previous"]
    print(f"\nPerbandingan dengan hasil sebelumnya: {status_text(previous['status'])}")
    if previous.get("changes"):
        print_table(
            ["Resolver", "Record", "Sebelumnya", "Terbaru"],
            [[item["resolver"], item["record_type"], ", ".join(item["before"]), ", ".join(item["after"])]
             for item in previous["changes"]],
        )
    elif previous.get("reason"):
        print(f"  {previous['reason']}")
    else:
        print("  Tidak ada perubahan yang dapat dipastikan.")


def _traffic_watch() -> None:
    settings = _settings()
    url = prompt("Alamat HTTPS untuk sampel latensi", "https://example.com")
    try:
        normalize_https_url(url)
        interval = float(settings.get("traffic_sample_seconds", 2.0))
        samples = int(settings.get("latency_samples", 3))
        result = watch_traffic(
            url,
            timeout=_timeout(settings),
            interval=interval,
            latency_samples=samples,
        )
    except (ValueError, ProbeError) as exc:
        print(paint(str(exc), Color.RED))
        return
    save_latest("traffic", result)
    print(f"\nCounter trafik (interval {interval:g} detik):")
    rates = result["traffic_rate"]
    if rates["status"] != "ok":
        print(f"  {status_text(rates['status'])}: {rates.get('reason', '')}")
    else:
        print_table(
            ["Interface", "RX B/s", "TX B/s", "RX KB/s", "TX KB/s"],
            [
                [
                    name,
                    item.get("rx_bytes_per_second", "—"),
                    item.get("tx_bytes_per_second", "—"),
                    round(item["rx_bytes_per_second"] / 1024, 2) if item.get("status") == "ok" else "—",
                    round(item["tx_bytes_per_second"] / 1024, 2) if item.get("status") == "ok" else "—",
                ]
                for name, item in rates["interfaces"].items()
            ],
        )
    latency = result["latency"]
    print("\nSampel latensi HTTPS:")
    print_table(
        ["Sampel", "Status", "Latency", "HTTP"],
        [
            [item["sample"], status_text(item["status"]), f"{item.get('latency_ms', '—')} ms", item.get("http_status", "—")]
            for item in latency["samples"]
        ],
    )
    print_json_summary("Ringkasan latensi", latency["summary"])
    print_json_summary("Koneksi TCP established", result["established_connections"])


def _security_inspector() -> None:
    settings = _settings()
    value = prompt("Domain/URL HTTPS publik (tanpa alamat IP)")
    result = inspector_error(value, _timeout(settings))
    save_latest("security", result)
    print_json_summary("Hasil TLS & HTTPS", result)
    if result.get("status") != "ok":
        return
    print("\nSertifikat:")
    print_table(
        ["Field", "Nilai"],
        [
            ["Peer IP", result.get("peer_ip", "—")],
            ["TLS trust store", "terverifikasi" if result["certificate"]["verified_by_system_trust_store"] else "unknown"],
            ["Berlaku sampai", result["certificate"].get("not_after") or "unavailable"],
            ["Hari tersisa", result["certificate"].get("days_remaining", "unavailable")],
            ["HTTP status", result["http_status"]],
            ["Header response dibaca", f"{result['response_header_bytes']} bytes (maksimum 32 KiB)"],
            ["Isi halaman diunduh", "Tidak"],
        ],
    )
    print("\nHeader keamanan:")
    print_table(
        ["Header", "Status", "Nilai"],
        [[item["header"], status_text(item["status"]), item.get("value") or "—"] for item in result["security_headers"]],
    )
    print("\nRingkasan:")
    print(f"  {result['summary']['certificate']['summary']}")
    for note in result["summary"]["notes"]:
        print(f"  - {note}")


def _snapshot_diff() -> None:
    settings = _settings()
    url = prompt("Alamat HTTPS untuk status konektivitas", "https://example.com")
    try:
        normalize_https_url(url)
    except ValueError as exc:
        print(paint(str(exc), Color.RED))
        return
    previous = latest_snapshot()
    current = create_snapshot(url, _timeout(settings))
    diff = diff_snapshots(previous, current)
    print(f"\nSnapshot disimpan: {current['timestamp']}")
    print(f"Status perbandingan: {status_text(diff['status'])}")
    if diff.get("reason"):
        print(f"  {diff['reason']}")
    if diff.get("changes"):
        print_table(
            ["Kategori", "Field", "Sebelumnya", "Terbaru"],
            [
                [item["category"], item["field"], json.dumps(item["before"], ensure_ascii=False),
                 json.dumps(item["after"], ensure_ascii=False)]
                for item in diff["changes"]
            ],
        )
    elif diff["status"] not in {"unavailable"}:
        print("  Tidak ada perubahan yang dapat dipastikan.")
    if diff.get("unknown"):
        print(f"  Field tidak diketahui/unavailable: {', '.join(diff['unknown'][:12])}")
    print(f"  {diff.get('note', '')}")
    print(f"Jumlah snapshot tersimpan: {len(snapshot_files())}")


def _basic_diagnostics() -> None:
    settings = _settings()
    url = prompt("Alamat HTTPS untuk uji konektivitas", "https://example.com")
    domain = prompt("Domain opsional untuk lookup DNS (kosongkan jika lewati)") or None
    try:
        normalize_https_url(url)
        result = run_basic_diagnostics(
            url=url,
            domain=domain,
            timeout=_timeout(settings),
            comparison_resolver=str(settings["comparison_resolver"]),
        )
    except ValueError as exc:
        print(paint(str(exc), Color.RED))
        return
    save_latest("diagnostics", result)
    print(f"\nStatus keseluruhan: {status_text(result['status'])}")
    print_table(
        ["Pemeriksaan", "Status"],
        [[check["name"], status_text(check["status"])] for check in result["checks"]],
    )
    print(
        f"Berhasil: {result['counts']['successful']} | Gagal: {result['counts']['failed']} | "
        f"Tidak tersedia: {result['counts']['unavailable']}"
    )
    if result["errors"]:
        print("\nError yang tercatat:")
        for error in result["errors"]:
            print(f"  - {error}")
    print("\nSaran tindak lanjut:")
    for item in result["follow_up"]:
        print(f"  - {item}")


def _export_reports() -> None:
    json_path, markdown_path, report = export_report()
    print(f"\nLaporan dibuat:")
    print(f"  JSON: {json_path}")
    print(f"  Markdown: {markdown_path}")
    print(f"Bagian laporan: {', '.join(report['sections']) or 'belum ada pemeriksaan tersimpan'}")


def _device_capabilities() -> None:
    result = detect_capabilities()
    save_latest("device", result)
    print_json_summary("Device capabilities (hasil deteksi saat ini)", result)
    print_table(
        ["Kemampuan", "Status"],
        [[item["name"], status_text(item["status"])] for item in result["capabilities"]],
    )
    print("\nData perangkat yang tidak terdeteksi ditampilkan sebagai unavailable; tidak diasumsikan.")


def _valid_resolver(value: str) -> str:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError as exc:
        raise ValueError("Resolver pembanding harus berupa alamat IPv4/IPv6.") from exc


def _settings_menu() -> None:
    settings = _settings()
    while True:
        print("\nSettings")
        print(f"  [1] Timeout pemeriksaan: {settings['timeout_seconds']} detik")
        print(f"  [2] Resolver pembanding DNS: {settings['comparison_resolver']}")
        print(f"  [3] Interval sampel trafik: {settings['traffic_sample_seconds']} detik")
        print(f"  [4] Jumlah sampel latensi: {settings['latency_samples']}")
        print("  [0] Kembali")
        choice = prompt("Phi NO.T-E Settings >")
        try:
            if choice == "1":
                value = float(prompt("Timeout (1–15 detik)"))
                if not 1 <= value <= 15:
                    raise ValueError("Timeout harus 1 sampai 15 detik.")
                settings["timeout_seconds"] = value
            elif choice == "2":
                settings["comparison_resolver"] = _valid_resolver(prompt("IP resolver pembanding"))
            elif choice == "3":
                value = float(prompt("Interval trafik (0.5–30 detik)"))
                if not 0.5 <= value <= 30:
                    raise ValueError("Interval harus 0.5 sampai 30 detik.")
                settings["traffic_sample_seconds"] = value
            elif choice == "4":
                value = int(prompt("Jumlah sampel latensi (1–5)"))
                if not 1 <= value <= 5:
                    raise ValueError("Jumlah sampel harus 1 sampai 5.")
                settings["latency_samples"] = value
            elif choice == "0":
                return
            else:
                print("Pilihan tidak dikenal.")
                continue
            save_settings(settings)
            print("Pengaturan disimpan.")
        except ValueError as exc:
            print(paint(str(exc), Color.RED))


def _dispatch(choice: str) -> bool:
    actions = {
        "1": _network_intelligence,
        "2": _dns_intelligence,
        "3": _traffic_watch,
        "4": _security_inspector,
        "5": _snapshot_diff,
        "6": _basic_diagnostics,
        "7": _export_reports,
        "8": _device_capabilities,
        "9": _settings_menu,
    }
    if choice == "0":
        print("Phi NO.T-E ditutup.")
        return False
    action = actions.get(choice)
    if action is None:
        print("Pilihan tidak dikenal. Pilih angka 0–9.")
        return True
    try:
        action()
    except KeyboardInterrupt:
        print("\nPemeriksaan dibatalkan oleh pengguna.")
    except Exception as exc:
        print(paint(f"Terjadi error yang tertangani: {type(exc).__name__}: {exc}", Color.RED))
    return True


def main() -> None:
    try:
        while True:
            clear_screen()
            print_banner()
            print_menu()
            choice = prompt("Phi NO.T-E >")
            if not _dispatch(choice):
                break
            wait_for_enter()
    except (EOFError, KeyboardInterrupt):
        print("\nPhi NO.T-E ditutup.")


if __name__ == "__main__":
    main()
