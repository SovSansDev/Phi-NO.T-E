# Phi NO.T-E

**Network Diagnostics & Security Inspection Toolkit**  
Developer: **SansDev**  
Platform utama: Android melalui Termux · Python 3.11+
Join server SANS TEAM: https://discord.gg/DXAm7CGgb8

Phi NO.T-E adalah alat inspeksi jaringan baca-saja untuk belajar dan mendiagnosis perangkat/jaringan yang memang boleh Anda periksa. Tool ini tidak melakukan port scanning, brute force, eksploitasi, pengubahan konfigurasi jaringan, atau pengunduhan isi halaman.

## Instalasi di Termux

```sh
pkg update
pkg install python
cd /path/ke/folder/phi-no-te
python -m pip install -r requirements.txt
PYTHONPATH=src python -m phi_no_te
