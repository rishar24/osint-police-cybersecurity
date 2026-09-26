# OSINT Public Sector Toolkit

Tools ini dirancang untuk kebutuhan yang sah dan terotentikasi, seperti:
- Intel domain dan aset publik milik lembaga/organisasi
- Monitoring situs resmi dan aset digital publik
- Pemetaan infrastruktur digital yang sudah dipublikasikan
- Dukungan investigasi cyber security yang memiliki otoritas/legal basis

Peringatan penting:
- Dilarang digunakan untuk doxing, pencarian data pribadi, surveillance, atau pengumpulan data tanpa dasar hukum yang sah.
- Gunakan hanya untuk domain/aset yang Anda miliki, sedang diaudit, atau diinvestigasi dengan otoritas yang jelas.
- Tidak ada fitur pencarian profil individu, media sosial, atau data pribadi.

Repository ini berisi toolkit legal dan etis untuk OSINT publik yang dibatasi pada aset dan situs yang bersifat publik.

## Fitur
- Domain intelligence: A/AAAA/MX/TXT/NS/CNAME
- Public subdomain enumeration via crt.sh
- Website header and TLS certificate checks
- Official asset monitoring (public pages only)
- Output ringkas untuk analisis cepat

## Struktur
- `tools/domain_intel.py` — analisis domain, DNS, TLS, headers
- `tools/public_asset_enumerator.py` — enumerasi subdomain publik
- `tools/official_monitor.py` — monitoring perubahan halaman situs resmi
- `requirements.txt` — dependency Python

## Instalasi di Termux

```bash
pkg update && pkg upgrade
pkg install python git curl openssl
pip install -r requirements.txt
```

## Contoh penggunaan

### 1) Sistem domain intel

```bash
python tools/domain_intel.py example.com
```

### 2) Enumerasi subdomain publik

```bash
python tools/public_asset_enumerator.py example.com
```

### 3) Monitoring aset resmi

```bash
python tools/official_monitor.py --url https://example.com --keyword "Cyber Security"
```

## Catatan keamanan
- Pastikan Anda memiliki izin yang jelas sebelum melakukan audit terhadap jaringan atau situs pihak lain.
- Untuk operasi di sektor pemerintah atau lembaga hukum, gunakan dengan surat kuasa / mandat / approval sesuai peraturan.

## Lisensi
MIT
