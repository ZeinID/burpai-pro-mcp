# BurpAI Pro - MCP Server

BurpAI Pro adalah Model Context Protocol (MCP) server yang berfungsi sebagai asisten AI untuk pengujian penetrasi web. Server ini mengintegrasikan Burp Suite melalui REST API dan menyediakan 20+ tools untuk analisis keamanan, generasi payload, dan pelaporan.

## Fitur Utama

- **Proxy & Traffic Analysis**: Mengambil dan menganalisis proxy history.
- **Vulnerability Scanning**: Integrasi dengan Burp Scanner dan standalone detection (SQLi, XSS, dll).
- **Payload Generation**: Membuat payload custom untuk SQLi, XSS, Path Traversal, dll.
- **Request Manipulation**: Mengirim HTTP request melalui Burp atau secara langsung.
- **Reporting**: Membuat laporan pentest berformat Markdown dan JSON.
- **Encoding Utils**: URL, Base64, HTML encoding/decoding dan Hashing.

## Instalasi

1. Pastikan Python 3.10+ terinstal.
2. Clone repository ini.
3. Install dependensi:
   ```bash
   pip install -r requirements.txt
   ```

## Konfigurasi

Ubah `config.py` atau atur environment variables:
- `BURP_API_HOST`: Host Burp Suite REST API (default: 127.0.0.1)
- `BURP_API_PORT`: Port Burp Suite REST API (default: 1337)
- `REPORT_OUTPUT_DIR`: Direktori output laporan (default: ./reports)

## Menjalankan Server

Server dapat dijalankan dalam dua mode transport: `stdio` (default) dan `streamable-http`.

### Mode stdio (Untuk Claude Desktop / Cursor)
```bash
python server.py --transport stdio
```

### Mode HTTP (Untuk testing / client remote)
```bash
python server.py --transport streamable-http
```

## Penggunaan Standalone

Jika Burp Suite REST API tidak tersedia, fitur analisis (seperti deteksi kerentanan, header analysis, encoding, dan payload generation) tetap dapat digunakan secara standalone.
