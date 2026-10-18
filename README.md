# ZOVOZ — Subdomain Takeover Triage

Tool CLI berbasis **Go** (bukan Python) untuk audit defensif subdomain. Tool memeriksa respons HTTP, status 404/error, CNAME, dan beberapa pola halaman error layanan hosting yang umum. Hasil `MUNGKIN_TAKEOVER` hanya indikasi awal dan **wajib diverifikasi manual**; tool tidak mencoba mendaftarkan atau mengambil alih domain.

## Build

Memerlukan Go 1.21+.

```bash
go build -o zovoz .
```

Windows:
```powershell
go build -o zovoz.exe .
```

## Penggunaan

```bash
./zovoz -u https://app.example.com
./zovoz -d example.com
./zovoz -l subdomains.txt
./zovoz -l subdomains.txt --live
./zovoz -l subdomains.txt -o hasil.jsonl
./zovoz -l subdomains.txt --live -o hasil.jsonl
./zovoz --version
./zovoz -h
```

- `-u`: satu URL/subdomain.
- `-d`: mengambil nama subdomain dari Certificate Transparency melalui `crt.sh`, lalu memeriksanya. Membutuhkan internet.
- `-l`: file daftar target, satu URL/hostname per baris; baris dengan `#` diabaikan.
- `-o` atau `-f`: menyimpan **semua hasil** dalam format JSON Lines (`.jsonl` disarankan). `--live` hanya memfilter tampilan terminal, bukan file output.
- `--live`: setelah semua target selesai dipindai, hanya menampilkan kandidat `MUNGKIN_TAKEOVER`.
- `--timeout`: timeout dalam detik, default 8.
- `--workers`: concurrency, default 5, maksimum 20.

## Arti status

- `AKTIF`: HTTP merespons, belum ada indikator yang dikenali.
- `404`: HTTP 404; ini **bukan** bukti takeover.
- `ERROR`: DNS/HTTP gagal atau respons error yang tidak cocok dengan fingerprint.
- `MUNGKIN_TAKEOVER`: ada kombinasi petunjuk seperti CNAME yang tidak dapat dijangkau atau pola halaman error provider. Ini bukan konfirmasi bahwa resource dapat diklaim ulang.
