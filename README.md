# dns-rpz
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
DNS resolver kustom dengan RPZ (Response Policy Zone), dibangun menggunakan Go.

## Latar Belakang

### Mengapa dibangun sendiri

Jaringan kami diwajibkan untuk menerapkan pemblokiran domain sesuai daftar Trustpositif Kominfo,
yang didistribusikan sebagai RPZ zone melalui AXFR. Daftar ini saat ini berisi **~7,8 juta domain**
dan terus bertambah setiap harinya.

### Panduan resmi dari Komdigi

Komdigi (Kementerian Komunikasi dan Digital) menerbitkan *Panduan Sinkronisasi dan Konfigurasi
RPZ BIND* sebagai acuan implementasi wajib bagi ISP. Berikut spesifikasi minimum yang mereka
rekomendasikan:

![Panduan Konfigurasi RPZ BIND9 dari Komdigi](assets/komdigi-rpz-guide.png)

| No | Jenis | Spesifikasi |
|---|---|---|
| 1 | Hardware Server | Minimal 4 core CPU, **minimal 8 GB RAM**, 50 GB Storage |
| 2 | Operating System | Linux (Debian, Ubuntu Server, dll.) |
| 3 | Paket Instalasi | BIND9 |
| 4 | Network | IP Publik Dedicated |

**8 GB RAM hanya untuk menjalankan BIND9 dengan RPZ.** Angka ini bukan kebetulan — ini memang
kebutuhan nyata BIND9 saat memuat jutaan entri RPZ ke memori. Panduan tersebut ditulis tanpa
pengujian beban aktual di skala Trustpositif yang sesungguhnya (~7,8 juta domain). Pada praktiknya,
server dengan 8 GB RAM pun bisa mengalami OOM saat AXFR besar berlangsung bersamaan dengan
lonjakan query.

Kami sudah mencoba mengikuti panduan ini dan menemukan masalah yang tidak tercantum di dokumen:

**BIND 9 dengan RPZ**
- Memuat ~7,8 juta entri RPZ menyebabkan konsumsi memori mendekati 8 GB — tepat di batas panduan
- CPU melonjak saat zone transfer dan reload — server menjadi tidak responsif
- Proses reload zone (AXFR) memblokir query selama beberapa menit
- Konfigurasi sangat kompleks dan rapuh pada skala ini

**Unbound dengan RPZ**
- Masalah memori serupa — implementasi RPZ Unbound memuat semua record ke memori
  dalam format yang dioptimalkan untuk DNS umum, bukan untuk pencarian blocklist massal
- Pada 8 juta entri, RSS melebihi RAM yang tersedia dan proses di-kill oleh OOM killer
- Reload membutuhkan restart penuh, menyebabkan downtime layanan

Kedua tool tersebut adalah DNS server serba guna yang sangat baik, namun tidak dirancang untuk
masalah spesifik penegakan blocklist dengan jutaan entri. Struktur data internalnya membawa
overhead yang signifikan per record, yang menumpuk pada skala ini.

**Keputusan membangun dns-rpz:**

Masalah yang perlu kami selesaikan sangat spesifik: diberikan nama domain yang di-query,
apakah ada di blocklist? Jika ya, terapkan kebijakan RPZ. Jika tidak, teruskan ke upstream.
Pada dasarnya ini hanyalah operasi pencarian hashmap.

Resolver yang dibuat khusus, menyimpan semua entri dalam satu `map[string]string` di Go
yang dimuat dari PostgreSQL saat startup, menyelesaikan masalah dengan overhead minimal:

| Metrik | BIND 9 / Unbound | dns-rpz |
|---|---|---|
| Memori pada 7,8 juta entri | ~8 GB (minimum versi Komdigi, OOM pada praktiknya) | ~800 MB |
| Waktu startup / load RPZ | 3–10 menit | < 35 detik |
| CPU saat reload zone | Spike 100%, query terganggu | Goroutine background, atomic swap |
| Kompleksitas konfigurasi | named.conf / unbound.conf dengan direktif RPZ | Satu file `.env` |
| Observabilitas | Butuh tooling log eksternal | Structured logging + audit log built-in |
| Deployment | Package manager / manual | `make deploy` — satu binary statis via SCP |

Inti pemikirannya: tool yang fokus mengerjakan satu hal dengan baik lebih unggul daripada
tool serba guna yang kesulitan menangani kasus yang memang bukan rancangannya.

---

## Cara Kerja

```
Query dari client
    │
    ▼
Cek ACL ── tidak diizinkan ──► REFUSED
    │
    ▼
Pencarian RPZ di in-memory index
    ├── cocok (exact) ──► terapkan aksi RPZ (NXDOMAIN / NODATA / walled garden)
    ├── cocok (wildcard) ──► terapkan aksi RPZ
    └── tidak cocok
            │
            ▼
        Cek response cache
            ├── cache hit ──► kembalikan response cache (TTL disesuaikan)
            └── cache miss
                    │
                    ▼
                Upstream resolver (8.8.8.8, 1.1.1.1, dll.)
                    │
                    ▼
                Simpan ke cache ──► kembalikan ke client
```

**Alur startup:**

1. Muat bootstrap config dari file `.env`
2. Koneksi ke PostgreSQL (pgxpool)
3. Jalankan migrasi schema (idempotent)
4. Muat CIDR yang aktif ke dalam ACL
5. Muat semua record RPZ ke in-memory hashmap (~7,8 juta entri dalam ~800 MB)
6. Jalankan DNS server (UDP + TCP pada port 53)
7. Jalankan scheduler sinkronisasi AXFR (periodic pull dari RPZ master)

**Alur sinkronisasi (AXFR):**

- Scheduler berjalan setiap `sync_interval` detik (default: 5 menit)
- Transfer AXFR penuh dari master → upsert ke PostgreSQL
- Penggantian in-memory index secara atomik (tidak ada downtime saat sync)
- Fallback ke master IP sekunder jika master utama gagal

---

## Arsitektur

```
cmd/dns-rpz/
├── main.go          — wiring: config, DB, index, ACL, upstream, server, SIGHUP handler
└── logger.go        — slog multiHandler (stdout + file tee), LevelVar untuk ubah level runtime

internal/
├── dns/
│   ├── server.go    — DNS query handler (penegakan RPZ, audit log, cek ACL)
│   ├── index.go     — in-memory hashmap thread-safe (RWMutex, 8 juta+ entri)
│   ├── upstream.go  — upstream pool (strategi roundrobin/random/race, TCP fallback)
│   └── cache.go     — TTL-aware LRU response cache (hashicorp/golang-lru/v2)
├── store/
│   ├── db.go        — koneksi pgxpool, migrasi schema
│   ├── zone.go      — CRUD RPZ zone
│   ├── record.go    — upsert/delete record RPZ (bulk)
│   ├── settings.go  — app settings (key/value di DB)
│   ├── ipfilter.go  — manajemen CIDR untuk ACL
│   └── synchistory.go — log riwayat sinkronisasi AXFR
└── syncer/
    └── syncer.go    — AXFR client, scheduler sinkronisasi zone

config/
└── config.go        — parser .env, BootstrapConfig, AppSettings

db/
├── schema.sql       — schema PostgreSQL (embedded)
└── seed.go          — seed pengaturan default
```

**Tech stack:**

| Komponen | Library |
|---|---|
| DNS server + AXFR client | `github.com/miekg/dns` |
| PostgreSQL driver + pool | `github.com/jackc/pgx/v5` (pgxpool) |
| Response cache | `github.com/hashicorp/golang-lru/v2` |
| Config | Parser `.env` pure Go (tanpa dependensi eksternal) |
| Logging | `log/slog` (stdlib) |

---

## Kebutuhan Sistem

- Go 1.25+
- PostgreSQL 14+
- Linux (systemd untuk deployment production)
- Akses SSH ke server production (untuk `make deploy`)

> **Tested in production:** Debian 13 (Trixie)

---

## Konfigurasi

Salin contoh config dan isi nilainya:

```bash
cp dns-rpz.conf.example dns-rpz.conf
```

### Bootstrap config (`dns-rpz.conf`)

Pengaturan ini dimuat saat startup dari file `.env`. Perubahan membutuhkan **restart penuh**
kecuali yang ditandai hot-reloadable.

| Key | Default | Keterangan |
|---|---|---|
| `DATABASE_DSN` | *(wajib)* | Connection string PostgreSQL |
| `DATABASE_MAX_CONNS` | `20` | Maksimal koneksi DB dalam pool |
| `DATABASE_MIN_CONNS` | `2` | Minimal koneksi DB idle |
| `DNS_ADDRESS` | `0.0.0.0:53` | Alamat listen DNS (UDP+TCP) |
| `HTTP_ADDRESS` | `0.0.0.0:8080` | Alamat listen HTTP dashboard |
| `DNS_UPSTREAM` | `8.8.8.8:53,8.8.4.4:53` | Upstream resolver, pisahkan dengan koma |
| `DNS_UPSTREAM_STRATEGY` | `roundrobin` | `roundrobin` / `random` / `race` |
| `DNS_CACHE_SIZE` | `100000` | Jumlah entri cache response upstream (0 = nonaktif) |
| `RPZ_DEFAULT_ACTION` | `nxdomain` | Aksi default saat entri RPZ tidak punya CNAME: `nxdomain` / `nodata` |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` — **hot-reloadable** |
| `LOG_FORMAT` | `text` | `text` / `json` |
| `LOG_FILE` | `false` | Tulis log ke file selain stdout |
| `LOG_FILE_PATH` | `dns-rpz.log` | Path file log (jika `LOG_FILE=true`) |
| `DNS_AUDIT_LOG` | `false` | Log setiap query (client+nama+type+result) — **hot-reloadable** |

### App settings (disimpan di PostgreSQL)

Pengaturan per-zone (master IP, TSIG, interval sync, dll.) dikelola di tabel `rpz_zones`
dan dapat diedit melalui dashboard.

---

## Instalasi

### Build

```bash
make build
# output: bin/dns-rpz (linux/amd64)
```

### Deploy ke production

```bash
make deploy    # build + scp ke server (atomik: upload ke .new, lalu mv)
make restart   # deploy + systemctl restart + tampilkan 15 baris log terakhir
```

### Systemd service

```ini
# /etc/systemd/system/dns-rpz.service
[Unit]
Description=DNS RPZ Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dns-rpz
ExecStart=/opt/dns-rpz/dns-rpz /opt/dns-rpz/dns-rpz.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now dns-rpz
```

---

## Operasional

### Reload tanpa restart (SIGHUP)

```bash
systemctl reload dns-rpz
```

Yang ikut di-reload:
- `LOG_LEVEL` — diterapkan langsung tanpa gangguan koneksi
- `DNS_AUDIT_LOG` — di-toggle secara atomik
- Daftar CIDR ACL — dimuat ulang dari PostgreSQL
- RPZ index — reload penuh dari PostgreSQL (atomic swap, tanpa downtime)

Yang **masih butuh restart penuh**: `DNS_ADDRESS`, `DATABASE_DSN`, `DNS_UPSTREAM`,
`DNS_UPSTREAM_STRATEGY`, `DNS_CACHE_SIZE`

### Aktifkan/nonaktifkan audit log saat runtime

```bash
# Aktifkan
sed -i 's/DNS_AUDIT_LOG=false/DNS_AUDIT_LOG=true/' /opt/dns-rpz/dns-rpz.conf
systemctl reload dns-rpz

# Nonaktifkan
sed -i 's/DNS_AUDIT_LOG=true/DNS_AUDIT_LOG=false/' /opt/dns-rpz/dns-rpz.conf
systemctl reload dns-rpz
```

### Melihat log

```bash
# Live log
journalctl -u dns-rpz -f

# Live, hanya audit
journalctl -u dns-rpz -f | grep audit

# Live, hanya yang diblokir
journalctl -u dns-rpz -f | grep result=blocked

# N baris terakhir
journalctl -u dns-rpz --no-pager -n 50

# Statistik: allowed vs blocked (5 menit terakhir)
journalctl -u dns-rpz --since '5 minutes ago' \
  | grep audit \
  | awk '{for(i=1;i<=NF;i++) if($i~/result=/) print $i}' \
  | sort | uniq -c | sort -rn
```

### Rotasi log

```bash
# /etc/logrotate.d/dns-rpz
/var/log/dns-rpz/dns-rpz.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill -s HUP dns-rpz 2>/dev/null || true
    endscript
}
```

> **Estimasi storage jika audit log aktif:** ~1,5 GB/hari pada 10 juta query/hari.
> Kurangi `rotate 7` menjadi `rotate 3` jika storage terbatas.

---

## Aksi RPZ

| CNAME target di zone | Aksi dns-rpz | Response DNS |
|---|---|---|
| `.` | NXDOMAIN | Domain tidak ada |
| `*.` | NODATA | Nama ada, tapi tidak ada record untuk type yang diminta |
| `walled.garden.` | Redirect | CNAME ke walled garden |
| *(kosong / tanpa CNAME)* | Fallback ke `RPZ_DEFAULT_ACTION` | NXDOMAIN atau NODATA |

---

## Catatan Performa (pada 8 juta entri)

| Metrik | Nilai |
|---|---|
| Memori (index + proses) | ~800 MB |
| Waktu startup / load index | ~25–35 detik |
| Latensi lookup DNS (RPZ hit) | < 1 ms (in-memory hashmap) |
| Latensi lookup DNS (pass-through, cache hit) | < 1 ms |
| Latensi lookup DNS (pass-through, cache miss) | 3–10 ms (upstream RTT) |
| Estimasi hit rate cache pada 10 juta/hari | 60–80% |
| Pengurangan panggilan upstream oleh cache | ~2,5 juta/hari (dari 10 juta) |

---

## Makefile Targets

```bash
make build    # compile untuk linux/amd64
make deploy   # build + upload ke server
make restart  # deploy + restart service + tampilkan log
```

---

## Dashboard *(Coming Soon)*

Dashboard web sedang dalam pengembangan. Fitur yang direncanakan:

- **Manajemen zone RPZ** — tambah, edit, hapus zone; lihat status sinkronisasi AXFR terakhir
- **Manajemen ACL** — tambah/hapus CIDR yang diizinkan menggunakan resolver ini
- **Statistik query** — grafik query per jam, rasio allowed/blocked, top domain yang diblokir
- **Audit log viewer** — cari dan filter log query per client IP atau domain
- **Kontrol runtime** — toggle audit log dan ubah log level tanpa masuk ke server
- **Riwayat sinkronisasi** — log AXFR per zone dengan jumlah record dan durasi transfer

Dashboard akan berjalan di alamat yang dikonfigurasi via `HTTP_ADDRESS` (default: `:8080`).

---

## Lisensi

Proyek ini dilisensikan di bawah [MIT License](LICENSE).

Bebas digunakan, dimodifikasi, dan didistribusikan — termasuk untuk keperluan komersial — selama menyertakan pemberitahuan lisensi dan hak cipta asli.

