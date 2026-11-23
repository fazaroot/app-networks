# NetShield X — Android Network Security Suite

NetShield X adalah aplikasi Android native (Kotlin, Jetpack Compose, Material 3)
untuk pemantauan dan perlindungan jaringan berbasis VPN lokal.

Cara kerjanya: aplikasi membuat interface VPN virtual di perangkatmu sendiri
lewat Android VpnService. Paket dari aplikasi lain dibaca, difilter berdasarkan
aturan DNS dan firewall, lalu diteruskan ke tujuan aslinya. **Tidak ada server
VPN eksternal milik developer. Tidak ada MITM HTTPS. Tidak ada instalasi
sertifikat CA. Tidak ada root.**

## Fitur

### 1. Live Network Monitor
- Status koneksi dan statistik trafik dari `TrafficStats` (data aktual sistem).
- Kecepatan unduh dan unggah dari sampling berkala.
- Daftar koneksi yang diproses VPN lokal (waktu, domain bila teridentifikasi,
  aplikasi bila terpetakan, status diizinkan atau diblokir).
- Grafik trafik real-time dari data aktual.
- Riwayat tersimpan di Room. Domain atau aplikasi yang tidak bisa
  diidentifikasi tampil sebagai unknown, tidak pernah dikarang.

### 2. DNS Ad dan Tracker Blocker
- DNS filtering lewat VPNService lokal.
- Kategori iklan, tracker, dan phishing/malware yang bisa diaktifkan
  atau dinonaktifkan.
- Blocklist dan allowlist kustom.
- Cache DNS dengan batas 512 entri dan TTL.
- Statistik pemblokiran dan log domain diblokir.
- Pembaruan daftar dari URL publik yang dipilih pengguna.

**Batasan yang jujur:** DNS filtering tidak bisa memblokir semua iklan,
terutama iklan yang memakai domain yang sama dengan konten normal.
Gunakan allowlist jika ada situs yang rusak karena pemblokiran.

### 3. Suspicious Domain Detector
- Memeriksa domain terhadap blocklist ancaman (phishing, malware, C2).
- Tingkat risiko: Rendah, Sedang, Tinggi, Kritis.
- Menampilkan alasan domain ditandai dan sumber daftarnya.
- Notifikasi untuk ancaman Tinggi dan Kritis.
- Riwayat deteksi tersimpan di Room.

**Batasan yang jujur:** aplikasi tidak bisa mendeteksi semua malware.
Satu koneksi mencurigakan tidak berarti perangkat terinfeksi.
Heuristik lokal (misalnya domain sangat panjang) hanya menghasilkan
penilaian "belum dapat dipastikan" dengan risiko Rendah.

### 4. Per-App Firewall
- Daftar aplikasi terpasang dengan nama, package name, dan statistik
  trafik per UID.
- Mode per aplikasi: Izinkan, Blokir, Pantau, Peringatkan.
- Pemetaan UID ke aplikasi lewat `PackageManager.getPackagesForUid`
  dan pemetaan port ke UID lewat `/proc/net` (teknik yang sama dengan
  aplikasi firewall lokal lainnya).
- Aturan Blokir berlaku di lapisan VPNService.

**Batasan yang jujur:** pemetaan port ke UID bersifat best-effort.
Koneksi yang sangat singkat bisa sudah tertutup saat `/proc/net` dibaca
dan tampil sebagai unknown.

### 5. Security Dashboard
- Status perlindungan dan VPN lokal.
- Total trafik, domain diblokir, tracker diblokir, ancaman terdeteksi,
  koneksi diperiksa, aplikasi teratas, dan grafik trafik.
- Semua statistik berasal dari data aktual, bukan angka dummy.

## Protokol yang didukung

| Protokol | Status |
|---|---|
| IPv4 | Didukung |
| DNS UDP port 53 | Didukung, difilter lokal |
| TCP IPv4 | Didukung, forwarding lewat Socket |
| UDP IPv4 non-DNS | Didukung, forwarding lewat DatagramSocket |
| IPv6 | Tidak diproses |
| ICMP | Dijatuhkan, tidak diteruskan |
| DNS-over-HTTPS / DNS-over-TLS | Tidak terlihat filter karena terenkripsi |

## Privasi

- Tidak mengumpulkan data pribadi.
- Tidak mengirim riwayat browsing ke server mana pun.
- Tidak memasang sertifikat CA.
- Tidak melakukan MITM HTTPS.
- Tidak memakai root, hidden API, atau Accessibility Service.
- Tidak mengubah aplikasi lain atau menyisipkan kode.
- Tidak menyimpan payload sensitif. Hanya metadata koneksi yang dicatat,
  dan log otomatis dihapus setelah 30 hari.
- Detail lengkap ada di layar Privasi dan Keamanan di dalam aplikasi.

## Sumber blocklist dan lisensi

Daftar bawaan adalah subset kurasi kecil agar aplikasi tetap ringan.
Daftar lengkap dimuat saat pengguna memperbarui dari URL sumber.

| Daftar | Sumber | Lisensi |
|---|---|---|
| StevenBlack/hosts | https://github.com/StevenBlack/hosts | MIT |
| URLHaus hostfile (abuse.ch) | https://urlhaus.abuse.ch/downloads/hostfile/ | CC0 |
| Phishing.Database | https://github.com/mitchellkrogza/Phishing.Database | CC BY 4.0 |

## Spesifikasi teknis

- Bahasa: Kotlin 1.9.24
- UI: Jetpack Compose (BOM 2024.06.00), Material 3, Navigation Compose
- Build: Gradle Kotlin DSL, Android Gradle Plugin 8.4.2, Gradle 8.7
- `compileSdk 34`, `targetSdk 34`, `minSdk 26` (Android 8.0)
- Java 17
- Database: Room 2.6.1
- Package: `com.netshieldx.app`

## Struktur proyek

```
NetShieldX/
├── .github/workflows/android.yml
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── res/
│       └── java/com/netshieldx/app/
│           ├── MainActivity.kt
│           ├── NetShieldApplication.kt
│           ├── vpn/ (NetShieldVpnService, VpnEngine, DnsPacket,
│           │        DnsFilter, DnsCache, BlocklistManager,
│           │        IpPacket, TransportPackets, Checksum, UidMapper)
│           ├── domain/ (ThreatClassifier)
│           ├── data/db/ (AppDatabase, Entities, Daos)
│           ├── data/repository/ (Repositories)
│           ├── device/ (TrafficMonitor, AppInfoProvider)
│           ├── notification/ (NotificationHelper)
│           ├── boot/ (BootReceiver)
│           └── ui/ (theme, navigation, viewmodel, components, screens)
└── app/src/test/ (unit tests)
```

## Cara build via GitHub Actions (tanpa Android Studio)

1. Push proyek ini ke repository GitHub.
2. Buka tab Actions di repository.
3. Workflow "Android CI - Build NetShield X" berjalan otomatis saat push
   ke branch main, atau jalankan manual lewat tombol Run workflow.
4. Workflow menjalankan unit tests, lalu `./gradlew assembleDebug`.
5. Unduh artifact bernama **NetShield-X-debug-apk** dari halaman run.
   Di dalamnya ada `app-debug.apk`.

## Cara build lokal (dengan Android Studio)

```bash
./gradlew testDebugUnitTest
./gradlew assembleDebug
```

APK debug ada di `app/build/outputs/apk/debug/app-debug.apk`.

## Cara install APK di Android

1. Salin `app-debug.apk` ke perangkat Android 8.0 atau lebih baru.
2. Di perangkat, izinkan install dari sumber ini saat diminta
   (Pengaturan akan menawarkannya saat membuka file APK).
3. Buka aplikasi, baca penjelasan di Dashboard, lalu tekan
   **Mulai Perlindungan** dan setujui permintaan VPN dari Android.
4. Uji pemblokiran dengan membuka situs yang memakai domain iklan
   umum, lalu periksa angka di Dashboard dan log di layar Proteksi.

## Cara menguji di perangkat nyata

1. **Dashboard:** tekan Mulai Perlindungan, setujui VPN, pastikan status
   berubah menjadi Aktif dan notifikasi foreground muncul.
2. **Jaringan:** buka browser dan beberapa aplikasi, pastikan riwayat
   koneksi muncul dengan domain yang benar.
3. **Proteksi:** periksa angka pemblokiran bertambah saat membuka situs
   beriklan. Tambah domain ke blocklist kustom dan allowlist, pastikan
   keduanya berfungsi.
4. **Firewall:** ubah satu aplikasi ke mode Blokir, buka aplikasi itu,
   pastikan koneksinya gagal. Kembalikan ke Izinkan.
5. **Pengaturan:** ubah tema, DNS upstream, dan interval pembaruan.
   Tutup dan buka lagi aplikasi, pastikan pengaturan tersimpan.
6. **Privasi:** buka layar Privasi dan Keamanan dan baca batasannya.

## Status build

Lihat `BUILD_NOTES.md` untuk status kompilasi yang sebenarnya,
apa yang sudah diverifikasi, dan apa yang masih perlu diuji di
perangkat nyata.
