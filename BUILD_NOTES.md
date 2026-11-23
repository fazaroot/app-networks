# BUILD_NOTES — NetShield X

Catatan jujur tentang status kompilasi proyek ini. Dibuat pada 2026-11-23
di VM Linux tempat proyek ini ditulis.

## Ringkasan status

**Kompilasi penuh (`./gradlew assembleDebug`) BELUM BERHASIL dijalankan di
VM ini, dan APK debug BELUM dihasilkan.** Penyebabnya adalah keterbatasan
lingkungan VM, yang dibuktikan dua kali di bawah. **Bukan** karena kesalahan
kode yang ditemukan — semua kesalahan kode yang ditemukan selama pemeriksaan
sudah diperbaiki (lihat bagian Verifikasi).

Jalur build yang didukung untuk proyek ini adalah GitHub Actions
(`.github/workflows/android.yml`), yang menjalankan unit tests lalu
`assembleDebug` dan mengunggah artifact `NetShield-X-debug-apk`.

## Percobaan build di VM ini

### Percobaan 1: Gradle Wrapper tanpa proxy

```
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  -u ALL_PROXY -u all_proxy \
  JAVA_HOME=/opt/jdk GRADLE_USER_HOME=/home/hatch/gradle-home \
  ./gradlew --no-daemon assembleDebug
```

Hasil: gagal sebelum build dimulai. Wrapper mencoba mengunduh distribusi
Gradle 8.7 dari services.gradle.org dan gagal dengan
`javax.net.ssl.SSLException: Unsupported or unrecognized SSL message`
karena VM ini tidak punya akses internet langsung (akses keluar hanya
lewat proxy HTTP, dan wrapper tidak memakai proxy tanpa konfigurasi
kredensial proxy).

### Percobaan 2: Gradle lokal 8.7, mode offline, tanpa daemon

```
/opt/gradle/gradle-8.7/bin/gradle --offline --no-daemon assembleDebug
```

Hasil: gagal dengan error yang sama persis seperti pada proyek CloneX:

```
FAILURE: Build failed with an exception.
* What went wrong:
Could not receive a message from the daemon.
```

Gradle tetap mem-fork single-use daemon meskipun dengan `--no-daemon`,
dan komunikasi TCP loopback Java tidak berfungsi di VM ini (sudah
dibuktikan pada proyek CloneX dengan uji soket Java-ke-Java).
Sesuai instruksi, percobaan tidak diulang berkali-kali.

## Verifikasi yang sudah dilakukan

### 1. Validasi XML

Seluruh 7 file XML diparse dengan parser XML Python dan semuanya valid:
AndroidManifest, strings, colors, themes, ic_launcher_foreground,
ic_launcher, ic_launcher_round.

### 2. Pemeriksaan sintaks Kotlin dengan kotlinc 1.9.24

Perintah (classpath hanya `android.jar` API 34, tanpa library Gradle):

```
kotlinc -cp ~/Android/Sdk/platforms/android-34/android.jar \
  -d /tmp/kotlinc-nsx-out $(find app/src/main/java -name "*.kt")
kotlinc -cp ~/Android/Sdk/platforms/android-34/android.jar \
  -d /tmp/kotlinc-nsx-test $(find app/src/test/java -name "*.kt")
```

Hasil akhir (setelah perbaikan di bawah):

- **0 syntax error** di seluruh 32 file Kotlin utama dan 5 file test.
- **0 unresolved reference ke `android.*`.** Semua pemakaian API
  framework Android resolve terhadap `android.jar` API 34.
- Sisa error semuanya `unresolved reference` ke library Gradle
  (Compose, Room, Navigation, lifecycle, coroutines, JUnit,
  Robolectric) yang wajar tanpa classpath penuh, ditambah efek
  lanjutan (cascade) dari library yang hilang — misalnya
  `viewModelScope` yang tidak dikenali sehingga pemanggilan `suspend`
  di dalamnya dilaporkan di luar korutin. Semua efek lanjutan sudah
  diperiksa dan tidak ada satu pun yang menunjukkan kesalahan pada
  kode dengan classpath lengkap.

### 3. Kesalahan nyata yang ditemukan dan diperbaiki

1. **SettingsScreen (kesalahan kompilasi):** empat pemanggilan
   `updateSettings { it.copy(... = it) }` memakai `it` yang ambigu
   karena lambda dalam dibayangi lambda luar. Diperbaiki dengan nama
   parameter eksplisit (`enabled`, `s`).
2. **BlocklistManager (bug runtime):** `defaultSources` didefinisikan
   sebelum daftar `DEFAULT_*` yang dipakai `entryCount`-nya, sehingga
   akan NPE saat inisialisasi object. Diperbaiki dengan memindahkan
   `defaultSources` ke setelah daftar default.
3. **UidMapper (kesalahan kompilasi):** KDoc berisi teks `/proc/net/*`
   yang membuka komentar bersarang di Kotlin dan membuat komentar
   tidak tertutup. Diperbaiki dengan mengubah teks komentar.
4. **PacketTest (kesalahan kompilasi):** literal `184` dan `216` dalam
   `byteArrayOf` tidak sesuai tipe Byte. Diperbaiki dengan `.toByte()`.
5. **DashboardScreen:** `when` tanpa cabang `else` dilaporkan tidak
   exhaustive oleh kotlinc. Ditambahkan cabang `else`.

### 4. Tinjauan manual kode

- Seluruh alur VPN ditinjau ulang: persetujuan lewat
  `VpnService.prepare()`, foreground service dengan notifikasi,
  penghentian aman, `protect()` pada semua soket keluar agar tidak
  terjadi loop routing.
- Tidak ada pemakaian hidden API, refleksi ke layanan sistem,
  Accessibility Service, root, MITM HTTPS, atau instalasi CA.
- Pemetaan UID memakai `/proc/net` (teknik publik yang sama dengan
  aplikasi firewall lokal lainnya) dan kegagalan pemetaan dilaporkan
  sebagai unknown, bukan dikarang.

## Yang masih perlu diuji

1. **Di GitHub Actions:** push ke repository, biarkan workflow berjalan,
   periksa unit tests dan `assembleDebug`, unduh artifact
   `NetShield-X-debug-apk`. Jika muncul error kompilasi, catat pesan
   lengkapnya; berdasarkan pemeriksaan di atas, kemungkinan besar
   berasal dari perbedaan versi dependency, bukan dari sintaks kode.
2. **Di perangkat nyata (target utama POCO M6 / HyperOS):** ikuti alur
   pengujian di `README.md` — mulai perlindungan, periksa pemblokiran
   DNS, uji firewall per aplikasi, uji pengaturan tersimpan, dan
   periksa perilaku VPN saat jaringan berganti (Wi-Fi ke data seluler).
3. **Stabilitas jangka panjang:** VPN dibiarkan aktif berjam-jam untuk
   memastikan tidak ada kebocoran memori pada tabel koneksi TCP/UDP
   dan tidak ada kebocoran trafik saat filtering aktif.

## File yang sengaja tidak disertakan

- `local.properties` (machine-specific, berisi path SDK lokal) tidak
  disertakan. Android Studio dan GitHub Actions membuatnya sendiri.
  Selama pengujian di VM ini, file tersebut dibuat sementara lalu
  dihapus sebelum penyerahan.
- Tidak ada keystore. Build rilis perlu signing manual.
- Tidak ada APK. APK hanya dihasilkan oleh GitHub Actions atau build
  lokal di mesin yang Gradle daemon-nya berfungsi.
