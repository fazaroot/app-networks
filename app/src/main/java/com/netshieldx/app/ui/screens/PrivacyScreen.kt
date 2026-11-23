package com.netshieldx.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacyScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Privasi dan Keamanan") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Kembali")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            PrivacySection(
                title = "Cara kerja VPN lokal",
                body = "NetShield X memakai Android VpnService untuk membuat interface jaringan virtual di perangkatmu sendiri. " +
                    "Aplikasi membuat terowongan lokal: paket dari aplikasi lain dibaca oleh NetShield X, difilter berdasarkan " +
                    "aturan DNS dan firewall, lalu diteruskan ke tujuan aslinya melalui koneksi internet biasa. " +
                    "Tidak ada server VPN eksternal milik developer. Trafik tidak pernah dikirim ke server NetShield X."
            )
            PrivacySection(
                title = "Data yang diproses",
                body = "Yang diproses: metadata koneksi (domain dari query DNS, alamat IP tujuan, port, protokol, UID aplikasi, " +
                    "dan jumlah byte). Riwayat ini disimpan lokal di database perangkat dan otomatis dihapus setelah 30 hari. " +
                    "Yang TIDAK pernah dikumpulkan: isi HTTPS yang terenkripsi, password, cookie, token, atau payload aplikasi."
            )
            PrivacySection(
                title = "Yang tidak dilakukan aplikasi ini",
                body = "• Tidak melakukan MITM HTTPS dan tidak memasang sertifikat CA.\n" +
                    "• Tidak membaca isi pesan, foto, atau file.\n" +
                    "• Tidak memakai root.\n" +
                    "• Tidak memakai hidden API atau Accessibility Service untuk memantau aktivitas.\n" +
                    "• Tidak mengubah aplikasi lain atau menyisipkan kode ke aplikasi lain.\n" +
                    "• Tidak mengirim riwayat browsing ke server mana pun."
            )
            PrivacySection(
                title = "Protokol yang didukung",
                body = "Didukung: IPv4, DNS UDP port 53 (filtering lokal), TCP IPv4 (forwarding), UDP IPv4 non-DNS (forwarding). " +
                    "Tidak didukung: IPv6 (paket tidak diproses), ICMP (dijatuhkan), dan protokol lain. " +
                    "Jika aplikasi memakai DNS-over-HTTPS atau DNS-over-TLS, query DNS-nya tidak terlihat oleh filter DNS " +
                    "karena terenkripsi, dan domain tersebut tidak bisa diblokir di lapisan DNS."
            )
            PrivacySection(
                title = "Keterbatasan yang jujur",
                body = "• DNS filtering tidak bisa memblokir iklan yang memakai domain yang sama dengan konten normal.\n" +
                    "• Deteksi ancaman hanya menandai domain yang terdaftar di blocklist tepercaya atau pola yang mencurigakan. " +
                    "Satu koneksi mencurigakan tidak berarti perangkat terinfeksi.\n" +
                    "• Pemetaan trafik ke aplikasi memakai UID dari /proc/net dan bersifat best-effort. " +
                    "Koneksi yang sangat singkat bisa tampil sebagai unknown.\n" +
                    "• Daftar bawaan adalah subset kurasi. Daftar lengkap dimuat saat pengguna memperbarui dari sumber publik."
            )
            PrivacySection(
                title = "Kontrol pengguna",
                body = "Kamu bisa menghentikan perlindungan kapan saja dari Dashboard. Saat VPN berhenti, tidak ada lagi paket " +
                    "yang diproses. Kamu bisa menghapus semua log dari Pengaturan, menonaktifkan kategori filter, dan memakai " +
                    "allowlist untuk domain yang salah diblokir."
            )
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun PrivacySection(title: String, body: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(4.dp))
            Text(text = body, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
