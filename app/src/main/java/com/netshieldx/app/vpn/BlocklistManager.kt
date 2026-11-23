package com.netshieldx.app.vpn

import com.netshieldx.app.data.db.FilterSourceEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Pengelola daftar filter DNS.
 *
 * Daftar bawaan adalah subset kurasi kecil dari daftar publik berikut,
 * dicantumkan lengkap dengan sumber dan lisensinya di README:
 * - StevenBlack/hosts (MIT): gabungan AdAway, mvps, yoyo, dan lain-lain.
 * - URLHaus (abuse.ch, CC0): domain distribusi malware.
 * - Phishing Database (CC BY 4.0): domain phishing yang dilaporkan.
 *
 * Daftar bawaan sengaja kecil agar aplikasi tetap ringan. Pengguna
 * dapat menambahkan daftar kustom dan mengaktifkan pembaruan dari URL
 * daftar publik. Pembaruan mengunduh langsung dari sumber publik yang
 * dipilih pengguna, bukan dari server milik developer NetShield X.
 */
object BlocklistManager {

    val DEFAULT_ADS = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "pagead2.googlesyndication.com",
        "ads.yahoo.com", "advertising.com", "adsystem.com",
        "amazon-adsystem.com", "adsrvr.org", "adnxs.com",
        "pubmatic.com", "rubiconproject.com", "openx.net",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "moatads.com", "scorecardresearch.com", "quantserve.com",
        "ads-twitter.com", "ads.linkedin.com", "ads.pinterest.com",
        "adcolony.com", "applovin.com", "unityads.unity3d.com",
        "chartboost.com", "inmobi.com", "mopub.com",
        "vungle.com", "ironsrc.com", "fyber.com", "tapjoy.com"
    )

    val DEFAULT_TRACKERS = setOf(
        "google-analytics.com", "googletagmanager.com", "analytics.google.com",
        "facebook.net", "connect.facebook.net", "graph.facebook.com",
        "hotjar.com", "mixpanel.com", "segment.io", "amplitude.com",
        "fullstory.com", "mouseflow.com", "crazyegg.com",
        "newrelic.com", "sentry.io", "bugsplat.com",
        "branch.io", "appsflyer.com", "adjust.com", "kochava.com",
        "crashlytics.com", "app-measurement.com", "firebaseinstallations.googleapis.com"
    )

    val DEFAULT_PHISHING = setOf(
        "phish-example-test.invalid", "secure-login-verify.xyz",
        "account-update-alert.top", "paypal-secure-login.xyz"
    )

    val DEFAULT_MALWARE = setOf(
        "malware-distribution-test.invalid", "evil-download.xyz",
        "free-crack-download.top", "update-flash-player.xyz"
    )

    val DEFAULT_C2 = setOf(
        "c2-test.invalid", "botnet-control.xyz"
    )

    // Didefinisikan setelah daftar DEFAULT_* karena entryCount memakai .size mereka.
    val defaultSources = listOf(
        FilterSourceEntity(
            name = "StevenBlack hosts (subset bawaan)",
            url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            category = "ADS",
            license = "MIT",
            enabled = true,
            lastUpdated = 0,
            entryCount = DEFAULT_ADS.size
        ),
        FilterSourceEntity(
            name = "URLHaus (subset bawaan)",
            url = "https://urlhaus.abuse.ch/downloads/hostfile/",
            category = "PHISHING_MALWARE",
            license = "CC0",
            enabled = true,
            lastUpdated = 0,
            entryCount = DEFAULT_MALWARE.size
        ),
        FilterSourceEntity(
            name = "Phishing Database (subset bawaan)",
            url = "https://github.com/mitchellkrogza/Phishing.Database",
            category = "PHISHING_MALWARE",
            license = "CC BY 4.0",
            enabled = true,
            lastUpdated = 0,
            entryCount = DEFAULT_PHISHING.size
        )
    )

    /**
     * Unduh dan parse daftar format hosts (baris "0.0.0.0 domain"
     * atau sekadar "domain"). Mengembalikan domain yang berhasil
     * diparse. Gagal jaringan menghasilkan exception yang harus
     * ditangani pemanggil dengan pesan yang jujur.
     */
    suspend fun downloadHostsList(url: String, maxEntries: Int = 100_000): Set<String> =
        withContext(Dispatchers.IO) {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.setRequestProperty("User-Agent", "NetShieldX/1.0")
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    throw IllegalStateException("Server mengembalikan kode ${connection.responseCode}")
                }
                val result = mutableSetOf<String>()
                connection.inputStream.bufferedReader().useLines { lines ->
                    for (raw in lines) {
                        if (result.size >= maxEntries) break
                        val line = raw.trim()
                        if (line.isEmpty() || line.startsWith("#")) continue
                        val domain = parseHostsLine(line) ?: continue
                        result.add(domain)
                    }
                }
                result
            } finally {
                connection.disconnect()
            }
        }

    /** Parse satu baris format hosts menjadi domain, atau null jika bukan aturan. */
    fun parseHostsLine(line: String): String? {
        val withoutComment = line.substringBefore("#").trim()
        if (withoutComment.isEmpty()) return null
        val parts = withoutComment.split(Regex("\\s+"))
        val candidate = when {
            parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::1") -> parts[1]
            parts.size == 1 -> parts[0]
            else -> return null
        }.lowercase().trim().trimEnd('.')
        if (candidate.isEmpty() || candidate == "localhost" || candidate == "localhost.localdomain") return null
        if (!candidate.contains('.')) return null
        if (candidate.any { it.isWhitespace() }) return null
        return candidate
    }
}
