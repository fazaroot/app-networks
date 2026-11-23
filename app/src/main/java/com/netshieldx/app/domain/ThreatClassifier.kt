package com.netshieldx.app.domain

/** Tingkat risiko ancaman. */
enum class RiskLevel(val label: String) {
    LOW("Rendah"),
    MEDIUM("Sedang"),
    HIGH("Tinggi"),
    CRITICAL("Kritis")
}

/** Hasil klasifikasi satu domain. */
data class ThreatAssessment(
    val domain: String,
    val level: RiskLevel,
    val reason: String,
    val source: String,
    /** true jika domain terdaftar di blocklist ancaman, false jika hanya heuristik. */
    val listed: Boolean
)

/**
 * Klasifikasi ancaman berdasarkan blocklist threat intelligence.
 *
 * Prinsip kejujuran yang dipakai:
 * - Domain yang terdaftar di blocklist phishing/malware/C2 dinilai
 *   berdasarkan kategori daftarnya.
 * - Heuristik (misalnya domain sangat panjang atau banyak angka)
 *   hanya menghasilkan penilaian "belum dapat dipastikan" dengan
 *   level Low dan listed = false, tidak pernah High atau Critical.
 * - Klasifikasi ini tidak pernah menyatakan perangkat terinfeksi.
 */
object ThreatClassifier {

    fun classify(
        domain: String,
        phishingDomains: Set<String>,
        malwareDomains: Set<String>,
        c2Domains: Set<String>
    ): ThreatAssessment? {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isBlank()) return null
        if (matches(normalized, c2Domains)) {
            return ThreatAssessment(
                domain = normalized,
                level = RiskLevel.CRITICAL,
                reason = "Domain terdaftar sebagai command-and-control (C2) pada daftar ancaman.",
                source = "Blocklist C2",
                listed = true
            )
        }
        if (matches(normalized, malwareDomains)) {
            return ThreatAssessment(
                domain = normalized,
                level = RiskLevel.HIGH,
                reason = "Domain terdaftar sebagai penyebar malware pada daftar ancaman.",
                source = "Blocklist Malware",
                listed = true
            )
        }
        if (matches(normalized, phishingDomains)) {
            return ThreatAssessment(
                domain = normalized,
                level = RiskLevel.HIGH,
                reason = "Domain terdaftar sebagai phishing pada daftar ancaman.",
                source = "Blocklist Phishing",
                listed = true
            )
        }
        if (looksSuspicious(normalized)) {
            return ThreatAssessment(
                domain = normalized,
                level = RiskLevel.LOW,
                reason = "Pola domain tidak biasa (sangat panjang atau didominasi angka). " +
                    "Belum dapat dipastikan berbahaya dan perlu pemeriksaan lebih lanjut.",
                source = "Heuristik lokal",
                listed = false
            )
        }
        return null
    }

    private fun matches(domain: String, rules: Set<String>): Boolean {
        if (rules.contains(domain)) return true
        var suffix = domain
        while (true) {
            val dot = suffix.indexOf('.')
            if (dot < 0) return false
            suffix = suffix.substring(dot + 1)
            if (rules.contains(suffix)) return true
        }
    }

    private fun looksSuspicious(domain: String): Boolean {
        if (domain.length > 60) return true
        val digits = domain.count { it.isDigit() }
        if (domain.isNotEmpty() && digits * 2 > domain.length) return true
        if (domain.count { it == '-' } > 5) return true
        return false
    }
}
