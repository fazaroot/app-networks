package com.netshieldx.app.vpn

/** Kategori filter DNS. */
enum class FilterCategory(val label: String) {
    ADS("Iklan"),
    TRACKER("Tracker"),
    PHISHING_MALWARE("Phishing dan Malware"),
    CUSTOM("Kustom")
}

sealed class FilterDecision {
    object Allowed : FilterDecision()
    data class Blocked(val category: FilterCategory, val matchedRule: String) : FilterDecision()
}

/**
 * Mesin pencocokan domain terhadap blocklist dan allowlist.
 * Mendukung pencocokan persis dan wildcard subdomain (aturan
 * "ads.example.com" juga memblokir "a.ads.example.com").
 * Allowlist selalu menang atas blocklist.
 * Kode murni Kotlin agar bisa diuji unit.
 */
class DnsFilter {

    private val blockedByCategory = mutableMapOf<FilterCategory, MutableSet<String>>()
    private val allowlist = mutableSetOf<String>()
    private val enabledCategories = mutableSetOf<FilterCategory>(
        FilterCategory.ADS,
        FilterCategory.TRACKER,
        FilterCategory.PHISHING_MALWARE,
        FilterCategory.CUSTOM
    )

    @Synchronized
    fun setBlocked(category: FilterCategory, domains: Collection<String>) {
        blockedByCategory[category] = domains
            .map { DnsPacket.normalizeDomain(it) }
            .filter { it.isNotBlank() }
            .toMutableSet()
    }

    @Synchronized
    fun addBlocked(category: FilterCategory, domain: String) {
        val normalized = DnsPacket.normalizeDomain(domain)
        if (normalized.isBlank()) return
        blockedByCategory.getOrPut(category) { mutableSetOf() }.add(normalized)
    }

    @Synchronized
    fun removeBlocked(category: FilterCategory, domain: String) {
        blockedByCategory[category]?.remove(DnsPacket.normalizeDomain(domain))
    }

    @Synchronized
    fun setAllowlist(domains: Collection<String>) {
        allowlist.clear()
        allowlist.addAll(domains.map { DnsPacket.normalizeDomain(it) }.filter { it.isNotBlank() })
    }

    @Synchronized
    fun addAllowlist(domain: String) {
        val normalized = DnsPacket.normalizeDomain(domain)
        if (normalized.isNotBlank()) allowlist.add(normalized)
    }

    @Synchronized
    fun removeAllowlist(domain: String) {
        allowlist.remove(DnsPacket.normalizeDomain(domain))
    }

    @Synchronized
    fun setCategoryEnabled(category: FilterCategory, enabled: Boolean) {
        if (enabled) enabledCategories.add(category) else enabledCategories.remove(category)
    }

    @Synchronized
    fun isCategoryEnabled(category: FilterCategory): Boolean = enabledCategories.contains(category)

    @Synchronized
    fun decide(rawDomain: String): FilterDecision {
        val domain = DnsPacket.normalizeDomain(rawDomain)
        if (domain.isBlank()) return FilterDecision.Allowed
        if (matchesAny(domain, allowlist)) return FilterDecision.Allowed
        for ((category, rules) in blockedByCategory) {
            if (!enabledCategories.contains(category)) continue
            val matched = findMatch(domain, rules)
            if (matched != null) return FilterDecision.Blocked(category, matched)
        }
        return FilterDecision.Allowed
    }

    @Synchronized
    fun blockedCount(category: FilterCategory): Int = blockedByCategory[category]?.size ?: 0

    @Synchronized
    fun allowlistDomains(): Set<String> = allowlist.toSet()

    @Synchronized
    fun blockedDomains(category: FilterCategory): Set<String> =
        blockedByCategory[category]?.toSet() ?: emptySet()

    private fun matchesAny(domain: String, rules: Set<String>): Boolean {
        return findMatch(domain, rules) != null
    }

    private fun findMatch(domain: String, rules: Set<String>): String? {
        if (rules.contains(domain)) return domain
        var suffix = domain
        while (true) {
            val dot = suffix.indexOf('.')
            if (dot < 0) return null
            suffix = suffix.substring(dot + 1)
            if (rules.contains(suffix)) return suffix
        }
    }
}
