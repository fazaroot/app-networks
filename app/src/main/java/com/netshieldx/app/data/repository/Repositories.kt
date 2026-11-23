package com.netshieldx.app.data.repository

import com.netshieldx.app.data.db.AppDatabase
import com.netshieldx.app.data.db.AppFirewallRuleEntity
import com.netshieldx.app.data.db.BlockedDomainEntity
import com.netshieldx.app.data.db.FilterSourceEntity
import com.netshieldx.app.data.db.NetworkActivityEntity
import com.netshieldx.app.data.db.ThreatDetectionEntity
import com.netshieldx.app.data.db.UserSettingsEntity
import com.netshieldx.app.vpn.BlocklistManager
import com.netshieldx.app.vpn.DnsFilter
import com.netshieldx.app.vpn.FilterCategory
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

/** Mode firewall per aplikasi. */
enum class FirewallMode(val label: String) {
    ALLOW("Izinkan"),
    BLOCK("Blokir"),
    MONITOR("Pantau"),
    ALERT("Peringatkan")
}

class NetShieldRepository(private val db: AppDatabase) {

    val recentActivity: Flow<List<NetworkActivityEntity>> = db.networkActivityDao().getRecent()
    val totalConnections: Flow<Int> = db.networkActivityDao().getTotalCount()
    val totalBlockedConnections: Flow<Int> = db.networkActivityDao().getBlockedCount()
    val recentBlocked: Flow<List<BlockedDomainEntity>> = db.blockedDomainDao().getRecent()
    val totalBlocks: Flow<Int> = db.blockedDomainDao().getTotalBlocks()
    val adsBlocks: Flow<Int> = db.blockedDomainDao().getBlocksByCategory("ADS")
    val trackerBlocks: Flow<Int> = db.blockedDomainDao().getBlocksByCategory("TRACKER")
    val recentThreats: Flow<List<ThreatDetectionEntity>> = db.threatDetectionDao().getRecent()
    val totalThreats: Flow<Int> = db.threatDetectionDao().getTotalCount()
    val firewallRules: Flow<List<AppFirewallRuleEntity>> = db.appFirewallRuleDao().getAll()
    val filterSources: Flow<List<FilterSourceEntity>> = db.filterSourceDao().getAll()
    val settings: Flow<UserSettingsEntity?> = db.userSettingsDao().getSettings()

    suspend fun getSettings(): UserSettingsEntity {
        return db.userSettingsDao().getSettingsOnce() ?: UserSettingsEntity().also {
            db.userSettingsDao().save(it)
        }
    }

    suspend fun saveSettings(settings: UserSettingsEntity) {
        db.userSettingsDao().save(settings)
    }

    suspend fun recordActivity(activity: NetworkActivityEntity) {
        db.networkActivityDao().insert(activity)
    }

    suspend fun recordBlocked(domain: String, category: String, source: String) {
        val now = System.currentTimeMillis()
        val existing = db.blockedDomainDao().getByDomain(domain)
        if (existing == null) {
            db.blockedDomainDao().insert(
                BlockedDomainEntity(domain, category, source, now, now, 1)
            )
        } else {
            db.blockedDomainDao().insert(
                existing.copy(lastSeen = now, blockCount = existing.blockCount + 1)
            )
        }
    }

    suspend fun recordThreat(detection: ThreatDetectionEntity) {
        db.threatDetectionDao().insert(detection)
    }

    suspend fun setFirewallMode(packageName: String, mode: FirewallMode) {
        db.appFirewallRuleDao().upsert(
            AppFirewallRuleEntity(packageName, mode.name, System.currentTimeMillis())
        )
    }

    suspend fun getFirewallMode(packageName: String): FirewallMode {
        val rule = db.appFirewallRuleDao().getByPackage(packageName)
        return rule?.let {
            runCatching { FirewallMode.valueOf(it.mode) }.getOrDefault(FirewallMode.MONITOR)
        } ?: FirewallMode.MONITOR
    }

    suspend fun getBlockedPackages(): Set<String> {
        return db.appFirewallRuleDao().getBlockedRules().map { it.packageName }.toSet()
    }

    suspend fun ensureDefaultSources() {
        val existing = db.filterSourceDao().getAll().first()
        if (existing.isEmpty()) {
            for (source in BlocklistManager.defaultSources) {
                db.filterSourceDao().upsert(source)
            }
        }
    }

    suspend fun addFilterSource(source: FilterSourceEntity) {
        db.filterSourceDao().upsert(source)
    }

    suspend fun setFilterSourceEnabled(id: Long, enabled: Boolean) {
        val source = db.filterSourceDao().getById(id) ?: return
        db.filterSourceDao().upsert(source.copy(enabled = enabled))
    }

    suspend fun deleteFilterSource(id: Long) {
        db.filterSourceDao().delete(id)
    }

    suspend fun buildDnsFilter(customBlocked: Map<FilterCategory, Set<String>>, allowlist: Set<String>): DnsFilter {
        val filter = DnsFilter()
        filter.setBlocked(FilterCategory.ADS, BlocklistManager.DEFAULT_ADS + (customBlocked[FilterCategory.ADS] ?: emptySet()))
        filter.setBlocked(FilterCategory.TRACKER, BlocklistManager.DEFAULT_TRACKERS + (customBlocked[FilterCategory.TRACKER] ?: emptySet()))
        filter.setBlocked(
            FilterCategory.PHISHING_MALWARE,
            BlocklistManager.DEFAULT_PHISHING + BlocklistManager.DEFAULT_MALWARE +
                BlocklistManager.DEFAULT_C2 + (customBlocked[FilterCategory.PHISHING_MALWARE] ?: emptySet())
        )
        filter.setBlocked(FilterCategory.CUSTOM, customBlocked[FilterCategory.CUSTOM] ?: emptySet())
        filter.setAllowlist(allowlist)
        val settings = getSettings()
        filter.setCategoryEnabled(FilterCategory.ADS, settings.adsEnabled)
        filter.setCategoryEnabled(FilterCategory.TRACKER, settings.trackerEnabled)
        filter.setCategoryEnabled(FilterCategory.PHISHING_MALWARE, settings.phishingMalwareEnabled)
        return filter
    }

    /** Hapus log yang lebih tua dari batas retensi (30 hari). */
    suspend fun pruneOldLogs() {
        val cutoff = System.currentTimeMillis() - AppDatabase.LOG_RETENTION_MS
        db.networkActivityDao().deleteOlderThan(cutoff)
        db.threatDetectionDao().deleteOlderThan(cutoff)
    }

    suspend fun clearAllLogs() {
        db.networkActivityDao().clearAll()
        db.blockedDomainDao().clearAll()
        db.threatDetectionDao().clearAll()
    }

    suspend fun resetConfiguration() {
        clearAllLogs()
        db.userSettingsDao().save(UserSettingsEntity())
    }

    suspend fun getTopPackages(limit: Int = 5) = db.networkActivityDao().getTopPackages(limit)

    suspend fun exportLogsText(): String {
        val activities = db.networkActivityDao().getRecent(1000).first()
        val threats = db.threatDetectionDao().getRecent(200).first()
        val blocked = db.blockedDomainDao().getRecent(200).first()
        return buildString {
            appendLine("NetShield X - Ekspor Log")
            appendLine("Aktivitas jaringan (${activities.size} entri terbaru):")
            for (a in activities) {
                appendLine("${a.timestamp}\t${a.domain ?: "unknown"}\t${a.packageName ?: "unknown"}\t${a.protocol}\tallowed=${a.allowed}")
            }
            appendLine("Ancaman (${threats.size}):")
            for (t in threats) {
                appendLine("${t.timestamp}\t${t.domain}\t${t.riskLevel}\t${t.reason}")
            }
            appendLine("Domain diblokir (${blocked.size}):")
            for (b in blocked) {
                appendLine("${b.domain}\t${b.category}\tx${b.blockCount}")
            }
        }
    }
}
