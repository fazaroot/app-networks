package com.netshieldx.app.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Satu peristiwa koneksi yang diproses VPN lokal. */
@Entity(tableName = "network_activity")
data class NetworkActivityEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val domain: String?,
    val packageName: String?,
    val uid: Int,
    val protocol: String,
    val bytesRx: Long,
    val bytesTx: Long,
    val allowed: Boolean,
    val category: String?,
    val riskLevel: String?
)

/** Domain yang diblokir DNS filter, beserta jumlah pemblokirannya. */
@Entity(tableName = "blocked_domains")
data class BlockedDomainEntity(
    @PrimaryKey val domain: String,
    val category: String,
    val source: String,
    val firstSeen: Long,
    val lastSeen: Long,
    val blockCount: Int
)

/** Satu deteksi ancaman dari ThreatClassifier. */
@Entity(tableName = "threat_detections")
data class ThreatDetectionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val domain: String,
    val riskLevel: String,
    val reason: String,
    val source: String,
    val listed: Boolean
)

/** Mode firewall per aplikasi. Nilai mode: ALLOW, BLOCK, MONITOR, ALERT. */
@Entity(tableName = "app_firewall_rules")
data class AppFirewallRuleEntity(
    @PrimaryKey val packageName: String,
    val mode: String,
    val updatedAt: Long
)

/** Sumber daftar filter (blocklist) yang dikenal aplikasi. */
@Entity(tableName = "filter_sources")
data class FilterSourceEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val url: String,
    val category: String,
    val license: String,
    val enabled: Boolean,
    val lastUpdated: Long,
    val entryCount: Int
)

/** Pengaturan pengguna, satu baris dengan id tetap 1. */
@Entity(tableName = "user_settings")
data class UserSettingsEntity(
    @PrimaryKey val id: Int = 1,
    val startOnBoot: Boolean = false,
    val autoUpdateBlocklist: Boolean = false,
    val updateIntervalHours: Int = 24,
    val notificationsEnabled: Boolean = true,
    val darkTheme: Boolean = true,
    val upstreamDns: String = "1.1.1.1",
    val adsEnabled: Boolean = true,
    val trackerEnabled: Boolean = true,
    val phishingMalwareEnabled: Boolean = true
)
