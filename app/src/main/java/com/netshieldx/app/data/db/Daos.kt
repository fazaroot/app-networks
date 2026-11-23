package com.netshieldx.app.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface NetworkActivityDao {
    @Insert
    suspend fun insert(activity: NetworkActivityEntity)

    @Query("SELECT * FROM network_activity ORDER BY timestamp DESC LIMIT :limit")
    fun getRecent(limit: Int = 200): Flow<List<NetworkActivityEntity>>

    @Query("SELECT COUNT(*) FROM network_activity")
    fun getTotalCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM network_activity WHERE allowed = 0")
    fun getBlockedCount(): Flow<Int>

    @Query("SELECT * FROM network_activity WHERE packageName = :packageName ORDER BY timestamp DESC LIMIT :limit")
    fun getForPackage(packageName: String, limit: Int = 100): Flow<List<NetworkActivityEntity>>

    @Query("SELECT packageName, COUNT(*) as c FROM network_activity WHERE packageName IS NOT NULL GROUP BY packageName ORDER BY c DESC LIMIT :limit")
    suspend fun getTopPackages(limit: Int = 5): List<PackageCount>

    @Query("DELETE FROM network_activity WHERE timestamp < :beforeMs")
    suspend fun deleteOlderThan(beforeMs: Long)

    @Query("DELETE FROM network_activity")
    suspend fun clearAll()
}

data class PackageCount(val packageName: String?, val c: Int)

@Dao
interface BlockedDomainDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(domain: BlockedDomainEntity)

    @Query("SELECT * FROM blocked_domains ORDER BY lastSeen DESC LIMIT :limit")
    fun getRecent(limit: Int = 200): Flow<List<BlockedDomainEntity>>

    @Query("SELECT * FROM blocked_domains WHERE domain = :domain LIMIT 1")
    suspend fun getByDomain(domain: String): BlockedDomainEntity?

    @Query("SELECT COALESCE(SUM(blockCount), 0) FROM blocked_domains")
    fun getTotalBlocks(): Flow<Int>

    @Query("SELECT COALESCE(SUM(blockCount), 0) FROM blocked_domains WHERE category = :category")
    fun getBlocksByCategory(category: String): Flow<Int>

    @Query("DELETE FROM blocked_domains")
    suspend fun clearAll()
}

@Dao
interface ThreatDetectionDao {
    @Insert
    suspend fun insert(detection: ThreatDetectionEntity)

    @Query("SELECT * FROM threat_detections ORDER BY timestamp DESC LIMIT :limit")
    fun getRecent(limit: Int = 200): Flow<List<ThreatDetectionEntity>>

    @Query("SELECT COUNT(*) FROM threat_detections")
    fun getTotalCount(): Flow<Int>

    @Query("DELETE FROM threat_detections WHERE timestamp < :beforeMs")
    suspend fun deleteOlderThan(beforeMs: Long)

    @Query("DELETE FROM threat_detections")
    suspend fun clearAll()
}

@Dao
interface AppFirewallRuleDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(rule: AppFirewallRuleEntity)

    @Query("SELECT * FROM app_firewall_rules")
    fun getAll(): Flow<List<AppFirewallRuleEntity>>

    @Query("SELECT * FROM app_firewall_rules WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackage(packageName: String): AppFirewallRuleEntity?

    @Query("SELECT * FROM app_firewall_rules WHERE mode = 'BLOCK'")
    suspend fun getBlockedRules(): List<AppFirewallRuleEntity>

    @Query("DELETE FROM app_firewall_rules WHERE packageName = :packageName")
    suspend fun delete(packageName: String)
}

@Dao
interface FilterSourceDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(source: FilterSourceEntity)

    @Query("SELECT * FROM filter_sources ORDER BY name")
    fun getAll(): Flow<List<FilterSourceEntity>>

    @Query("SELECT * FROM filter_sources WHERE id = :id LIMIT 1")
    suspend fun getById(id: Long): FilterSourceEntity?

    @Query("DELETE FROM filter_sources WHERE id = :id")
    suspend fun delete(id: Long)
}

@Dao
interface UserSettingsDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(settings: UserSettingsEntity)

    @Query("SELECT * FROM user_settings WHERE id = 1 LIMIT 1")
    fun getSettings(): Flow<UserSettingsEntity?>

    @Query("SELECT * FROM user_settings WHERE id = 1 LIMIT 1")
    suspend fun getSettingsOnce(): UserSettingsEntity?
}
