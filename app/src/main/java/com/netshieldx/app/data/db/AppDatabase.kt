package com.netshieldx.app.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        NetworkActivityEntity::class,
        BlockedDomainEntity::class,
        ThreatDetectionEntity::class,
        AppFirewallRuleEntity::class,
        FilterSourceEntity::class,
        UserSettingsEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun networkActivityDao(): NetworkActivityDao
    abstract fun blockedDomainDao(): BlockedDomainDao
    abstract fun threatDetectionDao(): ThreatDetectionDao
    abstract fun appFirewallRuleDao(): AppFirewallRuleDao
    abstract fun filterSourceDao(): FilterSourceDao
    abstract fun userSettingsDao(): UserSettingsDao

    companion object {
        @Volatile
        private var instance: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "netshieldx.db"
                ).fallbackToDestructiveMigration().build().also { instance = it }
            }
        }

        /** Batas retensi log: 30 hari. Dipakai Repository saat pembersihan berkala. */
        const val LOG_RETENTION_MS = 30L * 24 * 60 * 60 * 1000
    }
}
