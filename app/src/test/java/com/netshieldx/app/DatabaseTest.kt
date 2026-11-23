package com.netshieldx.app

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.netshieldx.app.data.db.AppDatabase
import com.netshieldx.app.data.db.AppFirewallRuleEntity
import com.netshieldx.app.data.db.BlockedDomainEntity
import com.netshieldx.app.data.db.NetworkActivityEntity
import com.netshieldx.app.data.db.ThreatDetectionEntity
import com.netshieldx.app.data.db.UserSettingsEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Pengujian Room dengan database in-memory di Robolectric.
 * Memverifikasi DAO benar-benar menyimpan dan membaca data,
 * bukan hanya logika murni.
 */
@RunWith(RobolectricTestRunner::class)
class DatabaseTest {

    private lateinit var db: AppDatabase

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun teardown() {
        db.close()
    }

    @Test
    fun settings_saveAndRead() = runBlocking {
        val settings = UserSettingsEntity(startOnBoot = true, upstreamDns = "8.8.8.8")
        db.userSettingsDao().save(settings)
        val read = db.userSettingsDao().getSettingsOnce()
        assertNotNull(read)
        assertEquals(true, read!!.startOnBoot)
        assertEquals("8.8.8.8", read.upstreamDns)
    }

    @Test
    fun firewallRule_upsertAndRead() = runBlocking {
        db.appFirewallRuleDao().upsert(
            AppFirewallRuleEntity("com.example.app", "BLOCK", System.currentTimeMillis())
        )
        val rule = db.appFirewallRuleDao().getByPackage("com.example.app")
        assertNotNull(rule)
        assertEquals("BLOCK", rule!!.mode)
        val blocked = db.appFirewallRuleDao().getBlockedRules()
        assertEquals(1, blocked.size)
    }

    @Test
    fun networkActivity_insertAndCount() = runBlocking {
        db.networkActivityDao().insert(
            NetworkActivityEntity(
                timestamp = 1000L, domain = "example.com", packageName = "com.example.app",
                uid = 1000, protocol = "DNS", bytesRx = 0, bytesTx = 0,
                allowed = true, category = null, riskLevel = null
            )
        )
        db.networkActivityDao().insert(
            NetworkActivityEntity(
                timestamp = 2000L, domain = "ads.example.com", packageName = "com.example.app",
                uid = 1000, protocol = "DNS", bytesRx = 0, bytesTx = 0,
                allowed = false, category = "ADS", riskLevel = null
            )
        )
        assertEquals(2, db.networkActivityDao().getTotalCount().first())
        assertEquals(1, db.networkActivityDao().getBlockedCount().first())
        val recent = db.networkActivityDao().getRecent(10).first()
        assertEquals(2, recent.size)
        assertEquals("ads.example.com", recent[0].domain)
    }

    @Test
    fun blockedDomain_insertAndSum() = runBlocking {
        db.blockedDomainDao().insert(
            BlockedDomainEntity("ads.example.com", "ADS", "DNS Filter", 1000L, 1000L, 3)
        )
        db.blockedDomainDao().insert(
            BlockedDomainEntity("tracker.example.com", "TRACKER", "DNS Filter", 1000L, 1000L, 2)
        )
        assertEquals(5, db.blockedDomainDao().getTotalBlocks().first())
        assertEquals(3, db.blockedDomainDao().getBlocksByCategory("ADS").first())
    }

    @Test
    fun threatDetection_insertAndPrune() = runBlocking {
        val now = System.currentTimeMillis()
        db.threatDetectionDao().insert(
            ThreatDetectionEntity(
                timestamp = now - 40L * 24 * 60 * 60 * 1000,
                domain = "old.example.com", riskLevel = "HIGH",
                reason = "Lama", source = "Test", listed = true
            )
        )
        db.threatDetectionDao().insert(
            ThreatDetectionEntity(
                timestamp = now, domain = "new.example.com", riskLevel = "LOW",
                reason = "Baru", source = "Test", listed = false
            )
        )
        assertEquals(2, db.threatDetectionDao().getTotalCount().first())
        db.threatDetectionDao().deleteOlderThan(now - AppDatabase.LOG_RETENTION_MS)
        val remaining = db.threatDetectionDao().getRecent(10).first()
        assertEquals(1, remaining.size)
        assertEquals("new.example.com", remaining[0].domain)
    }

    @Test
    fun clearAll_emptiesLogs() = runBlocking {
        db.networkActivityDao().insert(
            NetworkActivityEntity(
                timestamp = 1000L, domain = null, packageName = null,
                uid = -1, protocol = "TCP", bytesRx = 10, bytesTx = 20,
                allowed = true, category = null, riskLevel = null
            )
        )
        assertTrue(db.networkActivityDao().getTotalCount().first() > 0)
        db.networkActivityDao().clearAll()
        assertEquals(0, db.networkActivityDao().getTotalCount().first())
    }
}
