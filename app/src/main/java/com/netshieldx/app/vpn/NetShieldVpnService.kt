package com.netshieldx.app.vpn

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.netshieldx.app.data.db.AppDatabase
import com.netshieldx.app.data.db.NetworkActivityEntity
import com.netshieldx.app.data.db.ThreatDetectionEntity
import com.netshieldx.app.data.repository.FirewallMode
import com.netshieldx.app.data.repository.NetShieldRepository
import com.netshieldx.app.device.AppInfoProvider
import com.netshieldx.app.domain.RiskLevel
import com.netshieldx.app.domain.ThreatAssessment
import com.netshieldx.app.notification.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

sealed class VpnState {
    object Stopped : VpnState()
    object Starting : VpnState()
    data class Running(val startedAtMs: Long) : VpnState()
    data class Failed(val reason: String) : VpnState()
}

data class VpnLiveStats(
    val bytesRx: Long = 0,
    val bytesTx: Long = 0,
    val connectionsProcessed: Long = 0,
    val packetsProcessed: Long = 0,
    val blockedCount: Long = 0
)

/**
 * VpnService lokal NetShield X.
 *
 * - Meminta persetujuan lewat VpnService.prepare() di MainActivity,
 *   tidak pernah memulai diam-diam.
 * - Berjalan sebagai foreground service dengan notifikasi selama aktif.
 * - Semua pemrosesan paket terjadi lokal. Trafik yang diizinkan
 *   diteruskan ke tujuan aslinya, bukan ke server developer.
 * - HTTPS tidak dibaca isinya dan tidak ada MITM.
 */
class NetShieldVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.netshieldx.app.ACTION_START_VPN"
        const val ACTION_STOP = "com.netshieldx.app.ACTION_STOP_VPN"
        const val VIRTUAL_DNS = "10.8.0.1"
        const val VIRTUAL_ADDRESS = "10.8.0.2"

        private val _state = MutableStateFlow<VpnState>(VpnState.Stopped)
        val state: StateFlow<VpnState> = _state.asStateFlow()

        private val _liveStats = MutableStateFlow(VpnLiveStats())
        val liveStats: StateFlow<VpnLiveStats> = _liveStats.asStateFlow()
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tun: ParcelFileDescriptor? = null
    private var engine: VpnEngine? = null
    private var dnsFilter: DnsFilter = DnsFilter()
    private var upstreamDns: String = "1.1.1.1"
    private var blockedUids: Set<Int> = emptySet()
    private var alertUids: Set<Int> = emptySet()
    private var notificationsEnabled: Boolean = true
    private val blockedCounter = AtomicLong(0)
    private val alertNotifiedUids = mutableSetOf<Int>()

    private lateinit var repository: NetShieldRepository

    override fun onCreate() {
        super.onCreate()
        repository = NetShieldRepository(AppDatabase.getInstance(this))
        NotificationHelper.createChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return Service.START_NOT_STICKY
            }
            ACTION_START -> startVpn()
        }
        return Service.START_STICKY
    }

    private fun startVpn() {
        if (_state.value is VpnState.Running || _state.value is VpnState.Starting) return
        _state.value = VpnState.Starting
        scope.launch {
            try {
                val settings = repository.getSettings()
                notificationsEnabled = settings.notificationsEnabled
                upstreamDns = settings.upstreamDns.ifBlank { "1.1.1.1" }
                dnsFilter = repository.buildDnsFilter(emptyMap(), emptySet())
                repository.ensureDefaultSources()
                refreshFirewallUids()

                val builder = Builder()
                    .setSession("NetShield X")
                    .addAddress(VIRTUAL_ADDRESS, 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(VIRTUAL_DNS)
                    .setMtu(1500)
                    .setBlocking(false)
                val descriptor = builder.establish()
                if (descriptor == null) {
                    _state.value = VpnState.Failed("Sistem menolak membuat interface VPN. Coba lagi atau periksa izin VPN di Pengaturan.")
                    return@launch
                }
                tun = descriptor
                startForeground(
                    NotificationHelper.VPN_NOTIFICATION_ID,
                    NotificationHelper.buildVpnNotification(this@NetShieldVpnService, 0, 0)
                )
                val input = FileInputStream(descriptor.fileDescriptor)
                val output = FileOutputStream(descriptor.fileDescriptor)
                val dnsAddress = IpPacket.parseAddress(VIRTUAL_DNS) ?: byteArrayOf(10, 8, 0, 1)
                val engineInstance = VpnEngine(input, output, dnsAddress, vpnCallbacks)
                engine = engineInstance
                engineInstance.start()
                _state.value = VpnState.Running(System.currentTimeMillis())
                launchStatsLoop(engineInstance)
                repository.pruneOldLogs()
            } catch (e: Exception) {
                Log.e("NetShieldVpn", "Gagal memulai VPN", e)
                _state.value = VpnState.Failed("Gagal memulai VPN: ${e.message ?: "kesalahan tidak diketahui"}")
                stopVpn()
            }
        }
    }

    private fun launchStatsLoop(engineInstance: VpnEngine) {
        scope.launch {
            while (engineInstance.isRunning()) {
                kotlinx.coroutines.delay(2000)
                _liveStats.value = VpnLiveStats(
                    bytesRx = engineInstance.bytesReceived.get(),
                    bytesTx = engineInstance.bytesSent.get(),
                    connectionsProcessed = engineInstance.connectionsProcessed.get(),
                    packetsProcessed = engineInstance.packetsProcessed.get(),
                    blockedCount = blockedCounter.get()
                )
            }
        }
    }

    private suspend fun refreshFirewallUids() {
        val blockedPackages = repository.getBlockedPackages()
        blockedUids = blockedPackages.mapNotNull { pkg ->
            val uid = AppInfoProvider.getUidForPackage(this, pkg)
            if (uid >= 0) uid else null
        }.toSet()
        val rules = repository.firewallRules
        val alertPackages = mutableSetOf<String>()
        try {
            kotlinx.coroutines.flow.first(rules).forEach { rule ->
                if (rule.mode == FirewallMode.ALERT.name) alertPackages.add(rule.packageName)
            }
        } catch (_: Exception) {
        }
        alertUids = alertPackages.mapNotNull { pkg ->
            val uid = AppInfoProvider.getUidForPackage(this, pkg)
            if (uid >= 0) uid else null
        }.toSet()
    }

    /** Dipanggil UI setelah aturan firewall berubah agar mesin memakai aturan baru. */
    fun refreshFirewallRules() {
        scope.launch { refreshFirewallUids() }
    }

    /** Dipanggil UI setelah daftar filter berubah agar mesin memakai filter baru. */
    fun refreshDnsFilter() {
        scope.launch {
            dnsFilter = repository.buildDnsFilter(emptyMap(), emptySet())
        }
    }

    private val vpnCallbacks = object : VpnCallbacks {
        override fun protectSocket(socket: Socket): Boolean {
            return try {
                protect(socket)
            } catch (_: Exception) {
                false
            }
        }

        override fun protectSocket(socket: DatagramSocket): Boolean {
            return try {
                protect(socket)
            } catch (_: Exception) {
                false
            }
        }

        override fun getDnsFilter(): DnsFilter = dnsFilter
        override fun getUpstreamDns(): String = upstreamDns
        override fun getCustomBlocked(): Map<FilterCategory, Set<String>> = emptyMap()
        override fun getAllowlist(): Set<String> = emptySet()

        override fun isUidBlocked(uid: Int): Boolean {
            return uid >= 0 && blockedUids.contains(uid)
        }

        override fun getModeForUid(uid: Int): String {
            return when {
                uid < 0 -> "MONITOR"
                blockedUids.contains(uid) -> "BLOCK"
                alertUids.contains(uid) -> "ALERT"
                else -> "MONITOR"
            }
        }

        override fun onDnsEvent(domain: String, uid: Int, decision: FilterDecision) {
            scope.launch {
                val packageName = if (uid >= 0) {
                    AppInfoProvider.getPackagesForUid(this@NetShieldVpnService, uid).firstOrNull()
                } else null
                val allowed = decision is FilterDecision.Allowed
                if (!allowed) {
                    blockedCounter.incrementAndGet()
                    val blocked = decision as FilterDecision.Blocked
                    repository.recordBlocked(domain, blocked.category.name, "DNS Filter")
                }
                repository.recordActivity(
                    NetworkActivityEntity(
                        timestamp = System.currentTimeMillis(),
                        domain = domain,
                        packageName = packageName,
                        uid = uid,
                        protocol = "DNS",
                        bytesRx = 0,
                        bytesTx = 0,
                        allowed = allowed,
                        category = (decision as? FilterDecision.Blocked)?.category?.name,
                        riskLevel = null
                    )
                )
            }
        }

        override fun onThreat(assessment: ThreatAssessment) {
            scope.launch {
                repository.recordThreat(
                    ThreatDetectionEntity(
                        timestamp = System.currentTimeMillis(),
                        domain = assessment.domain,
                        riskLevel = assessment.level.name,
                        reason = assessment.reason,
                        source = assessment.source,
                        listed = assessment.listed
                    )
                )
                if (notificationsEnabled &&
                    (assessment.level == RiskLevel.HIGH || assessment.level == RiskLevel.CRITICAL)
                ) {
                    NotificationHelper.showThreatNotification(
                        this@NetShieldVpnService,
                        assessment.domain,
                        assessment.level.label,
                        assessment.reason
                    )
                }
            }
        }

        override fun onConnectionOpened(protocol: String, dstAddress: String, dstPort: Int, uid: Int) {
        }

        override fun onConnectionClosed(protocol: String, uid: Int, bytesRx: Long, bytesTx: Long) {
            scope.launch {
                val packageName = if (uid >= 0) {
                    AppInfoProvider.getPackagesForUid(this@NetShieldVpnService, uid).firstOrNull()
                } else null
                repository.recordActivity(
                    NetworkActivityEntity(
                        timestamp = System.currentTimeMillis(),
                        domain = null,
                        packageName = packageName,
                        uid = uid,
                        protocol = protocol,
                        bytesRx = bytesRx,
                        bytesTx = bytesTx,
                        allowed = true,
                        category = null,
                        riskLevel = null
                    )
                )
            }
        }

        override fun onAlertModeConnection(uid: Int, dstAddress: String, dstPort: Int) {
            if (!notificationsEnabled) return
            synchronized(alertNotifiedUids) {
                if (!alertNotifiedUids.add(uid)) return
            }
            scope.launch {
                val packageName = AppInfoProvider.getPackagesForUid(this@NetShieldVpnService, uid).firstOrNull()
                    ?: "unknown"
                NotificationHelper.showAlertNotification(this@NetShieldVpnService, packageName, "$dstAddress:$dstPort")
                kotlinx.coroutines.delay(60_000)
                synchronized(alertNotifiedUids) { alertNotifiedUids.remove(uid) }
            }
        }
    }

    private fun stopVpn() {
        try {
            engine?.stop()
        } catch (_: Exception) {
        }
        engine = null
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
        _state.value = VpnState.Stopped
        _liveStats.value = VpnLiveStats()
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
