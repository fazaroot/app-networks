package com.netshieldx.app.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.netshieldx.app.NetShieldApplication
import com.netshieldx.app.data.db.FilterSourceEntity
import com.netshieldx.app.data.db.NetworkActivityEntity
import com.netshieldx.app.data.db.UserSettingsEntity
import com.netshieldx.app.data.repository.FirewallMode
import com.netshieldx.app.data.repository.NetShieldRepository
import com.netshieldx.app.device.AppInfoProvider
import com.netshieldx.app.device.InstalledAppInfo
import com.netshieldx.app.device.TrafficMonitor
import com.netshieldx.app.device.TrafficSnapshot
import com.netshieldx.app.vpn.BlocklistManager
import com.netshieldx.app.vpn.DnsFilter
import com.netshieldx.app.vpn.FilterCategory
import com.netshieldx.app.vpn.NetShieldVpnService
import com.netshieldx.app.vpn.VpnLiveStats
import com.netshieldx.app.vpn.VpnState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

fun repositoryViewModelFactory(context: Context): ViewModelProvider.Factory {
    val repository = (context.applicationContext as NetShieldApplication).repository
    return object : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return when {
                modelClass.isAssignableFrom(DashboardViewModel::class.java) ->
                    DashboardViewModel(repository) as T
                modelClass.isAssignableFrom(NetworkViewModel::class.java) ->
                    NetworkViewModel(repository) as T
                modelClass.isAssignableFrom(FirewallViewModel::class.java) ->
                    FirewallViewModel(context.applicationContext, repository) as T
                modelClass.isAssignableFrom(ProtectionViewModel::class.java) ->
                    ProtectionViewModel(repository) as T
                modelClass.isAssignableFrom(SettingsViewModel::class.java) ->
                    SettingsViewModel(repository) as T
                else -> throw IllegalArgumentException("ViewModel tidak dikenal: ${modelClass.name}")
            }
        }
    }
}

data class DashboardUiState(
    val vpnState: VpnState = VpnState.Stopped,
    val liveStats: VpnLiveStats = VpnLiveStats(),
    val traffic: TrafficSnapshot = TrafficSnapshot(0, 0, 0, 0, 0),
    val totalConnections: Int = 0,
    val totalBlocked: Int = 0,
    val adsBlocked: Int = 0,
    val trackerBlocked: Int = 0,
    val totalThreats: Int = 0,
    val topPackages: List<Pair<String, Int>> = emptyList(),
    val rateHistory: List<Long> = emptyList()
)

class DashboardViewModel(private val repository: NetShieldRepository) : ViewModel() {
    private val rateHistory = mutableListOf<Long>()

    val state: StateFlow<DashboardUiState> = combine(
        NetShieldVpnService.state,
        NetShieldVpnService.liveStats,
        TrafficMonitor.sampleRates(2000L),
        repository.totalConnections,
        repository.totalBlocks,
        repository.adsBlocks,
        repository.trackerBlocks,
        repository.totalThreats
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        val vpnState = values[0] as VpnState
        val liveStats = values[1] as VpnLiveStats
        val traffic = values[2] as TrafficSnapshot
        if (traffic.totalRxBytes >= 0) {
            rateHistory.add(traffic.rxRateBytesPerSec)
            if (rateHistory.size > 30) rateHistory.removeAt(0)
        }
        DashboardUiState(
            vpnState = vpnState,
            liveStats = liveStats,
            traffic = traffic,
            totalConnections = values[3] as Int,
            totalBlocked = values[4] as Int,
            adsBlocked = values[5] as Int,
            trackerBlocked = values[6] as Int,
            totalThreats = values[7] as Int,
            rateHistory = rateHistory.toList()
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DashboardUiState())

    private val _topPackages = MutableStateFlow<List<Pair<String, Int>>>(emptyList())
    val topPackages: StateFlow<List<Pair<String, Int>>> = _topPackages

    init {
        viewModelScope.launch {
            val top = repository.getTopPackages(5)
            _topPackages.value = top.map { (it.packageName ?: "unknown") to it.c }
        }
    }

    fun refreshTopPackages() {
        viewModelScope.launch {
            val top = repository.getTopPackages(5)
            _topPackages.value = top.map { (it.packageName ?: "unknown") to it.c }
        }
    }
}

class NetworkViewModel(private val repository: NetShieldRepository) : ViewModel() {
    val recentActivity: StateFlow<List<NetworkActivityEntity>> =
        repository.recentActivity.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val totalConnections: StateFlow<Int> =
        repository.totalConnections.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val liveStats: StateFlow<VpnLiveStats> = NetShieldVpnService.liveStats
    val vpnState: StateFlow<VpnState> = NetShieldVpnService.state

    fun clearLogs() {
        viewModelScope.launch { repository.clearAllLogs() }
    }
}

data class FirewallAppItem(
    val info: InstalledAppInfo,
    val mode: FirewallMode,
    val rxBytes: Long,
    val txBytes: Long
)

class FirewallViewModel(
    private val context: Context,
    private val repository: NetShieldRepository
) : ViewModel() {
    private val _apps = MutableStateFlow<List<FirewallAppItem>>(emptyList())
    val apps: StateFlow<List<FirewallAppItem>> = _apps
    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading
    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _loading.value = true
            try {
                val installed = AppInfoProvider.getInstalledApps(context)
                val items = installed.map { info ->
                    FirewallAppItem(
                        info = info,
                        mode = repository.getFirewallMode(info.packageName),
                        rxBytes = TrafficMonitor.uidRxBytes(info.uid),
                        txBytes = TrafficMonitor.uidTxBytes(info.uid)
                    )
                }
                _apps.value = items
            } catch (e: Exception) {
                _message.value = "Gagal memuat daftar aplikasi: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }

    fun setMode(packageName: String, mode: FirewallMode) {
        viewModelScope.launch {
            repository.setFirewallMode(packageName, mode)
            _apps.value = _apps.value.map {
                if (it.info.packageName == packageName) it.copy(mode = mode) else it
            }
            _message.value = "Aturan $packageName diubah ke ${mode.label}."
        }
    }

    fun clearMessage() {
        _message.value = null
    }
}

class ProtectionViewModel(private val repository: NetShieldRepository) : ViewModel() {
    val recentBlocked = repository.recentBlocked
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val recentThreats = repository.recentThreats
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val totalBlocks = repository.totalBlocks
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val filterSources = repository.filterSources
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val settings: StateFlow<UserSettingsEntity?> = repository.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message

    private val _customBlocked = MutableStateFlow<Map<FilterCategory, Set<String>>>(emptyMap())
    val customBlocked: StateFlow<Map<FilterCategory, Set<String>>> = _customBlocked

    private val _allowlist = MutableStateFlow<Set<String>>(emptySet())
    val allowlist: StateFlow<Set<String>> = _allowlist

    private val _updating = MutableStateFlow(false)
    val updating: StateFlow<Boolean> = _updating

    init {
        viewModelScope.launch { repository.ensureDefaultSources() }
    }

    fun setCategoryEnabled(category: FilterCategory, enabled: Boolean) {
        viewModelScope.launch {
            val current = repository.getSettings()
            val updated = when (category) {
                FilterCategory.ADS -> current.copy(adsEnabled = enabled)
                FilterCategory.TRACKER -> current.copy(trackerEnabled = enabled)
                FilterCategory.PHISHING_MALWARE -> current.copy(phishingMalwareEnabled = enabled)
                FilterCategory.CUSTOM -> current
            }
            repository.saveSettings(updated)
            _message.value = "Kategori ${category.label} ${if (enabled) "diaktifkan" else "dinonaktifkan"}."
        }
    }

    fun addCustomBlocked(domain: String) {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isBlank() || !normalized.contains('.')) {
            _message.value = "Domain tidak valid."
            return
        }
        val current = _customBlocked.value[FilterCategory.CUSTOM] ?: emptySet()
        _customBlocked.value = _customBlocked.value + (FilterCategory.CUSTOM to (current + normalized))
        _message.value = "$normalized ditambahkan ke blocklist kustom."
    }

    fun removeCustomBlocked(domain: String) {
        val current = _customBlocked.value[FilterCategory.CUSTOM] ?: emptySet()
        _customBlocked.value = _customBlocked.value + (FilterCategory.CUSTOM to (current - domain))
        _message.value = "$domain dihapus dari blocklist kustom."
    }

    fun addAllowlist(domain: String) {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isBlank() || !normalized.contains('.')) {
            _message.value = "Domain tidak valid."
            return
        }
        _allowlist.value = _allowlist.value + normalized
        _message.value = "$normalized ditambahkan ke allowlist."
    }

    fun removeAllowlist(domain: String) {
        _allowlist.value = _allowlist.value - domain
        _message.value = "$domain dihapus dari allowlist."
    }

    fun setFilterSourceEnabled(id: Long, enabled: Boolean) {
        viewModelScope.launch {
            repository.setFilterSourceEnabled(id, enabled)
        }
    }

    fun addFilterSource(name: String, url: String, category: String) {
        if (name.isBlank() || url.isBlank() || !url.startsWith("https://")) {
            _message.value = "Nama dan URL https daftar filter harus diisi."
            return
        }
        viewModelScope.launch {
            repository.addFilterSource(
                FilterSourceEntity(
                    name = name.trim(),
                    url = url.trim(),
                    category = category,
                    license = "Lihat sumber",
                    enabled = true,
                    lastUpdated = 0,
                    entryCount = 0
                )
            )
            _message.value = "Sumber filter $name ditambahkan."
        }
    }

    fun updateFilterSource(source: FilterSourceEntity) {
        viewModelScope.launch {
            _updating.value = true
            try {
                val domains = BlocklistManager.downloadHostsList(source.url)
                repository.addFilterSource(
                    source.copy(lastUpdated = System.currentTimeMillis(), entryCount = domains.size)
                )
                val category = when (source.category) {
                    "ADS" -> FilterCategory.ADS
                    "TRACKER" -> FilterCategory.TRACKER
                    else -> FilterCategory.PHISHING_MALWARE
                }
                val current = _customBlocked.value[category] ?: emptySet()
                _customBlocked.value = _customBlocked.value + (category to (current + domains))
                _message.value = "${source.name} diperbarui: ${domains.size} domain dimuat."
            } catch (e: Exception) {
                _message.value = "Gagal memperbarui ${source.name}: ${e.message}"
            } finally {
                _updating.value = false
            }
        }
    }

    fun clearMessage() {
        _message.value = null
    }
}

class SettingsViewModel(private val repository: NetShieldRepository) : ViewModel() {
    val settings: StateFlow<UserSettingsEntity?> = repository.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message

    private val _exportText = MutableStateFlow<String?>(null)
    val exportText: StateFlow<String?> = _exportText

    init {
        viewModelScope.launch { repository.getSettings() }
    }

    fun updateSettings(transform: (UserSettingsEntity) -> UserSettingsEntity) {
        viewModelScope.launch {
            val current = repository.getSettings()
            repository.saveSettings(transform(current))
        }
    }

    fun clearLogs() {
        viewModelScope.launch {
            repository.clearAllLogs()
            _message.value = "Log dibersihkan."
        }
    }

    fun resetConfiguration() {
        viewModelScope.launch {
            repository.resetConfiguration()
            _message.value = "Konfigurasi direset ke awal."
        }
    }

    fun prepareExport() {
        viewModelScope.launch {
            _exportText.value = repository.exportLogsText()
        }
    }

    fun clearExport() {
        _exportText.value = null
    }

    fun clearMessage() {
        _message.value = null
    }
}
