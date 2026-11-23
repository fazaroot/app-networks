package com.netshieldx.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.netshieldx.app.device.TrafficMonitor
import com.netshieldx.app.ui.components.StatCard
import com.netshieldx.app.ui.viewmodel.NetworkViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory
import com.netshieldx.app.vpn.VpnState
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    val viewModel: NetworkViewModel = viewModel(factory = repositoryViewModelFactory(context))
    val activities by viewModel.recentActivity.collectAsState()
    val totalConnections by viewModel.totalConnections.collectAsState()
    val liveStats by viewModel.liveStats.collectAsState()
    val vpnState by viewModel.vpnState.collectAsState()
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("Semua") }

    val filtered = activities.filter { activity ->
        val matchesQuery = query.isBlank() ||
            (activity.domain?.contains(query, ignoreCase = true) == true) ||
            (activity.packageName?.contains(query, ignoreCase = true) == true)
        val matchesFilter = when (filter) {
            "Diblokir" -> !activity.allowed
            "Diizinkan" -> activity.allowed
            else -> true
        }
        matchesQuery && matchesFilter
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Jaringan") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(text = "Pemantauan jaringan", style = MaterialTheme.typography.titleLarge)
            Text(
                text = if (vpnState is VpnState.Running) {
                    "VPN lokal aktif. Koneksi yang diproses VPN ditampilkan di bawah."
                } else {
                    "VPN lokal tidak aktif. Riwayat di bawah adalah data yang tersimpan sebelumnya."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCard(
                    title = "Koneksi diproses",
                    value = liveStats.connectionsProcessed.toString(),
                    subtitle = "Total tersimpan: $totalConnections",
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Trafik VPN",
                    value = TrafficMonitor.formatBytes(liveStats.bytesRx + liveStats.bytesTx),
                    subtitle = "Paket: ${liveStats.packetsProcessed}",
                    modifier = Modifier.weight(1f)
                )
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Cari domain atau aplikasi") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (option in listOf("Semua", "Diizinkan", "Diblokir")) {
                    FilterChip(
                        selected = filter == option,
                        onClick = { filter = option },
                        label = { Text(option) }
                    )
                }
            }
            if (filtered.isEmpty()) {
                Text(
                    text = "Belum ada aktivitas jaringan yang cocok. Aktivitas muncul setelah VPN aktif.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filtered, key = { it.id }) { activity ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = activity.domain ?: "unknown",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Aplikasi: ${activity.packageName ?: "unknown"}",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    text = "Protokol: ${activity.protocol} • " +
                                        if (activity.allowed) "Diizinkan" else "Diblokir" +
                                            (activity.category?.let { " ($it)" } ?: ""),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = if (activity.allowed) {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    } else {
                                        MaterialTheme.colorScheme.error
                                    }
                                )
                                Text(
                                    text = DateFormat.getDateTimeInstance().format(Date(activity.timestamp)),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
            OutlinedButton(
                onClick = { viewModel.clearLogs() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Hapus Riwayat")
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}
