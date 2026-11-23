package com.netshieldx.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.netshieldx.app.device.TrafficMonitor
import com.netshieldx.app.ui.components.StatCard
import com.netshieldx.app.ui.components.StatusCard
import com.netshieldx.app.ui.components.StatusKind
import com.netshieldx.app.ui.components.TrafficChart
import com.netshieldx.app.ui.theme.DangerRed
import com.netshieldx.app.ui.theme.SuccessGreen
import com.netshieldx.app.ui.viewmodel.DashboardViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory
import com.netshieldx.app.vpn.VpnState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit,
    onOpenPrivacy: () -> Unit
) {
    val context = LocalContext.current
    val viewModel: DashboardViewModel = viewModel(factory = repositoryViewModelFactory(context))
    val state by viewModel.state.collectAsState()
    val topPackages by viewModel.topPackages.collectAsState()

    val running = state.vpnState is VpnState.Running
    val failed = state.vpnState as? VpnState.Failed

    Scaffold(
        topBar = { TopAppBar(title = { Text("NetShield X") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(text = "Dashboard", style = MaterialTheme.typography.titleLarge)
            StatusCard(
                title = "Status perlindungan",
                value = when (val s = state.vpnState) {
                    is VpnState.Running -> "Aktif"
                    is VpnState.Starting -> "Memulai…"
                    is VpnState.Failed -> "Gagal: ${s.reason}"
                    is VpnState.Stopped -> "Tidak aktif"
                    else -> "Tidak diketahui"
                },
                kind = when (state.vpnState) {
                    is VpnState.Running -> StatusKind.OK
                    is VpnState.Failed -> StatusKind.WARNING
                    else -> StatusKind.INFO
                },
                description = if (running) {
                    "VPN lokal aktif. DNS difilter di perangkat, trafik diteruskan ke tujuannya."
                } else {
                    "Tekan Mulai Perlindungan untuk mengaktifkan VPN lokal. Android akan meminta persetujuan VPN."
                }
            )
            if (failed != null) {
                Text(
                    text = failed.reason,
                    style = MaterialTheme.typography.bodyMedium,
                    color = DangerRed
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onStartProtection,
                    enabled = !running,
                    colors = ButtonDefaults.buttonColors(containerColor = SuccessGreen),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Mulai Perlindungan")
                }
                Button(
                    onClick = onStopProtection,
                    enabled = running,
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Hentikan")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCard(
                    title = "Unduhan",
                    value = TrafficMonitor.formatBytes(state.traffic.totalRxBytes),
                    subtitle = TrafficMonitor.formatRate(state.traffic.rxRateBytesPerSec),
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Unggahan",
                    value = TrafficMonitor.formatBytes(state.traffic.totalTxBytes),
                    subtitle = TrafficMonitor.formatRate(state.traffic.txRateBytesPerSec),
                    modifier = Modifier.weight(1f)
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCard(
                    title = "Domain diblokir",
                    value = state.totalBlocked.toString(),
                    subtitle = "Iklan: ${state.adsBlocked}, Tracker: ${state.trackerBlocked}",
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Ancaman terdeteksi",
                    value = state.totalThreats.toString(),
                    subtitle = "Koneksi diperiksa: ${state.totalConnections}",
                    modifier = Modifier.weight(1f)
                )
            }
            TrafficChart(values = state.rateHistory)
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(text = "Aplikasi dengan aktivitas tertinggi", style = MaterialTheme.typography.titleMedium)
                    Spacer(modifier = Modifier.height(6.dp))
                    if (topPackages.isEmpty()) {
                        Text(
                            text = "Belum ada data aktivitas. Data muncul setelah VPN aktif dan trafik diproses.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        for ((pkg, count) in topPackages) {
                            Text(
                                text = "• $pkg — $count koneksi",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }
            }
            Text(
                text = "Semua angka di atas berasal dari data aktual perangkat (TrafficStats, VPN lokal, dan database). Tidak ada angka dummy.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedButton(onClick = onOpenPrivacy, modifier = Modifier.fillMaxWidth()) {
                Text("Cara Kerja dan Privasi")
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
