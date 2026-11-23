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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.netshieldx.app.ui.components.StatCard
import com.netshieldx.app.ui.viewmodel.ProtectionViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory
import com.netshieldx.app.vpn.FilterCategory
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProtectionScreen() {
    val context = LocalContext.current
    val viewModel: ProtectionViewModel = viewModel(factory = repositoryViewModelFactory(context))
    val recentBlocked by viewModel.recentBlocked.collectAsState()
    val recentThreats by viewModel.recentThreats.collectAsState()
    val totalBlocks by viewModel.totalBlocks.collectAsState()
    val filterSources by viewModel.filterSources.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val customBlocked by viewModel.customBlocked.collectAsState()
    val allowlist by viewModel.allowlist.collectAsState()
    val updating by viewModel.updating.collectAsState()
    val message by viewModel.message.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var customDomain by remember { mutableStateOf("") }
    var allowDomain by remember { mutableStateOf("") }
    var sourceName by remember { mutableStateOf("") }
    var sourceUrl by remember { mutableStateOf("") }
    var sourceCategory by remember { mutableStateOf("ADS") }

    LaunchedEffect(message) {
        val text = message
        if (text != null) {
            snackbarHostState.showSnackbar(text)
            viewModel.clearMessage()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = { TopAppBar(title = { Text("Proteksi") }) }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Text(text = "Proteksi DNS dan ancaman", style = MaterialTheme.typography.titleLarge)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "DNS filtering tidak bisa memblokir semua iklan, terutama iklan yang memakai domain yang sama dengan konten normal. Gunakan allowlist jika ada situs yang rusak karena pemblokiran.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    StatCard(
                        title = "Total diblokir",
                        value = totalBlocks.toString(),
                        modifier = Modifier.weight(1f)
                    )
                    StatCard(
                        title = "Ancaman tercatat",
                        value = recentThreats.size.toString(),
                        subtitle = "200 entri terakhir",
                        modifier = Modifier.weight(1f)
                    )
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Kategori filter", style = MaterialTheme.typography.titleMedium)
                        CategoryRow(
                            label = "Iklan",
                            enabled = settings?.adsEnabled ?: true,
                            onToggle = { viewModel.setCategoryEnabled(FilterCategory.ADS, it) }
                        )
                        CategoryRow(
                            label = "Tracker",
                            enabled = settings?.trackerEnabled ?: true,
                            onToggle = { viewModel.setCategoryEnabled(FilterCategory.TRACKER, it) }
                        )
                        CategoryRow(
                            label = "Phishing dan Malware",
                            enabled = settings?.phishingMalwareEnabled ?: true,
                            onToggle = { viewModel.setCategoryEnabled(FilterCategory.PHISHING_MALWARE, it) }
                        )
                    }
                }
            }
            item {
                Text(text = "Ancaman terbaru", style = MaterialTheme.typography.titleMedium)
            }
            if (recentThreats.isEmpty()) {
                item {
                    Text(
                        text = "Belum ada ancaman tercatat. Deteksi hanya menandai domain yang terdaftar di blocklist ancaman atau pola yang mencurigakan, dan tidak pernah menyatakan perangkat terinfeksi hanya dari satu koneksi.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                items(recentThreats, key = { it.id }) { threat ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(text = threat.domain, style = MaterialTheme.typography.titleMedium)
                            Text(
                                text = "Risiko: ${threat.riskLevel} • ${if (threat.listed) "Terdaftar di blocklist" else "Belum dapat dipastikan"}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error
                            )
                            Text(text = threat.reason, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                text = "Sumber: ${threat.source} • ${DateFormat.getDateTimeInstance().format(Date(threat.timestamp))}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
            item {
                Text(text = "Domain diblokir terbaru", style = MaterialTheme.typography.titleMedium)
            }
            if (recentBlocked.isEmpty()) {
                item {
                    Text(
                        text = "Belum ada domain yang diblokir.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                items(recentBlocked.take(20), key = { it.domain }) { blocked ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = blocked.domain, style = MaterialTheme.typography.titleMedium)
                                Text(
                                    text = "${blocked.category} • diblokir ${blocked.blockCount}x",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Blocklist kustom", style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            value = customDomain,
                            onValueChange = { customDomain = it },
                            label = { Text("contoh: iklan.example.com") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                viewModel.addCustomBlocked(customDomain)
                                customDomain = ""
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Tambah ke Blocklist")
                        }
                        val customs = customBlocked[FilterCategory.CUSTOM] ?: emptySet()
                        if (customs.isEmpty()) {
                            Text(
                                text = "Belum ada domain kustom.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            for (domain in customs) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(text = domain, modifier = Modifier.weight(1f))
                                    IconButton(onClick = { viewModel.removeCustomBlocked(domain) }) {
                                        Icon(Icons.Filled.Delete, contentDescription = "Hapus $domain")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Allowlist", style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = "Domain di allowlist selalu diizinkan dan mengalahkan blocklist. Gunakan untuk memperbaiki false positive.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        OutlinedTextField(
                            value = allowDomain,
                            onValueChange = { allowDomain = it },
                            label = { Text("contoh: situs-tepercaya.com") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                viewModel.addAllowlist(allowDomain)
                                allowDomain = ""
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Tambah ke Allowlist")
                        }
                        if (allowlist.isEmpty()) {
                            Text(
                                text = "Allowlist kosong.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            for (domain in allowlist) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(text = domain, modifier = Modifier.weight(1f))
                                    IconButton(onClick = { viewModel.removeAllowlist(domain) }) {
                                        Icon(Icons.Filled.Delete, contentDescription = "Hapus $domain")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            item {
                Text(text = "Sumber filter", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "Pembaruan mengunduh langsung dari URL publik yang tercantum, bukan dari server developer.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            items(filterSources, key = { it.id }) { source ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = source.name, style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = "${source.category} • Lisensi: ${source.license} • Entri: ${source.entryCount}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = source.url,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(if (source.enabled) "Aktif" else "Nonaktif")
                            Switch(
                                checked = source.enabled,
                                onCheckedChange = { viewModel.setFilterSourceEnabled(source.id, it) }
                            )
                        }
                        OutlinedButton(
                            onClick = { viewModel.updateFilterSource(source) },
                            enabled = !updating,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(if (updating) "Memperbarui…" else "Perbarui Sekarang")
                        }
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Tambah sumber filter", style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            value = sourceName,
                            onValueChange = { sourceName = it },
                            label = { Text("Nama sumber") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = sourceUrl,
                            onValueChange = { sourceUrl = it },
                            label = { Text("URL https daftar hosts") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                viewModel.addFilterSource(sourceName, sourceUrl, sourceCategory)
                                sourceName = ""
                                sourceUrl = ""
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Tambah Sumber")
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun CategoryRow(label: String, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = enabled, onCheckedChange = onToggle)
    }
}
