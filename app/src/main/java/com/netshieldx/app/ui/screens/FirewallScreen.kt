package com.netshieldx.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import com.netshieldx.app.data.repository.FirewallMode
import com.netshieldx.app.device.TrafficMonitor
import com.netshieldx.app.ui.viewmodel.FirewallViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallScreen() {
    val context = LocalContext.current
    val viewModel: FirewallViewModel = viewModel(factory = repositoryViewModelFactory(context))
    val apps by viewModel.apps.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val message by viewModel.message.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    LaunchedEffect(message) {
        val text = message
        if (text != null) {
            snackbarHostState.showSnackbar(text)
            viewModel.clearMessage()
        }
    }

    val filtered = apps.filter { item ->
        val matchesQuery = query.isBlank() ||
            item.info.label.contains(query, ignoreCase = true) ||
            item.info.packageName.contains(query, ignoreCase = true)
        val matchesSystem = showSystem || !item.info.isSystem
        matchesQuery && matchesSystem
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Firewall") },
                actions = {
                    IconButton(onClick = { viewModel.refresh() }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Muat ulang")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(text = "Firewall per aplikasi", style = MaterialTheme.typography.titleLarge)
            Text(
                text = "Aturan berlaku di lapisan VPN lokal dan hanya aktif saat perlindungan berjalan. " +
                    "Pemetaan trafik ke aplikasi memakai UID dari /proc/net dan bersifat best-effort: " +
                    "koneksi yang sangat singkat bisa tidak terpetakan dan tampil sebagai unknown.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Cari aplikasi") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.Checkbox(
                    checked = showSystem,
                    onCheckedChange = { showSystem = it }
                )
                Text("Tampilkan aplikasi sistem")
            }
            if (loading) {
                CircularProgressIndicator()
            } else if (filtered.isEmpty()) {
                Text(
                    text = "Tidak ada aplikasi yang cocok.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(filtered, key = { it.info.packageName }) { item ->
                        FirewallAppRow(
                            label = item.info.label,
                            packageName = item.info.packageName,
                            mode = item.mode,
                            rxBytes = item.rxBytes,
                            txBytes = item.txBytes,
                            onModeChange = { viewModel.setMode(item.info.packageName, it) }
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FirewallAppRow(
    label: String,
    packageName: String,
    mode: FirewallMode,
    rxBytes: Long,
    txBytes: Long,
    onModeChange: (FirewallMode) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(text = label, style = MaterialTheme.typography.titleMedium)
            Text(
                text = packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = "Unduhan: ${TrafficMonitor.formatBytes(rxBytes)} • Unggahan: ${TrafficMonitor.formatBytes(txBytes)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = !expanded }
            ) {
                OutlinedTextField(
                    value = mode.label,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Mode") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth()
                )
                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false }
                ) {
                    for (option in FirewallMode.values()) {
                        DropdownMenuItem(
                            text = { Text(option.label) },
                            onClick = {
                                expanded = false
                                onModeChange(option)
                            }
                        )
                    }
                }
            }
        }
    }
}
