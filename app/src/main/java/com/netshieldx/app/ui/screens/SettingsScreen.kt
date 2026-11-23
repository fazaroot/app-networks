package com.netshieldx.app.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.netshieldx.app.ui.viewmodel.SettingsViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onOpenPrivacy: () -> Unit) {
    val context = LocalContext.current
    val viewModel: SettingsViewModel = viewModel(factory = repositoryViewModelFactory(context))
    val settings by viewModel.settings.collectAsState()
    val message by viewModel.message.collectAsState()
    val exportText by viewModel.exportText.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    var showResetDialog by remember { mutableStateOf(false) }
    var showClearDialog by remember { mutableStateOf(false) }
    var dnsExpanded by remember { mutableStateOf(false) }
    var intervalExpanded by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        val text = exportText
        if (uri != null && text != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use { stream ->
                    stream.write(text.toByteArray(Charsets.UTF_8))
                }
                viewModel.clearExport()
            } catch (_: Exception) {
            }
        }
    }

    LaunchedEffect(message) {
        val text = message
        if (text != null) {
            snackbarHostState.showSnackbar(text)
            viewModel.clearMessage()
        }
    }

    LaunchedEffect(exportText) {
        if (exportText != null) {
            exportLauncher.launch("netshieldx-log.txt")
        }
    }

    val current = settings
    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = { TopAppBar(title = { Text("Pengaturan") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(text = "Pengaturan", style = MaterialTheme.typography.titleLarge)
            if (current == null) {
                Text("Memuat pengaturan…")
            } else {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Perlindungan", style = MaterialTheme.typography.titleMedium)
                        SettingRow(
                            label = "Mulai saat boot",
                            description = "Memulai VPN lokal setelah perangkat menyala, hanya jika persetujuan VPN sudah diberikan sebelumnya.",
                            checked = current.startOnBoot,
                            onToggle = { enabled -> viewModel.updateSettings { s -> s.copy(startOnBoot = enabled) } }
                        )
                        SettingRow(
                            label = "Notifikasi ancaman",
                            description = "Beri tahu saat ancaman High atau Critical terdeteksi.",
                            checked = current.notificationsEnabled,
                            onToggle = { enabled -> viewModel.updateSettings { s -> s.copy(notificationsEnabled = enabled) } }
                        )
                    }
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "DNS dan filter", style = MaterialTheme.typography.titleMedium)
                        ExposedDropdownMenuBox(
                            expanded = dnsExpanded,
                            onExpandedChange = { dnsExpanded = !dnsExpanded }
                        ) {
                            OutlinedTextField(
                                value = current.upstreamDns,
                                onValueChange = {},
                                readOnly = true,
                                label = { Text("DNS upstream") },
                                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = dnsExpanded) },
                                modifier = Modifier.menuAnchor().fillMaxWidth()
                            )
                            ExposedDropdownMenu(
                                expanded = dnsExpanded,
                                onDismissRequest = { dnsExpanded = false }
                            ) {
                                for (dns in listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222")) {
                                    DropdownMenuItem(
                                        text = { Text(dns) },
                                        onClick = {
                                            dnsExpanded = false
                                            viewModel.updateSettings { it.copy(upstreamDns = dns) }
                                        }
                                    )
                                }
                            }
                        }
                        SettingRow(
                            label = "Perbarui blocklist otomatis",
                            description = "Mengunduh ulang daftar filter dari sumber publik yang aktif.",
                            checked = current.autoUpdateBlocklist,
                            onToggle = { enabled -> viewModel.updateSettings { s -> s.copy(autoUpdateBlocklist = enabled) } }
                        )
                        ExposedDropdownMenuBox(
                            expanded = intervalExpanded,
                            onExpandedChange = { intervalExpanded = !intervalExpanded }
                        ) {
                            OutlinedTextField(
                                value = "${current.updateIntervalHours} jam",
                                onValueChange = {},
                                readOnly = true,
                                label = { Text("Interval pembaruan") },
                                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = intervalExpanded) },
                                modifier = Modifier.menuAnchor().fillMaxWidth()
                            )
                            ExposedDropdownMenu(
                                expanded = intervalExpanded,
                                onDismissRequest = { intervalExpanded = false }
                            ) {
                                for (hours in listOf(6, 12, 24, 72)) {
                                    DropdownMenuItem(
                                        text = { Text("$hours jam") },
                                        onClick = {
                                            intervalExpanded = false
                                            viewModel.updateSettings { it.copy(updateIntervalHours = hours) }
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Tampilan", style = MaterialTheme.typography.titleMedium)
                        SettingRow(
                            label = "Mode gelap",
                            description = "Matikan untuk memakai mode terang.",
                            checked = current.darkTheme,
                            onToggle = { enabled -> viewModel.updateSettings { s -> s.copy(darkTheme = enabled) } }
                        )
                    }
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(text = "Data", style = MaterialTheme.typography.titleMedium)
                        Text(
                            text = "Log disimpan lokal dan otomatis dihapus setelah 30 hari.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { viewModel.prepareExport() },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Ekspor Log")
                        }
                        OutlinedButton(
                            onClick = { showClearDialog = true },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Hapus Semua Log")
                        }
                        OutlinedButton(
                            onClick = { showResetDialog = true },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Reset Konfigurasi")
                        }
                    }
                }
                OutlinedButton(
                    onClick = onOpenPrivacy,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Privasi dan Keamanan")
                }
                Text(
                    text = "NetShield X versi 1.0.0. Semua pemrosesan dilakukan lokal di perangkat.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text("Hapus semua log?") },
            text = { Text("Riwayat aktivitas, domain diblokir, dan deteksi ancaman akan dihapus dan tidak bisa dikembalikan.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        showClearDialog = false
                        viewModel.clearLogs()
                    }
                ) { Text("Hapus") }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) { Text("Batal") }
            }
        )
    }
    if (showResetDialog) {
        AlertDialog(
            onDismissRequest = { showResetDialog = false },
            title = { Text("Reset konfigurasi?") },
            text = { Text("Pengaturan dikembalikan ke awal dan semua log dihapus.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        showResetDialog = false
                        viewModel.resetConfiguration()
                    }
                ) { Text("Reset") }
            },
            dismissButton = {
                TextButton(onClick = { showResetDialog = false }) { Text("Batal") }
            }
        )
    }
}

@Composable
private fun SettingRow(
    label: String,
    description: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onToggle)
    }
}
