package com.netshieldx.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.netshieldx.app.ui.navigation.AppRoute
import com.netshieldx.app.ui.screens.DashboardScreen
import com.netshieldx.app.ui.screens.FirewallScreen
import com.netshieldx.app.ui.screens.NetworkScreen
import com.netshieldx.app.ui.screens.PrivacyScreen
import com.netshieldx.app.ui.screens.ProtectionScreen
import com.netshieldx.app.ui.screens.SettingsScreen
import com.netshieldx.app.ui.theme.NetShieldXTheme
import com.netshieldx.app.ui.viewmodel.SettingsViewModel
import com.netshieldx.app.ui.viewmodel.repositoryViewModelFactory
import com.netshieldx.app.vpn.NetShieldVpnService
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NetShieldApp()
        }
    }
}

private data class BottomItem(val route: AppRoute, val icon: ImageVector)

private val bottomItems = listOf(
    BottomItem(AppRoute.Dashboard, Icons.Filled.Dashboard),
    BottomItem(AppRoute.Network, Icons.Filled.NetworkCheck),
    BottomItem(AppRoute.Firewall, Icons.Filled.Shield),
    BottomItem(AppRoute.Protection, Icons.Filled.Security),
    BottomItem(AppRoute.Settings, Icons.Filled.Settings)
)

@Composable
private fun NetShieldApp() {
    val context = LocalContext.current
    val navController = rememberNavController()
    val settingsViewModel: SettingsViewModel =
        viewModel(factory = repositoryViewModelFactory(context))
    val settings by settingsViewModel.settings.collectAsState()
    val darkTheme = settings?.darkTheme ?: true
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var pendingStart by remember { mutableStateOf(false) }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService(context)
        } else {
            scope.launch {
                snackbarHostState.showSnackbar("Persetujuan VPN ditolak. Perlindungan tidak dimulai.")
            }
        }
        pendingStart = false
    }

    fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    fun startProtection() {
        requestNotificationPermissionIfNeeded()
        val prepareIntent = try {
            VpnService.prepare(context)
        } catch (e: Exception) {
            scope.launch {
                snackbarHostState.showSnackbar("Tidak bisa menyiapkan VPN: ${e.message}")
            }
            return
        }
        if (prepareIntent == null) {
            startVpnService(context)
        } else {
            pendingStart = true
            vpnPermissionLauncher.launch(prepareIntent)
        }
    }

    fun stopProtection() {
        val intent = Intent(context, NetShieldVpnService::class.java)
        intent.action = NetShieldVpnService.ACTION_STOP
        context.startService(intent)
    }

    NetShieldXTheme(darkTheme = darkTheme) {
        Scaffold(
            snackbarHost = { SnackbarHost(snackbarHostState) },
            bottomBar = {
                val backStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = backStackEntry?.destination?.route
                if (currentRoute != AppRoute.Privacy.route) {
                    NavigationBar {
                        for (item in bottomItems) {
                            NavigationBarItem(
                                selected = currentRoute == item.route.route,
                                onClick = {
                                    navController.navigate(item.route.route) {
                                        popUpTo(navController.graph.startDestinationId) {
                                            saveState = true
                                        }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                },
                                icon = { Icon(item.icon, contentDescription = item.route.label) },
                                label = { Text(item.route.label) }
                            )
                        }
                    }
                }
            }
        ) { padding ->
            NavHost(
                navController = navController,
                startDestination = AppRoute.Dashboard.route,
                modifier = Modifier.padding(padding)
            ) {
                composable(AppRoute.Dashboard.route) {
                    DashboardScreen(
                        onStartProtection = { startProtection() },
                        onStopProtection = { stopProtection() },
                        onOpenPrivacy = { navController.navigate(AppRoute.Privacy.route) }
                    )
                }
                composable(AppRoute.Network.route) { NetworkScreen() }
                composable(AppRoute.Firewall.route) { FirewallScreen() }
                composable(AppRoute.Protection.route) { ProtectionScreen() }
                composable(AppRoute.Settings.route) {
                    SettingsScreen(onOpenPrivacy = { navController.navigate(AppRoute.Privacy.route) })
                }
                composable(AppRoute.Privacy.route) {
                    PrivacyScreen(onBack = { navController.popBackStack() })
                }
            }
        }
    }
}

private fun startVpnService(context: android.content.Context) {
    val intent = Intent(context, NetShieldVpnService::class.java)
    intent.action = NetShieldVpnService.ACTION_START
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}
